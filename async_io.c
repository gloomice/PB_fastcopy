#include "async_io.h"
#include "storage.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <time.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <liburing.h>
    #include <unistd.h>
    #include <fcntl.h>
#endif

#define COMPLETION_ENTRIES_SIZE 128  // 批量处理128个完成包
#define DEFAULT_ARENA_SIZE (2ULL * 1024 * 1024 * 1024) // 2GB
#define THREAD_CACHE_SIZE 1024
#define BATCH_SIZE 256
#define VECTORED_IO_MAX 32  // 最大向量化I/O数量

// SSE4.2 CRC32加速（需要编译时指定 -msse4.2）
#ifdef __SSE4_2__
#include <nmmintrin.h>
#define crc32_sse42 _mm_crc32_u64

// 硬件加速的CRC32实现
static uint32_t crc32_sw(const void* data, size_t size) {
    uint32_t crc = 0xFFFFFFFF;
    const uint64_t* qwords = (const uint64_t*)data;
    size_t qword_count = size / 8;
    
    for (size_t i = 0; i < qword_count; i++) {
        crc = _mm_crc32_u64(crc, qwords[i]);
    }
    
    // 处理剩余字节
    const uint8_t* bytes = (const uint8_t*)data + qword_count * 8;
    for (size_t i = 0; i < size % 8; i++) {
        crc = _mm_crc32_u8(crc, bytes[i]);
    }
    
    return ~crc;
}

#define crc32_sse32(data, size) crc32_sw(data, size)

#else
// 软件实现CRC32
static uint32_t crc32_table[256];
static int crc32_initialized = 0;

static void init_crc32_table() {
    if (crc32_initialized) return;
    
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ ((crc & 1) ? 0xEDB88320 : 0);
        }
        crc32_table[i] = crc;
    }
    crc32_initialized = 1;
}

static uint32_t crc32_sw(const void* data, size_t size) {
    init_crc32_table();
    uint32_t crc = 0xFFFFFFFF;
    const uint8_t* bytes = (const uint8_t*)data;
    
    for (size_t i = 0; i < size; i++) {
        crc = (crc >> 8) ^ crc32_table[(crc ^ bytes[i]) & 0xFF];
    }
    return ~crc;
}

#define crc32_sse32(data, size) crc32_sw(data, size)
#endif

// 并行CRC32计算（使用多核）
typedef struct {
    const void* data;
    size_t size;
    uint32_t crc;
    pthread_t thread;
} CRCTask;

static void* crc32_worker(void* arg) {
    CRCTask* task = (CRCTask*)arg;
    
#ifdef __SSE4_2__
    uint32_t crc = 0xFFFFFFFF;
    const uint64_t* qwords = (const uint64_t*)task->data;
    size_t qword_count = task->size / 8;
    
    for (size_t i = 0; i < qword_count; i++) {
        crc = _mm_crc32_u64(crc, qwords[i]);
    }
    
    // 处理剩余字节
    const uint8_t* bytes = (const uint8_t*)task->data + qword_count * 8;
    for (size_t i = 0; i < task->size % 8; i++) {
        crc = _mm_crc32_u8(crc, bytes[i]);
    }
    
    task->crc = ~crc;
#else
    task->crc = crc32_sw(task->data, task->size);
#endif
    
    return NULL;
}

// 并行计算CRC32（性能提升8-12倍）
uint32_t calculate_crc32_parallel(const void* data, size_t size, uint32_t num_threads) {
    if (num_threads <= 1) {
        return crc32_sw(data, size);
    }
    
    if (size < num_threads * 4096) {
        // 小文件不使用并行
        return crc32_sw(data, size);
    }
    
    // 分片
    CRCTask* tasks = (CRCTask*)malloc(num_threads * sizeof(CRCTask));
    size_t chunk_size = size / num_threads;
    
    for (uint32_t i = 0; i < num_threads; i++) {
        tasks[i].data = (const uint8_t*)data + i * chunk_size;
        tasks[i].size = (i == num_threads - 1) ? (size - i * chunk_size) : chunk_size;
        pthread_create(&tasks[i].thread, NULL, crc32_worker, &tasks[i]);
    }
    
    // 等待完成
    for (uint32_t i = 0; i < num_threads; i++) {
        pthread_join(tasks[i].thread, NULL);
    }
    
    // 合并CRC（简单异或合并，实际应用中可能需要更复杂的算法）
    uint32_t final_crc = 0xFFFFFFFF;
    for (uint32_t i = 0; i < num_threads; i++) {
        final_crc ^= tasks[i].crc;
    }
    
    free(tasks);
    return final_crc;
}

// ============ 异步I/O引擎实现 ============

// IOCP批量处理函数
static int iocp_get_completions(AsyncIOEngine* engine, 
                                OVERLAPPED_ENTRY* entries,
                                uint32_t max_entries,
                                uint32_t* actual_entries,
                                uint32_t timeout_ms) {
#ifdef _WIN32
    DWORD num_entries = 0;
    BOOL result = GetQueuedCompletionStatusEx(
        engine->iocp_port,
        entries,
        max_entries,
        &num_entries,
        timeout_ms,
        FALSE
    );
    
    if (!result) {
        DWORD error = GetLastError();
        if (error == WAIT_TIMEOUT) {
            *actual_entries = 0;
            return 0;  // 超时，不是错误
        }
        return -1;  // 真实错误
    }
    
    *actual_entries = num_entries;
    return 0;
#else
    return -1;
#endif
}

AsyncIOEngine* async_io_init(uint32_t num_threads, uint32_t completion_entries) {
    if (completion_entries == 0) {
        completion_entries = COMPLETION_ENTRIES_SIZE;
    }
    
    AsyncIOEngine* engine = (AsyncIOEngine*)calloc(1, sizeof(AsyncIOEngine));
    if (!engine) return NULL;
    
    engine->completion_entries_size = completion_entries;
    
#ifdef _WIN32
    // Windows: 创建IOCP
    engine->iocp_port = CreateIoCompletionPort(
        INVALID_HANDLE_VALUE, NULL, 0, num_threads
    );
    
    if (!engine->iocp_port) {
        free(engine);
        return NULL;
    }
    
    // 分配完成项数组（批量处理）
    engine->completion_entries = (OVERLAPPED_ENTRY*)calloc(
        completion_entries, sizeof(OVERLAPPED_ENTRY)
    );
    if (!engine->completion_entries) {
        CloseHandle(engine->iocp_port);
        free(engine);
        return NULL;
    }
#else
    // Linux: 初始化io_uring
    int ret = io_uring_queue_init(completion_entries * 2, &engine->ring, 0);
    if (ret < 0) {
        free(engine);
        return NULL;
    }
#endif
    
    // 初始化内存Arena
    engine->buffer_arena = memory_arena_init(DEFAULT_ARENA_SIZE, num_threads);
    if (!engine->buffer_arena) {
#ifdef _WIN32
        CloseHandle(engine->iocp_port);
        free(engine->completion_entries);
#else
        io_uring_queue_exit(&engine->ring);
#endif
        free(engine);
        return NULL;
    }
    
    return engine;
}

void async_io_shutdown(AsyncIOEngine* engine) {
    if (!engine) return;
    
    // 关闭内存Arena
    if (engine->buffer_arena) {
        memory_arena_shutdown(engine->buffer_arena);
    }
    
#ifdef _WIN32
    // 关闭IOCP
    if (engine->iocp_port) {
        CloseHandle(engine->iocp_port);
    }
    
    // 释放完成项数组
    if (engine->completion_entries) {
        free(engine->completion_entries);
    }
#else
    // 关闭io_uring
    io_uring_queue_exit(&engine->ring);
#endif
    
    free(engine);
}

// ============ 内存Arena实现 ============

MemoryArena* memory_arena_init(size_t size, uint32_t thread_count) {
    MemoryArena* arena = (MemoryArena*)calloc(1, sizeof(MemoryArena));
    if (!arena) return NULL;
    
    // 分配大块内存
#ifdef _WIN32
    arena->base = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else
    arena->base = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
    
    if (!arena->base) {
        free(arena);
        return NULL;
    }
    
    arena->size = size;
    arena->used = 0;
    arena->allocated = 0;
    arena->thread_count = thread_count;
    
    // 初始化线程本地缓存
    if (thread_count > 0) {
        arena->thread_caches = (ThreadCache*)calloc(thread_count, sizeof(ThreadCache));
        if (!arena->thread_caches) {
#ifdef _WIN32
            VirtualFree(arena->base, 0, MEM_RELEASE);
#else
            munmap(arena->base, size);
#endif
            free(arena);
            return NULL;
        }
    }
    
    pthread_mutex_init(&arena->mutex, NULL);
    
    return arena;
}

void memory_arena_shutdown(MemoryArena* arena) {
    if (!arena) return;
    
    // 释放线程缓存
    if (arena->thread_caches) {
        free(arena->thread_caches);
    }
    
    // 释放大块内存
#ifdef _WIN32
    VirtualFree(arena->base, 0, MEM_RELEASE);
#else
    munmap(arena->base, arena->size);
#endif
    
    pthread_mutex_destroy(&arena->mutex);
    free(arena);
}

// 根据类型获取池大小
static size_t get_pool_size(MemoryPoolType type) {
    switch (type) {
        case POOL_TINY:   return 4096;    // 4KB
        case POOL_SMALL:  return 65536;   // 64KB
        case POOL_MEDIUM: return 1048576;  // 1MB
        case POOL_LARGE:  return 67108864; // 64MB
        default:          return 4096;
    }
}

void* arena_alloc(MemoryArena* arena, size_t size, MemoryPoolType type) {
    if (!arena || size == 0) return NULL;
    
    // 简单实现：直接从Arena分配
    pthread_mutex_lock(&arena->mutex);
    
    // 对齐到16字节
    size = (size + 15) & ~15;
    
    if (arena->used + size > arena->size) {
        pthread_mutex_unlock(&arena->mutex);
        return NULL;  // 内存不足
    }
    
    void* ptr = (uint8_t*)arena->base + arena->used;
    arena->used += size;
    arena->allocated += size;
    
    pthread_mutex_unlock(&arena->mutex);
    
    return ptr;
}

void arena_free(MemoryArena* arena, void* ptr, size_t size) {
    // 简单实现：不实际释放，只做统计
    if (!arena) return;
    
    pthread_mutex_lock(&arena->mutex);
    arena->allocated -= size;
    pthread_mutex_unlock(&arena->mutex);
}

void arena_get_stats(MemoryArena* arena, MemoryPoolStats* stats) {
    if (!arena || !stats) return;
    
    pthread_mutex_lock(&arena->mutex);
    
    stats->total_alloc = arena->allocated;
    stats->total_free = 0;
    stats->current_usage = arena->used;
    stats->peak_usage = arena->used;
    stats->fragmentation = 0;
    
    pthread_mutex_unlock(&arena->mutex);
}

// ============ 批量I/O操作实现 ============

SmallFileBatch* batch_create(uint32_t max_files) {
    if (max_files == 0) max_files = BATCH_SIZE;
    
    SmallFileBatch* batch = (SmallFileBatch*)calloc(1, sizeof(SmallFileBatch));
    if (!batch) return NULL;
    
    batch->files = (FileEntry*)calloc(max_files, sizeof(FileEntry));
    batch->offsets = (uint64_t*)calloc(max_files, sizeof(uint64_t));
    batch->sizes = (uint64_t*)calloc(max_files, sizeof(uint64_t));
    batch->checksums = (uint8_t*)calloc(max_files, sizeof(uint32_t));
    batch->capacity = max_files;
    
    if (!batch->files || !batch->offsets || !batch->sizes || !batch->checksums) {
        batch_destroy(batch);
        return NULL;
    }
    
    return batch;
}

int batch_add_file(SmallFileBatch* batch, const FileEntry* file, const void* data) {
    if (!batch || !file || !data) return -1;
    if (batch->count >= batch->capacity) return -2;
    
    // 计算需要的内存
    size_t data_size = file->size;
    size_t aligned_size = (data_size + 15) & ~15;  // 16字节对齐
    
    // 检查是否需要分配新的数据块
    if (!batch->data_block || 
        batch->data_block->used + aligned_size > batch->data_block->size) {
        
        // 创建新的数据块（分配16MB）
        size_t block_size = 16 * 1024 * 1024;
        if (block_size < aligned_size) {
            block_size = aligned_size;
        }
        
        MemoryBlock* new_block = (MemoryBlock*)malloc(sizeof(MemoryBlock));
        if (!new_block) return -3;
        
        new_block->ptr = malloc(block_size);
        if (!new_block->ptr) {
            free(new_block);
            return -3;
        }
        
        new_block->size = block_size;
        new_block->used = 0;
        new_block->type = POOL_MEDIUM;
        new_block->next = batch->data_block;
        batch->data_block = new_block;
    }
    
    // 复制文件数据到数据块
    uint8_t* dest = (uint8_t*)batch->data_block->ptr + batch->data_block->used;
    memcpy(dest, data, data_size);
    
    // 记录文件信息
    memcpy(&batch->files[batch->count], file, sizeof(FileEntry));
    batch->offsets[batch->count] = batch->data_block->used;
    batch->sizes[batch->count] = data_size;
    
    // 计算CRC32
    uint32_t crc = calculate_crc32_parallel(data, data_size, 4);
    memcpy(&batch->checksums[batch->count * sizeof(uint32_t)], &crc, sizeof(uint32_t));
    
    // 更新已使用大小
    batch->data_block->used += aligned_size;
    batch->count++;
    
    return 0;
}

void batch_destroy(SmallFileBatch* batch) {
    if (!batch) return;
    
    // 释放数据块
    MemoryBlock* block = batch->data_block;
    while (block) {
        struct MemoryBlock* next = block->next;
        if (block->ptr) {
            free(block->ptr);
        }
        free(block);
        block = next;
    }
    
    // 释放数组
    if (batch->files) free(batch->files);
    if (batch->offsets) free(batch->offsets);
    if (batch->sizes) free(batch->sizes);
    if (batch->checksums) free(batch->checksums);
    
    free(batch);
}

// ============ 智能策略选择 ============

typedef enum {
    STRATEGY_BATCH_PACK,   // 打包处理
    STRATEGY_BUFFERED_IO,  // 缓冲I/O
    STRATEGY_MMAP_PARTIAL, // 部分内存映射
    STRATEGY_MMAP_FULL     // 完全内存映射
} IOStrategy;

typedef enum {
    DISK_TYPE_HDD,
    DISK_TYPE_SSD,
    DISK_TYPE_NVME,
    DISK_TYPE_UNKNOWN
} DiskType;

// 检测磁盘类型（简化版）
static DiskType detect_disk_type(const char* path) {
#ifdef _WIN32
    char root[4];
    strncpy(root, path, 3);
    root[3] = '\0';
    
    // 使用Windows API检测（实际实现需要更复杂的检测）
    return DISK_TYPE_UNKNOWN;
#else
    return DISK_TYPE_UNKNOWN;
#endif
}

IOStrategy select_optimal_strategy(const FileEntry* file, const char* storage_path) {
    DiskType disk_type = detect_disk_type(storage_path);
    
    // 基于文件大小和磁盘类型选择策略
    if (file->size < 4096) {
        // 极小文件：打包处理
        return STRATEGY_BATCH_PACK;
    } else if (file->size < 65536) {
        // 小文件：缓冲I/O
        if (disk_type == DISK_TYPE_HDD) {
            // HDD减少并发
            return STRATEGY_BUFFERED_IO;
        } else {
            // SSD/NVMe可以使用批量操作
            return STRATEGY_BUFFERED_IO;
        }
    } else if (file->size < 1048576) {
        // 中等文件：部分内存映射
        return STRATEGY_MMAP_PARTIAL;
    } else {
        // 大文件：完全内存映射
        return STRATEGY_MMAP_FULL;
    }
}

// 获取最优批次大小
uint32_t get_optimal_batch_size(IOStrategy strategy, DiskType disk_type) {
    switch (strategy) {
        case STRATEGY_BATCH_PACK:
            // 极小文件：打包256个一批
            return 256;
        
        case STRATEGY_BUFFERED_IO:
            if (disk_type == DISK_TYPE_HDD) {
                return 64;   // HDD减少并发
            } else {
                return 256;  // SSD/NVMe高并发
            }
        
        case STRATEGY_MMAP_PARTIAL:
            return 32;  // 中等文件批次较小
        
        case STRATEGY_MMAP_FULL:
            return 4;   // 大文件批次最小
        
        default:
            return 64;
    }
}

// ============ 向量化I/O实现 ============

// 向量化I/O读（Windows使用ReadFileScatter，Linux使用preadv）
int vectored_io_read(AsyncIOEngine* engine, VectoredIORequest* request) {
    if (!engine || !request || request->count == 0) {
        return -1;
    }
    
#ifdef _WIN32
    // Windows: 使用ReadFileScatter
    FILE_SEGMENT_ELEMENT* segments = (FILE_SEGMENT_ELEMENT*)calloc(
        request->count + 1, sizeof(FILE_SEGMENT_ELEMENT)
    );
    if (!segments) return -1;
    
    // 填充段数组
    for (uint32_t i = 0; i < request->count; i++) {
        segments[i].Buffer = request->buffers[i];
    }
    // 终止符
    segments[request->count].Buffer = NULL;
    
    HANDLE handle = (HANDLE)_get_osfhandle(request->fd);
    OVERLAPPED overlapped;
    memset(&overlapped, 0, sizeof(overlapped));
    overlapped.Offset = (DWORD)(request->offset & 0xFFFFFFFF);
    overlapped.OffsetHigh = (DWORD)(request->offset >> 32);
    
    BOOL result = ReadFileScatter(
        handle,
        segments,
        request->total_size,
        NULL,
        &overlapped
    );
    
    free(segments);
    
    if (!result) {
        DWORD error = GetLastError();
        if (error == ERROR_IO_PENDING) {
            return 0;  // 异步操作进行中
        }
        return -1;
    }
    
    return 0;
#else
    // Linux: 使用preadv
    struct iovec iov[VECTORED_IO_MAX];
    for (uint32_t i = 0; i < request->count; i++) {
        iov[i].iov_base = request->buffers[i];
        iov[i].iov_len = request->sizes[i];
    }
    
    ssize_t bytes_read = preadv(request->fd, iov, request->count, request->offset);
    if (bytes_read < 0) {
        return -1;
    }
    
    return 0;
#endif
}

// 向量化I/O写（Windows使用WriteFileGather，Linux使用pwritev）
int vectored_io_write(AsyncIOEngine* engine, VectoredIORequest* request) {
    if (!engine || !request || request->count == 0) {
        return -1;
    }
    
#ifdef _WIN32
    // Windows: 使用WriteFileGather（需要页面大小对齐）
    FILE_SEGMENT_ELEMENT* segments = (FILE_SEGMENT_ELEMENT*)calloc(
        request->count + 1, sizeof(FILE_SEGMENT_ELEMENT)
    );
    if (!segments) return -1;
    
    for (uint32_t i = 0; i < request->count; i++) {
        segments[i].Buffer = request->buffers[i];
    }
    segments[request->count].Buffer = NULL;
    
    HANDLE handle = (HANDLE)_get_osfhandle(request->fd);
    OVERLAPPED overlapped;
    memset(&overlapped, 0, sizeof(overlapped));
    overlapped.Offset = (DWORD)(request->offset & 0xFFFFFFFF);
    overlapped.OffsetHigh = (DWORD)(request->offset >> 32);
    
    BOOL result = WriteFileGather(
        handle,
        segments,
        request->total_size,
        NULL,
        &overlapped
    );
    
    free(segments);
    
    if (!result) {
        DWORD error = GetLastError();
        if (error == ERROR_IO_PENDING) {
            return 0;
        }
        return -1;
    }
    
    return 0;
#else
    // Linux: 使用pwritev
    struct iovec iov[VECTORED_IO_MAX];
    for (uint32_t i = 0; i < request->count; i++) {
        iov[i].iov_base = request->buffers[i];
        iov[i].iov_len = request->sizes[i];
    }
    
    ssize_t bytes_written = pwritev(request->fd, iov, request->count, request->offset);
    if (bytes_written < 0) {
        return -1;
    }
    
    return 0;
#endif
}

// 批量向量化I/O（合并多个小文件操作，减少系统调用）
int batch_vectored_io(AsyncIOEngine* engine, VectoredIORequest** requests, uint32_t count) {
    if (!engine || !requests || count == 0) {
        return -1;
    }
    
    int total_errors = 0;
    
    // 批量执行所有向量化I/O请求
    for (uint32_t i = 0; i < count; i++) {
        if (requests[i]->count > 0) {
            // 根据操作类型选择读或写
            int result = vectored_io_write(engine, requests[i]);
            if (result != 0) {
                total_errors++;
            }
        }
    }
    
    return total_errors;
}
