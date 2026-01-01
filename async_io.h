#ifndef ASYNC_IO_H
#define ASYNC_IO_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <liburing.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

// 内存池类型
typedef enum {
    POOL_TINY    = 0,   // 1KB-4KB，用于小文件元数据
    POOL_SMALL   = 1,   // 4KB-64KB，用于小文件数据
    POOL_MEDIUM  = 2,   // 64KB-1MB，用于中等文件
    POOL_LARGE   = 3    // 1MB-64MB，用于大文件预读
} MemoryPoolType;

// 内存块
typedef struct MemoryBlock {
    void* ptr;              // 内存指针
    size_t size;            // 内存大小
    size_t used;            // 已使用大小
    MemoryPoolType type;     // 池类型
    struct MemoryBlock* next; // 下一个块
} MemoryBlock;

// 线程本地缓存
typedef struct {
    MemoryBlock* tiny_pool;    // 极小文件池
    MemoryBlock* small_pool;   // 小文件池
    MemoryBlock* medium_pool;  // 中等文件池
    MemoryBlock* large_pool;   // 大文件池
    uint64_t alloc_count;      // 分配次数
    uint64_t free_count;       // 释放次数
} ThreadCache;

// 内存池统计
typedef struct {
    uint64_t total_alloc;
    uint64_t total_free;
    uint64_t current_usage;
    uint64_t peak_usage;
    uint64_t fragmentation;
} MemoryPoolStats;

// 异步I/O操作类型
typedef enum {
    IO_OP_READ,
    IO_OP_WRITE,
    IO_OP_FLUSH
} IOOperationType;

// 异步I/O请求
typedef struct {
    void* buffer;              // 数据缓冲区
    size_t size;              // 数据大小
    size_t offset;             // 文件偏移
    IOOperationType type;      // 操作类型
    void* user_data;          // 用户数据
    int result;                // 操作结果
    size_t bytes_transferred;  // 传输字节数
#ifdef _WIN32
    OVERLAPPED overlapped;     // Windows重叠结构
    HANDLE file_handle;        // 文件句柄
#else
    struct io_uring_sqe* sqe;  // liburing提交队列项
    int fd;                    // 文件描述符
#endif
} AsyncIORequest;

// 批量I/O操作
typedef struct {
    AsyncIORequest* requests;  // 请求数组
    uint32_t count;            // 请求数量
    uint32_t capacity;         // 容量
    void* batch_buffer;       // 批量缓冲区
} IOBatch;

// 向量化I/O请求
typedef struct {
    void** buffers;           // 缓冲区数组
    size_t* sizes;            // 每个缓冲区大小
    uint32_t count;           // 缓冲区数量
    uint64_t offset;          // 文件偏移
    size_t total_size;        // 总大小
    int fd;                   // 文件描述符
} VectoredIORequest;

// 前向声明
typedef struct MemoryArena MemoryArena;

// 异步I/O引擎
typedef struct {
#ifdef _WIN32
    HANDLE iocp_port;                    // IOCP完成端口
    OVERLAPPED_ENTRY* completion_entries; // 批量完成项数组
    HANDLE io_threads[4];                // IO线程池
#else
    struct io_uring ring;               // io_uring实例
    int io_threads[4];                   // IO线程池
#endif
    uint32_t completion_entries_size;    // 完成项数组大小
    void* thread_pool;                  // 线程池（未实现，保留指针）
    MemoryArena* buffer_arena;          // 统一内存管理
    
    // 性能统计
    uint64_t total_operations;
    uint64_t total_bytes;
    uint64_t failed_operations;
    double avg_latency_us;
} AsyncIOEngine;

// 内存Arena（统一内存管理）
typedef struct {
    void* base;              // 基地址
    size_t size;            // 总大小
    size_t used;            // 已使用
    size_t allocated;       // 已分配
    MemoryBlock* blocks;    // 内存块链表
    ThreadCache* thread_caches; // 线程本地缓存
    uint32_t thread_count;  // 线程数量
    pthread_mutex_t mutex;  // 全局锁
} MemoryArena;

// 小文件批次
typedef struct {
    FileEntry* files;          // 文件数组
    uint32_t count;            // 当前文件数量
    uint32_t capacity;         // 最大容量
    MemoryBlock* data_block;   // 合并的数据内存块
    uint64_t* offsets;         // 各文件在数据块中的偏移
    uint64_t* sizes;           // 各文件大小
    uint8_t* checksums;        // 各文件CRC32校验和
} SmallFileBatch;

// 文件条目
typedef struct {
    uint64_t file_id;          // 文件ID
    char path[512];           // 文件路径
    uint64_t size;            // 文件大小
    uint64_t offset;          // 偏移量
    uint32_t block_id;        // 块ID
    uint64_t create_time;     // 创建时间
    uint64_t modify_time;     // 修改时间
    uint32_t checksum;        // CRC32校验
} FileEntry;

// 初始化异步I/O引擎
AsyncIOEngine* async_io_init(uint32_t num_threads, uint32_t completion_entries);

// 关闭异步I/O引擎
void async_io_shutdown(AsyncIOEngine* engine);

// 提交异步读请求
int async_io_read(AsyncIOEngine* engine, int fd, void* buffer, 
                  size_t size, size_t offset, AsyncIORequest** request);

// 提交异步写请求
int async_io_write(AsyncIOEngine* engine, int fd, const void* buffer, 
                   size_t size, size_t offset, AsyncIORequest** request);

// 批量提交I/O请求
int async_io_submit_batch(AsyncIOEngine* engine, IOBatch* batch);

// 等待I/O完成
int async_io_wait_completion(AsyncIOEngine* engine, uint32_t timeout_ms);

// 初始化内存Arena
MemoryArena* memory_arena_init(size_t size, uint32_t thread_count);

// 关闭内存Arena
void memory_arena_shutdown(MemoryArena* arena);

// 从Arena分配内存
void* arena_alloc(MemoryArena* arena, size_t size, MemoryPoolType type);

// 释放内存到Arena
void arena_free(MemoryArena* arena, void* ptr, size_t size);

// 获取内存池统计信息
void arena_get_stats(MemoryArena* arena, MemoryPoolStats* stats);

// 创建小文件批次
SmallFileBatch* batch_create(uint32_t max_files);

// 添加文件到批次
int batch_add_file(SmallFileBatch* batch, const FileEntry* file, const void* data);

// 提交批次写入
int batch_write(AsyncIOEngine* engine, int fd, SmallFileBatch* batch);

// 销毁批次
void batch_destroy(SmallFileBatch* batch);

#ifdef __cplusplus
}
#endif

#endif // ASYNC_IO_H
