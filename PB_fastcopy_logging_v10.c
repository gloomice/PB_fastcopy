#include "PB_fastcopy_logging_v10.h"
#include <malloc.h>
#include <memory.h>
#include <assert.h>
#include <ntstatus.h>

// NTAPI 函数声明
typedef NTSTATUS (NTAPI *PNT_WRITE_FILE)(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
);

typedef NTSTATUS (NTAPI *PNT_SET_INFORMATION_FILE)(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
);

typedef NTSTATUS (NTAPI *PNT_CREATE_FILE)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
);

// 全局NTAPI函数指针
static PNT_WRITE_FILE           pNtWriteFile = NULL;
static PNT_SET_INFORMATION_FILE pNtSetInformationFile = NULL;
static PNT_CREATE_FILE          pNtCreateFile = NULL;

// ============================================================================
// 内部工具函数
// ============================================================================

// 初始化NTAPI函数指针
static bool pb_ntapi_initialize(void)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;
    
    pNtWriteFile = (PNT_WRITE_FILE)GetProcAddress(ntdll, "NtWriteFile");
    pNtSetInformationFile = (PNT_SET_INFORMATION_FILE)GetProcAddress(ntdll, "NtSetInformationFile");
    pNtCreateFile = (PNT_CREATE_FILE)GetProcAddress(ntdll, "NtCreateFile");
    
    return pNtWriteFile && pNtSetInformationFile && pNtCreateFile;
}

// 获取当前QPC时间戳
static inline uint64_t pb_get_qpc_timestamp(PB_Logger* logger)
{
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    return counter.QuadPart;
}

// 时间戳转换为纳秒
static inline uint64_t pb_qpc_to_ns(PB_Logger* logger, uint64_t qpc)
{
    return qpc * 1000000000ULL / logger->qpc_frequency.QuadPart;
}

// 对齐到缓存行
static inline void* pb_align_cache_line(void* ptr)
{
    const size_t cache_line_size = 64;
    uintptr_t addr = (uintptr_t)ptr;
    addr = (addr + cache_line_size - 1) & ~(cache_line_size - 1);
    return (void*)addr;
}

// 对齐到页面大小
static inline void* pb_align_page(void* ptr)
{
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    uintptr_t addr = (uintptr_t)ptr;
    addr = (addr + sys_info.dwPageSize - 1) & ~(sys_info.dwPageSize - 1);
    return (void*)addr;
}

// ============================================================================
// 无锁环形缓冲区实现
// ============================================================================

// 初始化环形缓冲区
static PB_RingBuffer* pb_ringbuffer_create(size_t buffer_size, size_t max_slot_size, uint32_t producer_id)
{
    // 确保缓冲区大小是缓存行的倍数
    buffer_size = (buffer_size + 63) & ~63;
    
    // 分配对齐的内存
    uint8_t* buffer = (uint8_t*)_aligned_malloc(buffer_size, 64);
    if (!buffer) return NULL;
    
    // 计算槽位数量
    size_t slot_count = buffer_size / (sizeof(PB_RingBufferSlot) + max_slot_size);
    
    PB_RingBuffer* rb = (PB_RingBuffer*)calloc(1, sizeof(PB_RingBuffer));
    if (!rb) {
        _aligned_free(buffer);
        return NULL;
    }
    
    rb->buffer = buffer;
    rb->buffer_size = buffer_size;
    rb->slot_count = slot_count;
    rb->slot_size = max_slot_size;
    rb->producer_id = producer_id;
    rb->write_pos = 0;
    rb->read_pos = 0;
    InitializeCriticalSection(&rb->fallback_lock);
    
    // 初始化序列号
    for (size_t i = 0; i < slot_count; i++) {
        PB_RingBufferSlot* slot = (PB_RingBufferSlot*)(buffer + i * (sizeof(PB_RingBufferSlot) + max_slot_size));
        slot->sequence = i;
    }
    
    return rb;
}

// 销毁环形缓冲区
static void pb_ringbuffer_destroy(PB_RingBuffer* rb)
{
    if (!rb) return;
    
    DeleteCriticalSection(&rb->fallback_lock);
    _aligned_free(rb->buffer);
    free(rb);
}

// 尝试写入环形缓冲区（无锁CAS实现）
static bool pb_ringbuffer_try_write(PB_RingBuffer* rb, const void* data, uint32_t data_size, uint64_t sequence)
{
    if (data_size > rb->slot_size) {
        return false;
    }
    
    uint64_t write_pos = rb->write_pos;
    uint64_t read_pos = rb->read_pos;
    
    // 检查是否已满
    if ((write_pos - read_pos) >= rb->slot_count) {
        return false;
    }
    
    // 计算槽位索引
    uint64_t slot_index = write_pos % rb->slot_count;
    PB_RingBufferSlot* slot = (PB_RingBufferSlot*)(rb->buffer + 
        slot_index * (sizeof(PB_RingBufferSlot) + rb->slot_size));
    
    // 检查槽位是否可用（序列号匹配）
    uint64_t expected_sequence = write_pos;
    uint64_t actual_sequence = InterlockedCompareExchange64((volatile LONG64*)&slot->sequence,
                                                            write_pos + rb->slot_count,
                                                            expected_sequence);
    
    if (actual_sequence != expected_sequence) {
        // 后备路径：使用锁
        EnterCriticalSection(&rb->fallback_lock);
        
        // 重新检查
        if ((rb->write_pos - rb->read_pos) >= rb->slot_count) {
            LeaveCriticalSection(&rb->fallback_lock);
            return false;
        }
        
        slot_index = rb->write_pos % rb->slot_count;
        slot = (PB_RingBufferSlot*)(rb->buffer + 
            slot_index * (sizeof(PB_RingBufferSlot) + rb->slot_size));
        
        // 写入数据
        slot->data_size = data_size;
        memcpy(slot->data, data, data_size);
        
        // 更新序列号（确保可见性）
        _WriteBarrier();
        slot->sequence = rb->write_pos + rb->slot_count;
        
        // 更新写位置
        rb->write_pos++;
        
        LeaveCriticalSection(&rb->fallback_lock);
        return true;
    }
    
    // 无锁写入成功
    slot->data_size = data_size;
    memcpy(slot->data, data, data_size);
    
    // 确保数据在更新序列号之前写入（内存屏障）
    _WriteBarrier();
    
    // 更新序列号
    slot->sequence = write_pos + rb->slot_count;
    
    // 原子更新写位置
    InterlockedIncrement64((volatile LONG64*)&rb->write_pos);
    
    return true;
}

// 从环形缓冲区读取批量数据
static uint32_t pb_ringbuffer_read_batch(PB_RingBuffer* rb, PB_LogEntry** entries, 
                                         uint32_t max_entries, uint64_t* batch_sequence)
{
    uint64_t read_pos = rb->read_pos;
    uint64_t write_pos = rb->write_pos;
    
    if (read_pos >= write_pos) {
        return 0;
    }
    
    uint32_t count = 0;
    uint64_t available = write_pos - read_pos;
    if (available > max_entries) {
        available = max_entries;
    }
    
    for (uint32_t i = 0; i < available; i++) {
        uint64_t slot_index = read_pos % rb->slot_count;
        PB_RingBufferSlot* slot = (PB_RingBufferSlot*)(rb->buffer + 
            slot_index * (sizeof(PB_RingBufferSlot) + rb->slot_size));
        
        // 检查序列号是否有效
        uint64_t expected_sequence = read_pos + rb->slot_count;
        if (slot->sequence != expected_sequence) {
            // 数据尚未准备好
            break;
        }
        
        // 分配内存并复制数据
        size_t entry_size = sizeof(PB_LogEntryHeader) + slot->data_size;
        PB_LogEntry* entry = (PB_LogEntry*)malloc(entry_size);
        if (!entry) break;
        
        // 填充头部
        entry->header.timestamp = pb_get_qpc_timestamp(NULL); // 这里logger未知，使用临时值
        entry->header.data_len = slot->data_size;
        entry->header.sequence = read_pos;
        entry->header.thread_id = rb->producer_id;
        
        // 复制数据
        memcpy(entry->data, slot->data, slot->data_size);
        
        entries[count++] = entry;
        
        // 更新槽位序列号
        slot->sequence = read_pos;
        
        read_pos++;
    }
    
    // 更新读位置
    if (count > 0) {
        InterlockedExchange64((volatile LONG64*)&rb->read_pos, read_pos);
        *batch_sequence = read_pos;
    }
    
    return count;
}

// ============================================================================
// 文件操作实现（NTAPI直接调用）
// ============================================================================

// 使用NTAPI创建文件
static HANDLE pb_nt_create_file(const wchar_t* filename, uint64_t preallocate_size)
{
    if (!pNtCreateFile) return INVALID_HANDLE_VALUE;
    
    UNICODE_STRING uni_name;
    RtlInitUnicodeString(&uni_name, filename);
    
    OBJECT_ATTRIBUTES obj_attr;
    InitializeObjectAttributes(&obj_attr, &uni_name,
                               OBJ_CASE_INSENSITIVE | OBJ_INHERIT,
                               NULL, NULL);
    
    IO_STATUS_BLOCK io_status;
    HANDLE file_handle = NULL;
    
    // 创建选项：无缓冲IO + 写直达
    ULONG create_options = FILE_NO_INTERMEDIATE_BUFFERING | 
                          FILE_WRITE_THROUGH |
                          FILE_SEQUENTIAL_WRITE;
    
    // 预分配大小
    LARGE_INTEGER alloc_size;
    alloc_size.QuadPart = preallocate_size;
    
    NTSTATUS status = pNtCreateFile(&file_handle,
                                    GENERIC_WRITE | SYNCHRONIZE,
                                    &obj_attr,
                                    &io_status,
                                    &alloc_size,  // 预分配
                                    FILE_ATTRIBUTE_NORMAL,
                                    0,
                                    FILE_OVERWRITE_IF,
                                    create_options,
                                    NULL,
                                    0);
    
    if (status != STATUS_SUCCESS) {
        return INVALID_HANDLE_VALUE;
    }
    
    return file_handle;
}

// 使用NTAPI写入文件
static bool pb_nt_write_file(HANDLE file_handle, const void* buffer, 
                            size_t buffer_size, uint64_t offset)
{
    if (!pNtWriteFile || file_handle == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    IO_STATUS_BLOCK io_status;
    LARGE_INTEGER byte_offset;
    byte_offset.QuadPart = offset;
    
    NTSTATUS status = pNtWriteFile(file_handle,
                                   NULL,
                                   NULL,
                                   NULL,
                                   &io_status,
                                   (PVOID)buffer,
                                   (ULONG)buffer_size,
                                   &byte_offset,
                                   NULL);
    
    return status == STATUS_SUCCESS;
}

// 预分配文件空间
static bool pb_nt_preallocate_file(HANDLE file_handle, uint64_t size)
{
    if (!pNtSetInformationFile) return false;
    
    FILE_ALLOCATION_INFORMATION alloc_info;
    alloc_info.AllocationSize.QuadPart = size;
    
    IO_STATUS_BLOCK io_status;
    NTSTATUS status = pNtSetInformationFile(file_handle,
                                           &io_status,
                                           &alloc_info,
                                           sizeof(alloc_info),
                                           FileAllocationInformation);
    
    return status == STATUS_SUCCESS;
}

// ============================================================================
// 主日志器实现
// ============================================================================

// 创建日志器
PB_Logger* pb_logger_create(const PB_LoggerConfig* config)
{
    // 初始化NTAPI
    if (!pb_ntapi_initialize()) {
        return NULL;
    }
    
    // 分配日志器
    PB_Logger* logger = (PB_Logger*)calloc(1, sizeof(PB_Logger));
    if (!logger) return NULL;
    
    // 复制配置
    memcpy(&logger->config, config, sizeof(PB_LoggerConfig));
    
    // 初始化性能计数器
    QueryPerformanceFrequency(&logger->qpc_frequency);
    
    // 初始化锁
    InitializeCriticalSection(&logger->file_lock);
    InitializeCriticalSection(&logger->stats_lock);
    
    // 创建后备文件名
    wcscpy_s(logger->fallback_filename, PB_LOG_MAX_FILENAME_LEN,
             config->filename);
    wcscat_s(logger->fallback_filename, PB_LOG_MAX_FILENAME_LEN, L".fallback");
    
    // 创建文件
    logger->file.handle = pb_nt_create_file(config->filename, config->preallocate_size);
    if (logger->file.handle == INVALID_HANDLE_VALUE) {
        // 尝试使用备用文件名
        logger->file.handle = pb_nt_create_file(logger->fallback_filename, 
                                               config->preallocate_size);
        if (logger->file.handle == INVALID_HANDLE_VALUE) {
            free(logger);
            return NULL;
        }
        logger->degraded_mode = true;
    }
    
    // 预分配文件
    if (config->preallocate_size > 0) {
        pb_nt_preallocate_file(logger->file.handle, config->preallocate_size);
    }
    
    // 创建环形缓冲区
    logger->ring_buffer_count = config->buffer_count;
    logger->ring_buffers = (PB_RingBuffer*)calloc(config->buffer_count, 
                                                 sizeof(PB_RingBuffer));
    
    for (uint32_t i = 0; i < config->buffer_count; i++) {
        logger->ring_buffers[i] = *pb_ringbuffer_create(config->buffer_size,
                                                       config->buffer_size / 64, // 最大槽位大小
                                                       i + 1); // 生产者ID
        if (!logger->ring_buffers[i].buffer) {
            // 清理
            for (uint32_t j = 0; j < i; j++) {
                pb_ringbuffer_destroy(&logger->ring_buffers[j]);
            }
            free(logger->ring_buffers);
            CloseHandle(logger->file.handle);
            free(logger);
            return NULL;
        }
    }
    
    // 创建临时缓冲区（页面对齐）
    logger->scratch_buffer_size = PB_LOG_SCRATCH_BUFFER_SIZE;
    logger->scratch_buffer = (uint8_t*)_aligned_malloc(logger->scratch_buffer_size, 4096);
    if (!logger->scratch_buffer) {
        // 清理
        for (uint32_t i = 0; i < config->buffer_count; i++) {
            pb_ringbuffer_destroy(&logger->ring_buffers[i]);
        }
        free(logger->ring_buffers);
        CloseHandle(logger->file.handle);
        free(logger);
        return NULL;
    }
    
    // 创建事件
    logger->io_start_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    logger->io_stop_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    
    // 启动I/O线程
    logger->io_running = true;
    logger->io_thread = CreateThread(NULL, 0, 
                                    (LPTHREAD_START_ROUTINE)pb_io_thread_proc,
                                    logger,
                                    0, NULL);
    
    if (!logger->io_thread) {
        // 清理
        pb_logger_destroy(logger);
        return NULL;
    }
    
    // 设置CPU亲和性和优先级
    if (config->io_thread_affinity != 0) {
        SetThreadAffinityMask(logger->io_thread, config->io_thread_affinity);
    }
    SetThreadPriority(logger->io_thread, config->io_thread_priority);
    
    // 触发I/O线程开始
    SetEvent(logger->io_start_event);
    
    return logger;
}

// I/O线程处理函数
static DWORD WINAPI pb_io_thread_proc(LPVOID param)
{
    PB_Logger* logger = (PB_Logger*)param;
    
    // 等待开始信号
    WaitForSingleObject(logger->io_start_event, INFINITE);
    
    PB_LogEntry* batch_entries[PB_LOG_MAX_BATCH_SIZE];
    uint8_t* write_buffer = logger->scratch_buffer;
    size_t write_buffer_used = 0;
    uint64_t last_flush_time = pb_get_qpc_timestamp(logger);
    
    while (logger->io_running) {
        uint32_t total_entries = 0;
        uint64_t current_time = pb_get_qpc_timestamp(logger);
        
        // 收集所有环形缓冲区的数据
        for (uint32_t i = 0; i < logger->ring_buffer_count; i++) {
            uint64_t batch_sequence;
            uint32_t entries_read = pb_ringbuffer_read_batch(
                &logger->ring_buffers[i],
                batch_entries + total_entries,
                PB_LOG_MAX_BATCH_SIZE - total_entries,
                &batch_sequence);
            
            total_entries += entries_read;
            
            if (total_entries >= PB_LOG_MAX_BATCH_SIZE) {
                break;
            }
        }
        
        // 处理收集到的条目
        if (total_entries > 0) {
            // 序列化到临时缓冲区
            for (uint32_t i = 0; i < total_entries; i++) {
                PB_LogEntry* entry = batch_entries[i];
                size_t entry_size = sizeof(PB_LogEntryHeader) + entry->header.data_len;
                
                // 检查缓冲区是否足够
                if (write_buffer_used + entry_size > logger->scratch_buffer_size) {
                    // 写入到文件
                    pb_flush_write_buffer(logger, write_buffer, write_buffer_used);
                    write_buffer_used = 0;
                }
                
                // 复制到缓冲区
                memcpy(write_buffer + write_buffer_used, entry, entry_size);
                write_buffer_used += entry_size;
                
                // 释放条目内存
                free(entry);
            }
            
            // 更新统计信息
            EnterCriticalSection(&logger->stats_lock);
            logger->stats.total_entries_written += total_entries;
            logger->stats.total_bytes_written += write_buffer_used;
            logger->stats.total_batches++;
            LeaveCriticalSection(&logger->stats_lock);
        }
        
        // 定期刷新
        uint64_t elapsed_ns = pb_qpc_to_ns(logger, current_time - last_flush_time);
        if (elapsed_ns > logger->config.flush_interval_ms * 1000000ULL ||
            write_buffer_used > logger->scratch_buffer_size / 2) {
            if (write_buffer_used > 0) {
                pb_flush_write_buffer(logger, write_buffer, write_buffer_used);
                write_buffer_used = 0;
            }
            last_flush_time = current_time;
        }
        
        // 如果没有数据，稍微休眠
        if (total_entries == 0) {
            Sleep(1);
        }
        
        // 检查停止信号
        if (WaitForSingleObject(logger->io_stop_event, 0) == WAIT_OBJECT_0) {
            break;
        }
    }
    
    // 刷新剩余数据
    if (write_buffer_used > 0) {
        pb_flush_write_buffer(logger, write_buffer, write_buffer_used);
    }
    
    return 0;
}

// 刷新写入缓冲区到文件
static void pb_flush_write_buffer(PB_Logger* logger, const uint8_t* buffer, size_t size)
{
    if (size == 0) return;
    
    EnterCriticalSection(&logger->file_lock);
    
    // 检查文件大小限制
    if (logger->file.current_pos + size > logger->config.max_file_size) {
        // 滚动到新文件
        pb_rotate_log_file(logger);
    }
    
    // 对齐写入（无缓冲IO要求）
    size_t aligned_size = (size + 511) & ~511; // 对齐到512字节扇区
    if (aligned_size > size) {
        // 填充零
        uint8_t* aligned_buffer = (uint8_t*)_aligned_malloc(aligned_size, 512);
        if (aligned_buffer) {
            memcpy(aligned_buffer, buffer, size);
            memset(aligned_buffer + size, 0, aligned_size - size);
            buffer = aligned_buffer;
        }
    }
    
    // 写入文件
    uint64_t start_time = pb_get_qpc_timestamp(logger);
    bool success = pb_nt_write_file(logger->file.handle, buffer, aligned_size, 
                                   logger->file.current_pos);
    uint64_t end_time = pb_get_qpc_timestamp(logger);
    
    if (aligned_size > size && buffer != aligned_buffer) {
        _aligned_free((void*)buffer);
    }
    
    if (success) {
        logger->file.current_pos += aligned_size;
        
        // 更新延迟统计
        uint64_t latency_ns = pb_qpc_to_ns(logger, end_time - start_time);
        EnterCriticalSection(&logger->stats_lock);
        if (latency_ns > logger->stats.max_latency_ns) {
            logger->stats.max_latency_ns = latency_ns;
        }
        if (latency_ns < logger->stats.min_latency_ns || 
            logger->stats.min_latency_ns == 0) {
            logger->stats.min_latency_ns = latency_ns;
        }
        // 简单移动平均
        logger->stats.avg_latency_ns = 
            (logger->stats.avg_latency_ns * 7 + latency_ns) / 8;
        LeaveCriticalSection(&logger->stats_lock);
    } else {
        // 写入失败，进入降级模式
        logger->degraded_mode = true;
        
        // 尝试写入后备文件
        HANDLE fallback_handle = pb_nt_create_file(logger->fallback_filename, 0);
        if (fallback_handle != INVALID_HANDLE_VALUE) {
            pb_nt_write_file(fallback_handle, buffer, aligned_size, 0);
            CloseHandle(fallback_handle);
        }
        
        EnterCriticalSection(&logger->stats_lock);
        logger->stats.total_dropped++;
        LeaveCriticalSection(&logger->stats_lock);
    }
    
    LeaveCriticalSection(&logger->file_lock);
}

// 滚动日志文件
static void pb_rotate_log_file(PB_Logger* logger)
{
    CloseHandle(logger->file.handle);
    
    // 生成带时间戳的新文件名
    wchar_t new_filename[PB_LOG_MAX_FILENAME_LEN];
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    _snwprintf_s(new_filename, PB_LOG_MAX_FILENAME_LEN, _TRUNCATE,
                L"%s.%04d%02d%02d_%02d%02d%02d.log",
                logger->config.filename,
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond);
    
    // 创建新文件
    logger->file.handle = pb_nt_create_file(new_filename, 
                                           logger->config.preallocate_size);
    logger->file.current_pos = 0;
    
    if (logger->file.handle == INVALID_HANDLE_VALUE) {
        // 回退到原文件
        logger->file.handle = pb_nt_create_file(logger->config.filename,
                                               logger->config.preallocate_size);
        logger->degraded_mode = true;
    } else {
        logger->degraded_mode = false;
    }
    
    // 清理旧文件
    pb_cleanup_old_files(logger);
}

// 清理旧文件
static void pb_cleanup_old_files(PB_Logger* logger)
{
    wchar_t search_pattern[PB_LOG_MAX_FILENAME_LEN];
    wcscpy_s(search_pattern, PB_LOG_MAX_FILENAME_LEN, logger->config.filename);
    wcscat_s(search_pattern, PB_LOG_MAX_FILENAME_LEN, L".*.log");
    
    WIN32_FIND_DATA find_data;
    HANDLE find_handle = FindFirstFile(search_pattern, &find_data);
    
    if (find_handle != INVALID_HANDLE_VALUE) {
        FILETIME oldest_allowed;
        GetSystemTimeAsFileTime(&oldest_allowed);
        
        // 计算允许的最旧时间（保留最近N个文件）
        // 这里简化处理，实际需要根据时间排序
        
        do {
            // 构建完整路径
            wchar_t full_path[MAX_PATH];
            wchar_t* last_backslash = wcsrchr(logger->config.filename, L'\\');
            if (last_backslash) {
                size_t dir_len = last_backslash - logger->config.filename + 1;
                wcsncpy_s(full_path, MAX_PATH, logger->config.filename, dir_len);
                wcscat_s(full_path, MAX_PATH, find_data.cFileName);
            } else {
                wcscpy_s(full_path, MAX_PATH, find_data.cFileName);
            }
            
            // 删除文件
            DeleteFile(full_path);
            
        } while (FindNextFile(find_handle, &find_data));
        
        FindClose(find_handle);
    }
}

// ============================================================================
// 公共API实现
// ============================================================================

// 写入单条日志
bool pb_log(PB_Logger* logger, uint16_t module_id, uint8_t level, 
            const void* data, uint32_t data_len)
{
    if (!logger || !data || data_len == 0) return false;
    
    // 根据线程ID选择环形缓冲区（减少竞争）
    uint32_t thread_id = GetCurrentThreadId();
    uint32_t buffer_index = thread_id % logger->ring_buffer_count;
    PB_RingBuffer* rb = &logger->ring_buffers[buffer_index];
    
    // 构建日志条目
    size_t entry_size = sizeof(PB_LogEntryHeader) + data_len;
    uint8_t* entry_buffer = (uint8_t*)alloca(entry_size);
    PB_LogEntry* entry = (PB_LogEntry*)entry_buffer;
    
    entry->header.timestamp = pb_get_qpc_timestamp(logger);
    entry->header.module_id = module_id;
    entry->header.level = level;
    entry->header.data_len = data_len;
    entry->header.thread_id = thread_id;
    entry->header.sequence = InterlockedIncrement64((volatile LONG64*)&logger->sequence_counter);
    
    memcpy(entry->data, data, data_len);
    
    // 尝试写入环形缓冲区
    bool success = pb_ringbuffer_try_write(rb, entry_buffer, (uint32_t)entry_size, 
                                          logger->sequence_counter);
    
    if (!success) {
        // 更新丢弃统计
        EnterCriticalSection(&logger->stats_lock);
        logger->stats.total_dropped++;
        LeaveCriticalSection(&logger->stats_lock);
    }
    
    return success;
}

// 批量写入日志
bool pb_log_batch(PB_Logger* logger, const PB_LogEntry** entries, 
                 uint32_t count, uint16_t module_id)
{
    if (!logger || !entries || count == 0 || count > PB_LOG_MAX_BATCH_SIZE) {
        return false;
    }
    
    uint32_t success_count = 0;
    uint32_t thread_id = GetCurrentThreadId();
    uint32_t buffer_index = thread_id % logger->ring_buffer_count;
    PB_RingBuffer* rb = &logger->ring_buffers[buffer_index];
    
    for (uint32_t i = 0; i < count; i++) {
        const PB_LogEntry* entry = entries[i];
        
        // 构建完整的条目数据
        size_t entry_size = sizeof(PB_LogEntryHeader) + entry->header.data_len;
        
        // 写入环形缓冲区
        if (pb_ringbuffer_try_write(rb, entry, (uint32_t)entry_size, 
                                   logger->sequence_counter)) {
            success_count++;
            InterlockedIncrement64((volatile LONG64*)&logger->sequence_counter);
        }
    }
    
    if (success_count < count) {
        EnterCriticalSection(&logger->stats_lock);
        logger->stats.total_dropped += (count - success_count);
        LeaveCriticalSection(&logger->stats_lock);
    }
    
    return success_count > 0;
}

// 性能日志
bool pb_log_performance(PB_Logger* logger, const PB_PerfData* perf_data)
{
    if (!logger || !perf_data) return false;
    
    // 计算路径长度
    size_t path_len = wcslen(perf_data->source_path) * sizeof(wchar_t);
    size_t data_size = offsetof(PB_PerfData, source_path) + path_len;
    
    // 构建二进制数据
    uint8_t* buffer = (uint8_t*)alloca(data_size);
    memcpy(buffer, perf_data, data_size);
    
    return pb_log(logger, PB_LOG_MODULE_PERF, PB_LOG_LEVEL_PERF, 
                 buffer, (uint32_t)data_size);
}

// 错误日志
bool pb_log_error(PB_Logger* logger, uint16_t module_id, uint32_t error_code,
                 const wchar_t* function_name, uint32_t line,
                 const wchar_t* additional_info)
{
    if (!logger) return false;
    
    // 计算数据大小
    size_t func_name_len = wcslen(function_name) * sizeof(wchar_t);
    size_t info_len = additional_info ? wcslen(additional_info) * sizeof(wchar_t) : 0;
    size_t data_size = offsetof(PB_ErrorData, additional_info) + info_len;
    
    // 构建错误数据
    uint8_t* buffer = (uint8_t*)alloca(data_size);
    PB_ErrorData* error_data = (PB_ErrorData*)buffer;
    
    error_data->error_code = error_code;
    error_data->line_number = line;
    wcsncpy_s(error_data->function_name, 32, function_name, _TRUNCATE);
    
    if (additional_info && info_len > 0) {
        wcsncpy_s(error_data->additional_info, info_len / sizeof(wchar_t) + 1,
                 additional_info, _TRUNCATE);
    }
    
    return pb_log(logger, module_id, PB_LOG_LEVEL_ERROR, buffer, (uint32_t)data_size);
}

// 刷新日志
void pb_logger_flush(PB_Logger* logger)
{
    if (!logger) return;
    
    // 通知I/O线程立即刷新
    SetEvent(logger->io_start_event);
}

// 获取统计信息
void pb_logger_get_stats(PB_Logger* logger, PB_LogStatistics* stats)
{
    if (!logger || !stats) return;
    
    EnterCriticalSection(&logger->stats_lock);
    memcpy(stats, &logger->stats, sizeof(PB_LogStatistics));
    LeaveCriticalSection(&logger->stats_lock);
}

// 重置统计信息
void pb_logger_reset_stats(PB_Logger* logger)
{
    if (!logger) return;
    
    EnterCriticalSection(&logger->stats_lock);
    memset(&logger->stats, 0, sizeof(PB_LogStatistics));
    LeaveCriticalSection(&logger->stats_lock);
}

// 检查是否降级
bool pb_logger_is_degraded(PB_Logger* logger)
{
    return logger ? logger->degraded_mode : false;
}

// 销毁日志器
void pb_logger_destroy(PB_Logger* logger)
{
    if (!logger) return;
    
    // 停止I/O线程
    logger->io_running = false;
    SetEvent(logger->io_stop_event);
    
    // 等待I/O线程结束
    WaitForSingleObject(logger->io_thread, 5000);
    
    // 关闭句柄
    CloseHandle(logger->io_thread);
    CloseHandle(logger->io_start_event);
    CloseHandle(logger->io_stop_event);
    
    // 刷新并关闭文件
    if (logger->file.handle != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(logger->file.handle);
        CloseHandle(logger->file.handle);
    }
    
    // 清理环形缓冲区
    for (uint32_t i = 0; i < logger->ring_buffer_count; i++) {
        pb_ringbuffer_destroy(&logger->ring_buffers[i]);
    }
    free(logger->ring_buffers);
    
    // 清理临时缓冲区
    if (logger->scratch_buffer) {
        _aligned_free(logger->scratch_buffer);
    }
    
    // 删除锁
    DeleteCriticalSection(&logger->file_lock);
    DeleteCriticalSection(&logger->stats_lock);
    
    // 释放日志器
    free(logger);
}

// ============================================================================
// 示例使用代码
// ============================================================================

// 初始化示例配置
PB_LoggerConfig pb_create_default_config(const wchar_t* filename)
{
    PB_LoggerConfig config = {0};
    
    wcscpy_s(config.filename, PB_LOG_MAX_FILENAME_LEN, filename);
    config.buffer_count = 4;  // 每个CPU核心一个缓冲区
    config.buffer_size = PB_LOG_DEFAULT_BUFFER_SIZE;
    config.preallocate_size = PB_LOG_PREALLOC_SIZE;
    config.io_thread_affinity = 1 << 7;  // 绑定到第8个CPU核心
    config.io_thread_priority = THREAD_PRIORITY_LOWEST;
    config.enable_binary_log = true;
    config.enable_compression = false;
    config.enable_async_flush = true;
    config.flush_interval_ms = 1000;  // 1秒刷新一次
    config.max_file_size = 100 * 1024 * 1024;  // 100MB
    config.max_file_count = 10;  // 保留最近10个文件
    
    return config;
}

// 使用示例
/*
int main()
{
    // 创建配置
    PB_LoggerConfig config = pb_create_default_config(L"C:\\logs\\fastcopy.log");
    
    // 创建日志器
    PB_Logger* logger = pb_logger_create(&config);
    if (!logger) {
        printf("Failed to create logger\n");
        return 1;
    }
    
    // 记录性能数据
    PB_PerfData perf_data = {0};
    perf_data.copy_start_time = pb_get_qpc_timestamp(logger);
    perf_data.copy_end_time = perf_data.copy_start_time + 1000000;
    perf_data.file_size = 1024 * 1024;  // 1MB
    wcscpy_s(perf_data.source_path, 256, L"C:\\source\\file.txt");
    
    pb_log_performance(logger, &perf_data);
    
    // 记录错误
    pb_log_error(logger, PB_LOG_MODULE_COPY, ERROR_FILE_NOT_FOUND,
                L"copy_file_worker", 123, L"Source file does not exist");
    
    // 获取统计信息
    PB_LogStatistics stats;
    pb_logger_get_stats(logger, &stats);
    printf("Entries written: %llu\n", stats.total_entries_written);
    printf("Bytes written: %llu\n", stats.total_bytes_written);
    
    // 清理
    pb_logger_destroy(logger);
    
    return 0;
}
*/