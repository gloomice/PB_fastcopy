#ifndef PB_FASTCOPY_LOGGING_V10_H
#define PB_FASTCOPY_LOGGING_V10_H

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// ============================================================================
// 常量定义
// ============================================================================
#define PB_LOG_MAX_MODULES          256
#define PB_LOG_MAX_FILENAME_LEN     1024
#define PB_LOG_DEFAULT_BUFFER_SIZE  (64 * 1024)     // 64KB 每个环形缓冲区
#define PB_LOG_MAX_BATCH_SIZE       1024            // 单次批量最大条目数
#define PB_LOG_PREALLOC_SIZE        (1 * 1024 * 1024 * 1024) // 1GB 预分配
#define PB_LOG_SCRATCH_BUFFER_SIZE  (4 * 1024 * 1024) // 4MB 临时缓冲区

// 日志级别（二进制存储，减少字符串操作）
typedef enum {
    PB_LOG_LEVEL_DEBUG   = 0x01,    // 调试信息
    PB_LOG_LEVEL_INFO    = 0x02,    // 常规信息
    PB_LOG_LEVEL_WARN    = 0x04,    // 警告
    PB_LOG_LEVEL_ERROR   = 0x08,    // 错误
    PB_LOG_LEVEL_FATAL   = 0x10,    // 致命错误
    PB_LOG_LEVEL_PERF    = 0x20     // 性能统计
} PB_LogLevel;

// 模块ID定义（可根据需要扩展）
typedef enum {
    PB_LOG_MODULE_CORE      = 0x0001,  // 核心模块
    PB_LOG_MODULE_COPY      = 0x0002,  // 文件复制模块
    PB_LOG_MODULE_META      = 0x0004,  // 元数据管理
    PB_LOG_MODULE_IO        = 0x0008,  // IO管理
    PB_LOG_MODULE_NETWORK   = 0x0010,  // 网络传输
    PB_LOG_MODULE_MONITOR   = 0x0020,  // 监控模块
    PB_LOG_MODULE_ALL       = 0xFFFF   // 所有模块
} PB_LogModule;

// 二进制日志条目头部（紧凑存储）
#pragma pack(push, 1)
typedef struct {
    uint64_t timestamp;          // QPC 时间戳 (8字节)
    uint16_t module_id;          // 模块ID (2字节)
    uint8_t  level;              // 日志级别 (1字节)
    uint8_t  reserved;           // 保留 (1字节)
    uint32_t data_len;           // 数据长度 (4字节)
    uint32_t thread_id;          // 线程ID (4字节)
    uint64_t sequence;           // 序列号 (8字节)
    // 可变长度数据紧随其后
} PB_LogEntryHeader;

// 性能统计数据结构
typedef struct {
    uint64_t copy_start_time;
    uint64_t copy_end_time;
    uint64_t file_size;
    uint64_t bytes_transferred;
    uint32_t file_attributes;
    wchar_t  source_path[1];     // 可变长度
} PB_PerfData;

// 错误信息数据结构
typedef struct {
    uint32_t error_code;
    uint32_t line_number;
    wchar_t  function_name[32];
    wchar_t  additional_info[1]; // 可变长度
} PB_ErrorData;
#pragma pack(pop)

// 内存中的日志条目
typedef struct {
    PB_LogEntryHeader header;
    uint8_t           data[1];   // 可变长度数据
} PB_LogEntry;

// 环形缓冲区槽位
typedef struct {
    volatile uint64_t sequence;      // 序列号，用于无锁同步
    uint32_t          data_size;     // 数据大小
    uint8_t           data[0];       // 可变长度数据
} PB_RingBufferSlot;

// 无锁环形缓冲区
typedef struct {
    uint8_t*          buffer;        // 缓冲区内存
    size_t            buffer_size;   // 缓冲区大小（字节）
    size_t            slot_count;    // 槽位数量
    size_t            slot_size;     // 每个槽位最大大小
    volatile uint64_t write_pos;     // 写位置（生产者）
    volatile uint64_t read_pos;      // 读位置（消费者）
    uint32_t          producer_id;   // 生产者ID
    CRITICAL_SECTION  fallback_lock; // 后备锁（仅用于极端情况）
} PB_RingBuffer;

// I/O统计信息
typedef struct {
    uint64_t total_entries_written;
    uint64_t total_bytes_written;
    uint64_t total_batches;
    uint64_t total_dropped;
    uint64_t max_latency_ns;
    uint64_t min_latency_ns;
    uint64_t avg_latency_ns;
} PB_LogStatistics;

// 日志器配置
typedef struct {
    wchar_t    filename[PB_LOG_MAX_FILENAME_LEN];
    uint32_t   buffer_count;         // 环形缓冲区数量
    size_t     buffer_size;          // 每个缓冲区大小
    size_t     preallocate_size;     // 文件预分配大小
    DWORD      io_thread_affinity;   // I/O线程CPU亲和性
    DWORD      io_thread_priority;   // I/O线程优先级
    bool       enable_binary_log;    // 启用二进制日志
    bool       enable_compression;   // 启用压缩（预留）
    bool       enable_async_flush;   // 启用异步刷新
    uint32_t   flush_interval_ms;    // 刷新间隔
    size_t     max_file_size;        // 最大文件大小
    uint32_t   max_file_count;       // 最大文件数量
} PB_LoggerConfig;

// 文件句柄包装（支持预分配）
typedef struct {
    HANDLE     handle;
    uint64_t   file_size;
    uint64_t   current_pos;
    uint64_t   preallocated_size;
    bool       use_unbuffered_io;
} PB_LogFile;

// 主日志器结构
typedef struct PB_Logger {
    // 配置
    PB_LoggerConfig     config;
    
    // 文件管理
    PB_LogFile          file;
    CRITICAL_SECTION    file_lock;
    
    // 环形缓冲区池
    PB_RingBuffer*      ring_buffers;
    uint32_t            ring_buffer_count;
    
    // I/O线程
    HANDLE              io_thread;
    HANDLE              io_start_event;
    HANDLE              io_stop_event;
    volatile bool       io_running;
    
    // 批量处理
    uint8_t*            scratch_buffer;
    size_t              scratch_buffer_size;
    
    // 统计信息
    PB_LogStatistics    stats;
    CRITICAL_SECTION    stats_lock;
    
    // 性能计数器
    LARGE_INTEGER       qpc_frequency;
    uint64_t            sequence_counter;
    
    // 降级处理
    volatile bool       degraded_mode;
    wchar_t             fallback_filename[PB_LOG_MAX_FILENAME_LEN];
} PB_Logger;

// ============================================================================
// 公共API
// ============================================================================

// 初始化日志系统
PB_Logger* pb_logger_create(const PB_LoggerConfig* config);

// 销毁日志系统
void pb_logger_destroy(PB_Logger* logger);

// 单条日志（线程安全）
bool pb_log(PB_Logger* logger, uint16_t module_id, uint8_t level, 
            const void* data, uint32_t data_len);

// 批量日志（更高性能）
bool pb_log_batch(PB_Logger* logger, const PB_LogEntry** entries, 
                 uint32_t count, uint16_t module_id);

// 性能日志专用接口
bool pb_log_performance(PB_Logger* logger, const PB_PerfData* perf_data);

// 错误日志专用接口
bool pb_log_error(PB_Logger* logger, uint16_t module_id, uint32_t error_code,
                 const wchar_t* function_name, uint32_t line,
                 const wchar_t* additional_info);

// 刷新日志到磁盘
void pb_logger_flush(PB_Logger* logger);

// 获取统计信息
void pb_logger_get_stats(PB_Logger* logger, PB_LogStatistics* stats);

// 重置统计信息
void pb_logger_reset_stats(PB_Logger* logger);

// 检查是否处于降级模式
bool pb_logger_is_degraded(PB_Logger* logger);

// ============================================================================
// 高级宏（生产环境使用）
// ============================================================================

#define PB_LOG_DEBUG(logger, module, fmt, ...) \
    do { \
        wchar_t __buf[512]; \
        _snwprintf_s(__buf, _countof(__buf), _TRUNCATE, fmt, ##__VA_ARGS__); \
        pb_log(logger, module, PB_LOG_LEVEL_DEBUG, __buf, (wcslen(__buf) + 1) * sizeof(wchar_t)); \
    } while(0)

#define PB_LOG_ERROR(logger, module, error_code, fmt, ...) \
    do { \
        wchar_t __buf[512]; \
        _snwprintf_s(__buf, _countof(__buf), _TRUNCATE, fmt, ##__VA_ARGS__); \
        pb_log_error(logger, module, error_code, L##__FUNCTIONW__, __LINE__, __buf); \
    } while(0)

#define PB_LOG_PERFORMANCE(logger, start_time, end_time, size, path) \
    do { \
        PB_PerfData __perf = { start_time, end_time, size, size, 0 }; \
        wcsncpy_s(__perf.source_path, _countof(__perf.source_path), path, _TRUNCATE); \
        pb_log_performance(logger, &__perf); \
    } while(0)

#endif // PB_FASTCOPY_LOGGING_V10_H