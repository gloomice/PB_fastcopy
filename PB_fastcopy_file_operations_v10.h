#ifndef PB_FASTCOPY_FILE_OPERATIONS_V10_H
#define PB_FASTCOPY_FILE_OPERATIONS_V10_H

#include <windows.h>
#include <winioctl.h>
#include <ntstatus.h>
#include <fileapi.h>
#include <ioapiset.h>
#include <memoryapi.h>
#include <sysinfoapi.h>
#include <errhandlingapi.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// 常量定义
// ============================================================================

// 系统版本检测
#define PB_WIN10_20H2 0x0A00  // Windows 10 20H2

// 缓存行大小（现代CPU通常为64字节）
#define PB_CACHE_LINE_SIZE 64

// 对齐宏
#define PB_ALIGN_UP(x, align) (((x) + ((align) - 1)) & ~((align) - 1))
#define PB_ALIGN_DOWN(x, align) ((x) & ~((align) - 1))
#define PB_CACHE_LINE_ALIGN __declspec(align(PB_CACHE_LINE_SIZE))

// 默认配置
#define PB_DEFAULT_SECTOR_SIZE 4096
#define PB_DEFAULT_QUEUE_DEPTH 256
#define PB_MAX_WORKER_THREADS 64
#define PB_MAX_BATCH_SIZE 128
#define PB_MAX_PATH_LENGTH 32768  // 支持长路径

// 内存池配置
#define PB_LARGE_PAGE_SIZE (2 * 1024 * 1024)  // 2MB大页
#define PB_BUFFER_POOL_SIZE (256 * 1024 * 1024)  // 256MB缓冲区池
#define PB_MAX_BUFFER_SIZE (64 * 1024 * 1024)  // 单个缓冲区最大64MB

// I/O策略阈值
#define PB_INLINE_THRESHOLD (16 * 1024)        // 16KB以下使用内联
#define PB_MMAP_THRESHOLD (1 * 1024 * 1024)    // 1MB以下使用内存映射
#define PB_BLOCK_CLONE_THRESHOLD (64 * 1024 * 1024)  // 64MB以上尝试块克隆

// ============================================================================
// 类型定义
// ============================================================================

// NTAPI函数指针类型定义
typedef NTSTATUS (NTAPI *PFN_NT_CREATE_FILE)(
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

typedef NTSTATUS (NTAPI *PFN_NT_READ_FILE)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
);

typedef NTSTATUS (NTAPI *PFN_NT_WRITE_FILE)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
);

typedef NTSTATUS (NTAPI *PFN_NT_QUERY_INFORMATION_FILE)(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
);

typedef NTSTATUS (NTAPI *PFN_NT_SET_INFORMATION_FILE)(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
);

// I/O策略枚举
typedef enum {
    PB_IO_STRATEGY_INLINE = 0,        // <16KB: 元数据+数据一体化
    PB_IO_STRATEGY_MMAP = 1,          // 16KB-1MB: 内存映射
    PB_IO_STRATEGY_ASYNC = 2,         // 1MB-64MB: 异步I/O
    PB_IO_STRATEGY_BLOCK_CLONE = 3,   // >64MB: 块克隆
    PB_IO_STRATEGY_DEFAULT = 4        // 默认策略
} PB_IO_Strategy;

// I/O优先级提示
typedef enum {
    PB_IO_PRIORITY_HINT_VERY_LOW = 0,
    PB_IO_PRIORITY_HINT_LOW = 1,
    PB_IO_PRIORITY_HINT_NORMAL = 2,
    PB_IO_PRIORITY_HINT_HIGH = 3,
    PB_IO_PRIORITY_HINT_CRITICAL = 4
} PB_IO_Priority_Hint;

// 异步操作状态
typedef enum {
    PB_ASYNC_STATE_IDLE = 0,
    PB_ASYNC_STATE_OPEN_SRC = 1,
    PB_ASYNC_STATE_OPEN_DST = 2,
    PB_ASYNC_STATE_READ = 3,
    PB_ASYNC_STATE_WRITE = 4,
    PB_ASYNC_STATE_CLOSE = 5,
    PB_ASYNC_STATE_COMPLETE = 6,
    PB_ASYNC_STATE_ERROR = 7
} PB_Async_State;

// 内存缓冲区状态
typedef enum {
    PB_BUFFER_FREE = 0,
    PB_BUFFER_ALLOCATED = 1,
    PB_BUFFER_IN_USE = 2,
    PB_BUFFER_PENDING = 3
} PB_Buffer_State;

// ============================================================================
// 核心数据结构
// ============================================================================

// 原子性能计数器（缓存行对齐）
PB_CACHE_LINE_ALIGN typedef struct {
    atomic_uint_least64_t copied_bytes;
    atomic_uint_least64_t file_count;
    atomic_uint_least64_t io_operations;
    atomic_uint_least64_t total_time_ns;
    uint8_t padding[PB_CACHE_LINE_SIZE - 32];  // 填充到64字节
} PB_PerfCounter;

// 内存缓冲区描述符
PB_CACHE_LINE_ALIGN typedef struct {
    void* address;
    size_t size;
    atomic_int state;
    DWORD numa_node;
    ULONG_PTR alignment_mask;
    struct PB_BufferDesc* next;
} PB_BufferDesc;

// 静态缓冲区池
typedef struct {
    PB_BufferDesc* buffers;
    size_t buffer_count;
    size_t buffer_size;
    atomic_size_t free_count;
    PB_BufferDesc* free_list;
    HANDLE heap;
    DWORD numa_node;
} PB_StaticBufferPool;

// 内存池配置
typedef struct {
    size_t page_size;
    size_t large_page_size;
    BOOL use_large_pages;
    BOOL lock_pages;
    DWORD allocation_flags;
} PB_MemoryConfig;

// 异步I/O上下文
PB_CACHE_LINE_ALIGN typedef struct {
    OVERLAPPED overlapped;
    HANDLE src_handle;
    HANDLE dst_handle;
    PB_BufferDesc* buffer;
    LARGE_INTEGER file_size;
    LARGE_INTEGER bytes_transferred;
    PB_Async_State state;
    PB_IO_Strategy strategy;
    DWORD last_error;
    ULONG_PTR user_context;
    struct PB_AsyncIOContext* next;
} PB_AsyncIOContext;

// 无锁队列节点
PB_CACHE_LINE_ALIGN typedef struct {
    void* data;
    atomic_uintptr_t next;
} PB_LockFreeNode;

// 无锁队列
typedef struct {
    atomic_uintptr_t head;
    atomic_uintptr_t tail;
    size_t capacity;
    PB_LockFreeNode* nodes;
    atomic_size_t count;
} PB_LockFreeQueue;

// 文件传输任务
PB_CACHE_LINE_ALIGN typedef struct {
    WCHAR src_path[PB_MAX_PATH_LENGTH];
    WCHAR dst_path[PB_MAX_PATH_LENGTH];
    LARGE_INTEGER file_size;
    FILETIME creation_time;
    FILETIME last_write_time;
    DWORD attributes;
    PB_IO_Strategy strategy;
    PB_IO_Priority_Hint priority;
    atomic_int status;
    ULONG_PTR task_id;
    PB_AsyncIOContext* io_context;
} PB_TransferTask;

// NUMA节点信息
typedef struct {
    DWORD node_number;
    ULONGLONG available_memory;
    DWORD processor_count;
    ULONGLONG processor_mask;
} PB_NumaNodeInfo;

// 线程上下文
PB_CACHE_LINE_ALIGN typedef struct {
    DWORD thread_id;
    HANDLE thread_handle;
    DWORD processor_core;
    DWORD numa_node;
    PB_PerfCounter local_perf;
    PB_StaticBufferPool* local_buffer_pool;
    HANDLE iocp;
    atomic_bool running;
} PB_ThreadContext;

// 复制引擎主上下文
typedef struct {
    // 配置
    size_t sector_size;
    size_t queue_depth;
    DWORD worker_thread_count;
    BOOL use_io_ring;
    BOOL enable_block_clone;
    BOOL numa_aware;
    
    // 性能统计
    PB_PerfCounter perf;
    
    // 内存管理
    PB_MemoryConfig memory_config;
    PB_StaticBufferPool* buffer_pools;
    size_t buffer_pool_count;
    
    // 线程管理
    PB_ThreadContext* workers;
    DWORD worker_count;
    
    // I/O完成端口
    HANDLE iocp;
    
    // 任务队列
    PB_LockFreeQueue* task_queue;
    
    // NTAPI函数指针
    PFN_NT_CREATE_FILE NtCreateFile;
    PFN_NT_READ_FILE NtReadFile;
    PFN_NT_WRITE_FILE NtWriteFile;
    PFN_NT_QUERY_INFORMATION_FILE NtQueryInformationFile;
    PFN_NT_SET_INFORMATION_FILE NtSetInformationFile;
    
    // 状态标志
    atomic_bool initialized;
    atomic_bool shutting_down;
} PB_CopyContext;

// ============================================================================
// 公共API
// ============================================================================

// 初始化/清理
PB_CopyContext* PB_CreateContext();
BOOL PB_InitializeContext(PB_CopyContext* ctx, DWORD worker_count);
void PB_DestroyContext(PB_CopyContext* ctx);

// 内存管理
void* PB_AllocateAligned(size_t size, size_t alignment, DWORD numa_node);
void PB_FreeAligned(void* ptr);
PB_StaticBufferPool* PB_CreateBufferPool(size_t buffer_size, size_t count, DWORD numa_node);
PB_BufferDesc* PB_AcquireBuffer(PB_StaticBufferPool* pool);
void PB_ReleaseBuffer(PB_StaticBufferPool* pool, PB_BufferDesc* buffer);

// 文件操作
BOOL PB_CopyFile(PB_CopyContext* ctx, const WCHAR* src, const WCHAR* dst);
BOOL PB_CopyFileEx(PB_CopyContext* ctx, const WCHAR* src, const WCHAR* dst, 
                   PB_IO_Strategy strategy, PB_IO_Priority_Hint priority);

// 批量操作
BOOL PB_EnqueueTask(PB_CopyContext* ctx, PB_TransferTask* task);
BOOL PB_StartWorkers(PB_CopyContext* ctx);
BOOL PB_StopWorkers(PB_CopyContext* ctx);

// 性能监控
void PB_GetPerformanceStats(PB_CopyContext* ctx, PB_PerfCounter* stats);
void PB_ResetPerformanceStats(PB_CopyContext* ctx);

// 工具函数
DWORD PB_GetOptimalWorkerCount();
DWORD PB_GetNumaNodeCount();
size_t PB_GetSystemSectorSize();
BOOL PB_IsReFSVolume(const WCHAR* path);

#ifdef __cplusplus
}
#endif

#endif // PB_FASTCOPY_FILE_OPERATIONS_V10_H