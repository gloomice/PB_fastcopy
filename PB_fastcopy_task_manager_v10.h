#pragma once

// ==============================================
// PB级小文件复制定时任务管理器 v10
// 极致性能优化版本
// ==============================================

// Windows头文件
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <ioringapi.h>
#include <memoryapi.h>
#include <processthreadsapi.h>
#include <sysinfoapi.h>

// C标准库
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

// ==============================================
// 常量定义
// ==============================================

// 内存对齐
#define CACHE_LINE_SIZE 64
#define ALIGN_CACHE __declspec(align(CACHE_LINE_SIZE))

// 文件操作
#define FILE_SEQUENTIAL_ONLY 0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING 0x00000008
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020

// 默认配置
#define DEFAULT_MAX_TASKS_PER_BATCH 256
#define DEFAULT_IO_RING_SIZE 4096
#define DEFAULT_MAX_WORKER_THREADS 64
#define DEFAULT_MAX_SCANNER_THREADS 8
#define DEFAULT_HANDLE_CACHE_SIZE 1024
#define DEFAULT_METADATA_CACHE_SIZE 65536
#define DEFAULT_BATCH_TIMEOUT_MS 100

// NUMA相关
#define MAX_NUMA_NODES 8
#define MAX_CPU_CORES 256

// ==============================================
// NT原生API声明
// ==============================================

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define OBJ_CASE_INSENSITIVE 0x00000040L

typedef NTSTATUS(NTAPI* PNtCreateFile)(
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

// ==============================================
// 核心数据结构
// ==============================================

// 文件任务结构（内存对齐）
typedef struct ALIGN_CACHE PB_TASK {
    uint64_t task_id;
    uint64_t file_size;
    uint64_t creation_time;
    uint64_t last_write_time;
    uint32_t source_path_hash;
    uint32_t target_path_hash;
    uint8_t priority;           // 0-255，数值越高优先级越高
    uint8_t numa_node;
    uint8_t retry_count;
    uint8_t flags;
    
    // 路径存储（内联存储，避免额外分配）
    char source_path[512];
    char target_path[512];
    
    // I/O状态
    volatile LONG status;
    HANDLE source_handle;
    HANDLE target_handle;
    void* buffer;
    size_t buffer_size;
    
    // 下一个任务指针（用于链表）
    struct PB_TASK* next;
} PB_TASK;

// NUMA感知的任务队列
typedef struct ALIGN_CACHE PB_NUMA_QUEUE {
    uint32_t numa_node;
    SRWLOCK lock;
    volatile LONG head;
    volatile LONG tail;
    volatile LONG count;
    volatile LONG watermark_high;
    volatile LONG watermark_low;
    
    // 环形缓冲区
    PB_TASK** tasks;
    uint32_t capacity;
    
    // 统计信息
    uint64_t total_processed;
    uint64_t total_failed;
    uint64_t total_bytes;
} PB_NUMA_QUEUE;

// I/O批次结构
typedef struct ALIGN_CACHE PB_IO_BATCH {
    HIORING io_ring;
    uint32_t batch_id;
    uint32_t numa_node;
    uint32_t task_count;
    uint32_t submitted_count;
    PB_TASK** tasks;
    IORING_HANDLE_REF* handle_refs;
    IORING_BUFFER_REF* buffer_refs;
    OVERLAPPED* overlappeds;
    void* buffers;
} PB_IO_BATCH;

// 句柄缓存项
typedef struct PB_HANDLE_CACHE_ENTRY {
    char path[512];
    HANDLE handle;
    uint64_t last_access;
    uint32_t access_count;
    struct PB_HANDLE_CACHE_ENTRY* next;
} PB_HANDLE_CACHE_ENTRY;

// 句柄缓存
typedef struct ALIGN_CACHE PB_HANDLE_CACHE {
    SRWLOCK lock;
    PB_HANDLE_CACHE_ENTRY** buckets;
    uint32_t bucket_count;
    uint32_t max_size;
    uint32_t current_size;
    uint64_t hit_count;
    uint64_t miss_count;
} PB_HANDLE_CACHE;

// 元数据缓存
typedef struct ALIGN_CACHE PB_METADATA_CACHE_ENTRY {
    uint64_t file_size;
    uint64_t creation_time;
    uint64_t last_write_time;
    uint32_t path_hash;
    char path[512];
    struct PB_METADATA_CACHE_ENTRY* next;
} PB_METADATA_CACHE_ENTRY;

typedef struct ALIGN_CACHE PB_METADATA_CACHE {
    SRWLOCK lock;
    PB_METADATA_CACHE_ENTRY** buckets;
    uint32_t bucket_count;
    uint64_t hit_count;
    uint64_t miss_count;
} PB_METADATA_CACHE;

// CPU核心绑定信息
typedef struct PB_CPU_CORE {
    uint32_t core_id;
    uint32_t numa_node;
    bool hyper_thread;
    volatile LONG utilization;  // 0-100
} PB_CPU_CORE;

// 定时任务配置
typedef struct PB_SCHEDULE_CONFIG {
    uint32_t hour;
    uint32_t minute;
    uint32_t day_of_week;      // 0-6，0=周日
    uint32_t day_of_month;     // 1-31
    uint32_t month;            // 1-12
    bool enabled;
} PB_SCHEDULE_CONFIG;

// 主管理器结构
typedef struct ALIGN_CACHE PB_TASK_MANAGER {
    // 配置
    uint32_t max_worker_threads;
    uint32_t max_scanner_threads;
    uint32_t io_ring_size;
    uint32_t max_batch_size;
    uint32_t batch_timeout_ms;
    bool use_large_pages;
    bool enable_io_ring;
    bool enable_ntapi;
    bool enable_handle_cache;
    
    // NUMA队列
    PB_NUMA_QUEUE* numa_queues[MAX_NUMA_NODES];
    uint32_t numa_node_count;
    
    // 工作线程
    HANDLE worker_threads[MAX_CPU_CORES];
    uint32_t worker_count;
    PB_CPU_CORE cpu_cores[MAX_CPU_CORES];
    
    // 扫描线程
    HANDLE scanner_threads[MAX_CPU_CORES];
    uint32_t scanner_count;
    
    // I/O批次管理器
    PB_IO_BATCH* io_batches;
    uint32_t io_batch_count;
    
    // 缓存系统
    PB_HANDLE_CACHE* handle_cache;
    PB_METADATA_CACHE* metadata_cache;
    
    // 定时任务
    PB_SCHEDULE_CONFIG* schedules;
    uint32_t schedule_count;
    HANDLE schedule_timer;
    
    // 同步原语
    SRWLOCK manager_lock;
    CONDITION_VARIABLE work_available;
    volatile LONG is_shutdown;
    volatile LONG total_tasks;
    volatile LONG pending_tasks;
    
    // 统计信息
    uint64_t total_files_processed;
    uint64_t total_bytes_processed;
    uint64_t total_errors;
    uint64_t start_time;
    uint64_t last_report_time;
    
    // NTAPI函数指针
    PNtCreateFile pNtCreateFile;
    
    // 内存分配信息
    void* large_page_base;
    size_t large_page_size;
} PB_TASK_MANAGER;

// ==============================================
// 函数声明
// ==============================================

// 初始化与清理
PB_TASK_MANAGER* pb_task_manager_create(const char* config_path);
bool pb_task_manager_destroy(PB_TASK_MANAGER* manager);
bool pb_task_manager_init_numa(PB_TASK_MANAGER* manager);

// 任务管理
bool pb_task_add(PB_TASK_MANAGER* manager, const char* source, const char* target, uint8_t priority);
bool pb_task_add_batch(PB_TASK_MANAGER* manager, const char** sources, const char** targets, uint32_t count, uint8_t priority);
PB_TASK* pb_task_pop(PB_TASK_MANAGER* manager, uint32_t numa_node, uint32_t timeout_ms);
bool pb_task_push(PB_TASK_MANAGER* manager, PB_TASK* task);

// I/O操作
bool pb_io_batch_create(PB_TASK_MANAGER* manager, uint32_t numa_node);
bool pb_io_batch_submit(PB_TASK_MANAGER* manager, uint32_t batch_id, PB_TASK** tasks, uint32_t count);
bool pb_io_batch_wait(PB_TASK_MANAGER* manager, uint32_t batch_id, uint32_t timeout_ms);
bool pb_io_batch_destroy(PB_TASK_MANAGER* manager, uint32_t batch_id);

// 文件操作（NTAPI优化）
HANDLE pb_file_open_nt(const char* path, DWORD access, DWORD share, DWORD disposition, DWORD flags);
bool pb_file_copy_nt(PB_TASK_MANAGER* manager, PB_TASK* task);
bool pb_file_read_batch(PB_TASK_MANAGER* manager, PB_TASK** tasks, uint32_t count);
bool pb_file_write_batch(PB_TASK_MANAGER* manager, PB_TASK** tasks, uint32_t count);

// 缓存管理
PB_HANDLE_CACHE* pb_handle_cache_create(uint32_t size);
HANDLE pb_handle_cache_get(PB_HANDLE_CACHE* cache, const char* path, DWORD access, DWORD share, DWORD flags);
bool pb_handle_cache_put(PB_HANDLE_CACHE* cache, const char* path, HANDLE handle);
bool pb_handle_cache_clear(PB_HANDLE_CACHE* cache);
PB_METADATA_CACHE* pb_metadata_cache_create(uint32_t size);
bool pb_metadata_cache_get(PB_METADATA_CACHE* cache, const char* path, uint64_t* size, uint64_t* creation, uint64_t* last_write);
bool pb_metadata_cache_put(PB_METADATA_CACHE* cache, const char* path, uint64_t size, uint64_t creation, uint64_t last_write);

// 线程函数
DWORD WINAPI pb_worker_thread(LPVOID param);
DWORD WINAPI pb_scanner_thread(LPVOID param);
DWORD WINAPI pb_scheduler_thread(LPVOID param);

// 定时任务
bool pb_schedule_add(PB_TASK_MANAGER* manager, const PB_SCHEDULE_CONFIG* config);
bool pb_schedule_remove(PB_TASK_MANAGER* manager, uint32_t schedule_id);
bool pb_schedule_check(PB_TASK_MANAGER* manager, SYSTEMTIME* current_time);
bool pb_schedule_execute(PB_TASK_MANAGER* manager, uint32_t schedule_id);

// 监控与统计
bool pb_stats_get(PB_TASK_MANAGER* manager, uint64_t* files_processed, uint64_t* bytes_processed, 
                  uint64_t* errors, uint32_t* queue_depth, uint32_t* active_workers);
void pb_stats_report(PB_TASK_MANAGER* manager, FILE* output);
bool pb_monitor_start(PB_TASK_MANAGER* manager, uint32_t interval_seconds);
bool pb_monitor_stop(PB_TASK_MANAGER* manager);

// 内存管理
void* pb_malloc_aligned(size_t size, size_t alignment);
void pb_free_aligned(void* ptr);
void* pb_malloc_large_page(size_t size);
void pb_free_large_page(void* ptr, size_t size);

// 工具函数
uint32_t pb_hash_string(const char* str);
uint32_t pb_get_numa_node_for_cpu(uint32_t cpu_id);
uint32_t pb_get_optimal_batch_size(PB_TASK_MANAGER* manager, uint32_t numa_node);
bool pb_set_thread_affinity(HANDLE thread, uint32_t cpu_mask);
bool pb_set_thread_priority_class(HANDLE thread, int priority);

// 配置管理
bool pb_config_load(PB_TASK_MANAGER* manager, const char* path);
bool pb_config_save(PB_TASK_MANAGER* manager, const char* path);
bool pb_config_set(PB_TASK_MANAGER* manager, const char* key, const char* value);

// 错误处理
const char* pb_error_to_string(int error_code);
bool pb_error_log(const char* format, ...);
bool pb_error_set_last(int error_code);

// ==============================================
// 内联函数
// ==============================================

static inline uint64_t pb_get_time_ns() {
    LARGE_INTEGER time, freq;
    QueryPerformanceCounter(&time);
    QueryPerformanceFrequency(&freq);
    return (uint64_t)((time.QuadPart * 1000000000) / freq.QuadPart);
}

static inline bool pb_is_shutdown(PB_TASK_MANAGER* manager) {
    return InterlockedCompareExchange(&manager->is_shutdown, 0, 0) != 0;
}

static inline void pb_memory_barrier() {
    _ReadWriteBarrier();
    MemoryBarrier();
}

// ==============================================
// 宏定义
// ==============================================

#define PB_SAFE_RELEASE_HANDLE(handle) \
    do { \
        if ((handle) != NULL && (handle) != INVALID_HANDLE_VALUE) { \
            CloseHandle((handle)); \
            (handle) = NULL; \
        } \
    } while(0)

#define PB_SAFE_FREE(ptr) \
    do { \
        if ((ptr) != NULL) { \
            free((ptr)); \
            (ptr) = NULL; \
        } \
    } while(0)

#define PB_CHECK_NULL(ptr) \
    do { \
        if ((ptr) == NULL) { \
            pb_error_log("Null pointer at %s:%d", __FILE__, __LINE__); \
            return false; \
        } \
    } while(0)

#define PB_ENTER_CRITICAL_SECTION(lock) \
    AcquireSRWLockExclusive(&(lock))

#define PB_LEAVE_CRITICAL_SECTION(lock) \
    ReleaseSRWLockExclusive(&(lock))

#define PB_ENTER_SHARED_SECTION(lock) \
    AcquireSRWLockShared(&(lock))

#define PB_LEAVE_SHARED_SECTION(lock) \
    ReleaseSRWLockShared(&(lock))