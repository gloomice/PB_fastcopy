#include "PB_fastcopy_file_operations_v10.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// ============================================================================
// 内部函数声明
// ============================================================================

// NTAPI动态加载
static BOOL PB_LoadNtApiFunctions(PB_CopyContext* ctx);

// 内存管理
static void* PB_InternalAllocate(size_t size, size_t alignment, DWORD flags, DWORD numa_node);
static BOOL PB_InitializeMemoryConfig(PB_CopyContext* ctx);

// 缓冲区池管理
static PB_BufferDesc* PB_CreateBufferDescriptors(size_t count, DWORD numa_node);
static void PB_InitializeBufferPool(PB_StaticBufferPool* pool, size_t buffer_size, 
                                    size_t count, DWORD numa_node);

// 无锁队列操作
static BOOL PB_InitializeQueue(PB_LockFreeQueue* queue, size_t capacity);
static BOOL PB_Enqueue(PB_LockFreeQueue* queue, void* data);
static void* PB_Dequeue(PB_LockFreeQueue* queue);
static void PB_DestroyQueue(PB_LockFreeQueue* queue);

// 线程管理
static DWORD WINAPI PB_WorkerThread(LPVOID param);
static BOOL PB_SetThreadAffinity(HANDLE thread, DWORD processor_core);
static BOOL PB_SetThreadPriorityEx(HANDLE thread, int priority);

// I/O操作
static BOOL PB_OpenFileHandle(PB_CopyContext* ctx, const WCHAR* path, 
                             HANDLE* handle, DWORD access, DWORD flags);
static BOOL PB_ReadFileAsync(PB_AsyncIOContext* ctx, HANDLE file, 
                            LARGE_INTEGER offset, DWORD length);
static BOOL PB_WriteFileAsync(PB_AsyncIOContext* ctx, HANDLE file, 
                             LARGE_INTEGER offset, DWORD length);
static BOOL PB_CloneFileBlocks(PB_CopyContext* ctx, HANDLE src, HANDLE dst, 
                              LARGE_INTEGER file_size);

// 状态机处理
static BOOL PB_ProcessAsyncState(PB_CopyContext* ctx, PB_AsyncIOContext* io_ctx);
static BOOL PB_CompleteAsyncOperation(PB_AsyncIOContext* io_ctx, DWORD bytes_transferred);

// 策略选择
static PB_IO_Strategy PB_SelectIOStrategy(LARGE_INTEGER file_size, 
                                         const WCHAR* src_vol, const WCHAR* dst_vol);
static BOOL PB_ShouldUseBlockClone(LARGE_INTEGER file_size, 
                                  const WCHAR* src_path, const WCHAR* dst_path);

// 辅助函数
static void PB_GetVolumePath(const WCHAR* file_path, WCHAR* volume_path, size_t size);
static BOOL PB_PathIsOnSameVolume(const WCHAR* path1, const WCHAR* path2);
static size_t PB_AlignToSector(size_t size, size_t sector_size);

// ============================================================================
// NTAPI函数指针全局变量
// ============================================================================

static HMODULE hNtdll = NULL;

// ============================================================================
// 公共API实现
// ============================================================================

PB_CopyContext* PB_CreateContext()
{
    PB_CopyContext* ctx = (PB_CopyContext*)calloc(1, sizeof(PB_CopyContext));
    if (!ctx)
        return NULL;
    
    // 设置默认配置
    ctx->sector_size = PB_DEFAULT_SECTOR_SIZE;
    ctx->queue_depth = PB_DEFAULT_QUEUE_DEPTH;
    ctx->worker_thread_count = PB_GetOptimalWorkerCount();
    ctx->use_io_ring = FALSE;  // 默认使用IOCP
    ctx->enable_block_clone = TRUE;
    ctx->numa_aware = TRUE;
    
    // 初始化原子变量
    atomic_init(&ctx->initialized, FALSE);
    atomic_init(&ctx->shutting_down, FALSE);
    
    // 加载NTAPI函数
    if (!PB_LoadNtApiFunctions(ctx))
    {
        free(ctx);
        return NULL;
    }
    
    return ctx;
}

BOOL PB_InitializeContext(PB_CopyContext* ctx, DWORD worker_count)
{
    if (!ctx || atomic_load(&ctx->initialized))
        return FALSE;
    
    // 调整工作线程数量
    if (worker_count > 0 && worker_count <= PB_MAX_WORKER_THREADS)
        ctx->worker_count = worker_count;
    else
        ctx->worker_count = PB_GetOptimalWorkerCount();
    
    // 初始化内存配置
    if (!PB_InitializeMemoryConfig(ctx))
        return FALSE;
    
    // 创建IOCP
    ctx->iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if (!ctx->iocp)
        return FALSE;
    
    // 初始化任务队列
    ctx->task_queue = (PB_LockFreeQueue*)malloc(sizeof(PB_LockFreeQueue));
    if (!ctx->task_queue)
        return FALSE;
    
    if (!PB_InitializeQueue(ctx->task_queue, ctx->queue_depth))
    {
        free(ctx->task_queue);
        ctx->task_queue = NULL;
        return FALSE;
    }
    
    // 创建缓冲区池（每个NUMA节点一个）
    DWORD numa_count = PB_GetNumaNodeCount();
    ctx->buffer_pools = (PB_StaticBufferPool*)calloc(numa_count, sizeof(PB_StaticBufferPool));
    ctx->buffer_pool_count = numa_count;
    
    if (!ctx->buffer_pools)
        return FALSE;
    
    for (DWORD i = 0; i < numa_count; i++)
    {
        // 为每个NUMA节点创建缓冲区池
        if (!PB_CreateBufferPool(PB_DEFAULT_SECTOR_SIZE * 32,  // 128KB缓冲区
                                 ctx->queue_depth * 2,         // 双倍队列深度
                                 i))
        {
            // 清理已创建的资源
            for (DWORD j = 0; j < i; j++)
                free(ctx->buffer_pools[j].buffers);
            free(ctx->buffer_pools);
            return FALSE;
        }
    }
    
    // 创建工作线程
    ctx->workers = (PB_ThreadContext*)calloc(ctx->worker_count, sizeof(PB_ThreadContext));
    if (!ctx->workers)
        return FALSE;
    
    // 设置标记
    atomic_store(&ctx->initialized, TRUE);
    
    return TRUE;
}

void PB_DestroyContext(PB_CopyContext* ctx)
{
    if (!ctx)
        return;
    
    // 停止工作线程
    PB_StopWorkers(ctx);
    
    // 标记关闭
    atomic_store(&ctx->shutting_down, TRUE);
    
    // 释放缓冲区池
    if (ctx->buffer_pools)
    {
        for (size_t i = 0; i < ctx->buffer_pool_count; i++)
        {
            PB_StaticBufferPool* pool = &ctx->buffer_pools[i];
            if (pool->buffers)
            {
                for (size_t j = 0; j < pool->buffer_count; j++)
                {
                    if (pool->buffers[j].address)
                        VirtualFree(pool->buffers[j].address, 0, MEM_RELEASE);
                }
                free(pool->buffers);
            }
        }
        free(ctx->buffer_pools);
    }
    
    // 释放任务队列
    if (ctx->task_queue)
    {
        PB_DestroyQueue(ctx->task_queue);
        free(ctx->task_queue);
    }
    
    // 关闭IOCP
    if (ctx->iocp)
        CloseHandle(ctx->iocp);
    
    // 释放工作线程数组
    free(ctx->workers);
    
    // 释放NTDLL句柄
    if (hNtdll)
        FreeLibrary(hNtdll);
    
    free(ctx);
}

// ============================================================================
// 内存管理实现
// ============================================================================

void* PB_AllocateAligned(size_t size, size_t alignment, DWORD numa_node)
{
    if (alignment == 0)
        alignment = PB_CACHE_LINE_SIZE;
    
    size_t aligned_size = PB_ALIGN_UP(size, alignment);
    
    // 尝试使用大页内存
    DWORD flags = MEM_RESERVE | MEM_COMMIT;
    if (size >= PB_LARGE_PAGE_SIZE)
        flags |= MEM_LARGE_PAGES;
    
    return PB_InternalAllocate(aligned_size, alignment, flags, numa_node);
}

void PB_FreeAligned(void* ptr)
{
    if (ptr)
        VirtualFree(ptr, 0, MEM_RELEASE);
}

PB_StaticBufferPool* PB_CreateBufferPool(size_t buffer_size, size_t count, DWORD numa_node)
{
    PB_StaticBufferPool* pool = (PB_StaticBufferPool*)malloc(sizeof(PB_StaticBufferPool));
    if (!pool)
        return NULL;
    
    PB_InitializeBufferPool(pool, buffer_size, count, numa_node);
    return pool;
}

PB_BufferDesc* PB_AcquireBuffer(PB_StaticBufferPool* pool)
{
    if (!pool || atomic_load(&pool->free_count) == 0)
        return NULL;
    
    // 使用原子操作获取空闲缓冲区
    PB_BufferDesc* buffer = NULL;
    PB_BufferDesc* next = NULL;
    
    do {
        buffer = (PB_BufferDesc*)atomic_load(&pool->free_list);
        if (!buffer)
            break;
        
        next = buffer->next;
    } while (!atomic_compare_exchange_strong(&pool->free_list, (uintptr_t*)&buffer, (uintptr_t)next));
    
    if (buffer)
    {
        atomic_store(&buffer->state, PB_BUFFER_IN_USE);
        atomic_fetch_sub(&pool->free_count, 1);
    }
    
    return buffer;
}

void PB_ReleaseBuffer(PB_StaticBufferPool* pool, PB_BufferDesc* buffer)
{
    if (!pool || !buffer)
        return;
    
    atomic_store(&buffer->state, PB_BUFFER_FREE);
    
    // 使用原子操作将缓冲区添加回空闲列表
    PB_BufferDesc* old_head = NULL;
    do {
        old_head = (PB_BufferDesc*)atomic_load(&pool->free_list);
        buffer->next = old_head;
    } while (!atomic_compare_exchange_strong(&pool->free_list, 
                                            (uintptr_t*)&old_head, 
                                            (uintptr_t)buffer));
    
    atomic_fetch_add(&pool->free_count, 1);
}

// ============================================================================
// 文件操作实现
// ============================================================================

BOOL PB_CopyFile(PB_CopyContext* ctx, const WCHAR* src, const WCHAR* dst)
{
    return PB_CopyFileEx(ctx, src, dst, PB_IO_STRATEGY_DEFAULT, PB_IO_PRIORITY_HINT_NORMAL);
}

BOOL PB_CopyFileEx(PB_CopyContext* ctx, const WCHAR* src, const WCHAR* dst, 
                   PB_IO_Strategy strategy, PB_IO_Priority_Hint priority)
{
    if (!ctx || !atomic_load(&ctx->initialized))
        return FALSE;
    
    // 创建传输任务
    PB_TransferTask* task = (PB_TransferTask*)PB_AllocateAligned(sizeof(PB_TransferTask), 
                                                               PB_CACHE_LINE_SIZE, 0);
    if (!task)
        return FALSE;
    
    // 初始化任务
    wcscpy_s(task->src_path, PB_MAX_PATH_LENGTH, src);
    wcscpy_s(task->dst_path, PB_MAX_PATH_LENGTH, dst);
    atomic_store(&task->status, 0);
    
    // 获取文件信息以确定策略
    WIN32_FILE_ATTRIBUTE_DATA file_attr;
    if (GetFileAttributesExW(src, GetFileExInfoStandard, &file_attr))
    {
        task->file_size.LowPart = file_attr.nFileSizeLow;
        task->file_size.HighPart = file_attr.nFileSizeHigh;
        task->creation_time = file_attr.ftCreationTime;
        task->last_write_time = file_attr.ftLastWriteTime;
        task->attributes = file_attr.dwFileAttributes;
        
        // 自动选择策略
        if (strategy == PB_IO_STRATEGY_DEFAULT)
        {
            WCHAR src_vol[MAX_PATH], dst_vol[MAX_PATH];
            PB_GetVolumePath(src, src_vol, MAX_PATH);
            PB_GetVolumePath(dst, dst_vol, MAX_PATH);
            
            task->strategy = PB_SelectIOStrategy(task->file_size, src_vol, dst_vol);
        }
        else
        {
            task->strategy = strategy;
        }
    }
    else
    {
        PB_FreeAligned(task);
        return FALSE;
    }
    
    task->priority = priority;
    
    // 将任务加入队列
    if (!PB_EnqueueTask(ctx, task))
    {
        PB_FreeAligned(task);
        return FALSE;
    }
    
    return TRUE;
}

// ============================================================================
// 批量操作实现
// ============================================================================

BOOL PB_EnqueueTask(PB_CopyContext* ctx, PB_TransferTask* task)
{
    if (!ctx || !ctx->task_queue)
        return FALSE;
    
    static atomic_uint_least64_t task_id_counter = 0;
    task->task_id = atomic_fetch_add(&task_id_counter, 1);
    
    return PB_Enqueue(ctx->task_queue, task);
}

BOOL PB_StartWorkers(PB_CopyContext* ctx)
{
    if (!ctx || !atomic_load(&ctx->initialized))
        return FALSE;
    
    // 为每个工作线程分配NUMA节点和CPU核心
    DWORD numa_count = PB_GetNumaNodeCount();
    DWORD cores_per_numa = ctx->worker_count / numa_count;
    
    for (DWORD i = 0; i < ctx->worker_count; i++)
    {
        PB_ThreadContext* worker = &ctx->workers[i];
        
        // 计算NUMA节点和CPU核心
        worker->numa_node = i % numa_count;
        worker->processor_core = i;
        
        // 创建线程
        worker->thread_handle = CreateThread(
            NULL,                        // 安全属性
            0,                           // 栈大小
            PB_WorkerThread,             // 线程函数
            worker,                      // 参数
            CREATE_SUSPENDED,            // 创建标志
            &worker->thread_id           // 线程ID
        );
        
        if (!worker->thread_handle)
        {
            // 清理已创建的线程
            for (DWORD j = 0; j < i; j++)
                CloseHandle(ctx->workers[j].thread_handle);
            return FALSE;
        }
        
        // 设置线程亲和性和优先级
        PB_SetThreadAffinity(worker->thread_handle, worker->processor_core);
        PB_SetThreadPriorityEx(worker->thread_handle, THREAD_PRIORITY_TIME_CRITICAL);
        
        // 关联IOCP
        worker->iocp = ctx->iocp;
        atomic_store(&worker->running, TRUE);
        
        // 恢复线程执行
        ResumeThread(worker->thread_handle);
    }
    
    return TRUE;
}

BOOL PB_StopWorkers(PB_CopyContext* ctx)
{
    if (!ctx)
        return FALSE;
    
    // 通知所有工作线程停止
    for (DWORD i = 0; i < ctx->worker_count; i++)
    {
        atomic_store(&ctx->workers[i].running, FALSE);
        
        // 发送退出消息到IOCP
        PostQueuedCompletionStatus(ctx->iocp, 0, 0, NULL);
    }
    
    // 等待所有线程退出
    WaitForMultipleObjects(ctx->worker_count, 
                          (const HANDLE*)ctx->workers, 
                          TRUE, INFINITE);
    
    // 关闭线程句柄
    for (DWORD i = 0; i < ctx->worker_count; i++)
        CloseHandle(ctx->workers[i].thread_handle);
    
    return TRUE;
}

// ============================================================================
// 性能监控实现
// ============================================================================

void PB_GetPerformanceStats(PB_CopyContext* ctx, PB_PerfCounter* stats)
{
    if (!ctx || !stats)
        return;
    
    // 复制原子值
    stats->copied_bytes = atomic_load(&ctx->perf.copied_bytes);
    stats->file_count = atomic_load(&ctx->perf.file_count);
    stats->io_operations = atomic_load(&ctx->perf.io_operations);
    stats->total_time_ns = atomic_load(&ctx->perf.total_time_ns);
    
    // 累加所有工作线程的本地统计
    for (DWORD i = 0; i < ctx->worker_count; i++)
    {
        PB_ThreadContext* worker = &ctx->workers[i];
        stats->copied_bytes += atomic_load(&worker->local_perf.copied_bytes);
        stats->file_count += atomic_load(&worker->local_perf.file_count);
        stats->io_operations += atomic_load(&worker->local_perf.io_operations);
        stats->total_time_ns += atomic_load(&worker->local_perf.total_time_ns);
    }
}

void PB_ResetPerformanceStats(PB_CopyContext* ctx)
{
    if (!ctx)
        return;
    
    atomic_store(&ctx->perf.copied_bytes, 0);
    atomic_store(&ctx->perf.file_count, 0);
    atomic_store(&ctx->perf.io_operations, 0);
    atomic_store(&ctx->perf.total_time_ns, 0);
    
    for (DWORD i = 0; i < ctx->worker_count; i++)
    {
        PB_ThreadContext* worker = &ctx->workers[i];
        atomic_store(&worker->local_perf.copied_bytes, 0);
        atomic_store(&worker->local_perf.file_count, 0);
        atomic_store(&worker->local_perf.io_operations, 0);
        atomic_store(&worker->local_perf.total_time_ns, 0);
    }
}

// ============================================================================
// 工具函数实现
// ============================================================================

DWORD PB_GetOptimalWorkerCount()
{
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    
    // 根据CPU核心数确定工作线程数量
    DWORD core_count = sys_info.dwNumberOfProcessors;
    
    // 对于I/O密集型任务，使用核心数 * 2
    DWORD worker_count = core_count * 2;
    
    // 限制最大线程数
    if (worker_count > PB_MAX_WORKER_THREADS)
        worker_count = PB_MAX_WORKER_THREADS;
    if (worker_count < 2)
        worker_count = 2;
    
    return worker_count;
}

DWORD PB_GetNumaNodeCount()
{
    ULONG highest_node_number;
    if (!GetNumaHighestNodeNumber(&highest_node_number))
        return 1;
    
    return highest_node_number + 1;
}

size_t PB_GetSystemSectorSize()
{
    DWORD sectors_per_cluster, bytes_per_sector, free_clusters, total_clusters;
    
    if (GetDiskFreeSpaceW(L"C:\\", &sectors_per_cluster, &bytes_per_sector,
                         &free_clusters, &total_clusters))
    {
        return bytes_per_sector;
    }
    
    return PB_DEFAULT_SECTOR_SIZE;
}

BOOL PB_IsReFSVolume(const WCHAR* path)
{
    WCHAR root_path[MAX_PATH];
    WCHAR file_system_name[MAX_PATH];
    
    // 提取根路径
    if (path[1] == L':')
    {
        root_path[0] = path[0];
        root_path[1] = L':';
        root_path[2] = L'\\';
        root_path[3] = L'\0';
    }
    else
    {
        return FALSE;
    }
    
    // 获取文件系统信息
    if (GetVolumeInformationW(root_path, NULL, 0, NULL, NULL, NULL,
                             file_system_name, MAX_PATH))
    {
        return (_wcsicmp(file_system_name, L"ReFS") == 0);
    }
    
    return FALSE;
}

// ============================================================================
// 内部函数实现
// ============================================================================

static BOOL PB_LoadNtApiFunctions(PB_CopyContext* ctx)
{
    if (!ctx)
        return FALSE;
    
    // 加载NTDLL
    hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll)
        return FALSE;
    
    // 获取NTAPI函数地址
    ctx->NtCreateFile = (PFN_NT_CREATE_FILE)GetProcAddress(hNtdll, "NtCreateFile");
    ctx->NtReadFile = (PFN_NT_READ_FILE)GetProcAddress(hNtdll, "NtReadFile");
    ctx->NtWriteFile = (PFN_NT_WRITE_FILE)GetProcAddress(hNtdll, "NtWriteFile");
    ctx->NtQueryInformationFile = (PFN_NT_QUERY_INFORMATION_FILE)GetProcAddress(hNtdll, "NtQueryInformationFile");
    ctx->NtSetInformationFile = (PFN_NT_SET_INFORMATION_FILE)GetProcAddress(hNtdll, "NtSetInformationFile");
    
    // 检查所有函数是否加载成功
    return (ctx->NtCreateFile && ctx->NtReadFile && ctx->NtWriteFile &&
            ctx->NtQueryInformationFile && ctx->NtSetInformationFile);
}

static void* PB_InternalAllocate(size_t size, size_t alignment, DWORD flags, DWORD numa_node)
{
    // 尝试NUMA感知分配
    PVOID base_address = NULL;
    
    if (numa_node > 0 && numa_node < 64)  // 合理的NUMA节点限制
    {
        // 使用VirtualAllocExNuma如果可用
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (hKernel32)
        {
            typedef PVOID (WINAPI *PFN_VirtualAllocExNuma)(HANDLE, PVOID, SIZE_T, DWORD, DWORD, DWORD);
            PFN_VirtualAllocExNuma pVirtualAllocExNuma = 
                (PFN_VirtualAllocExNuma)GetProcAddress(hKernel32, "VirtualAllocExNuma");
            
            if (pVirtualAllocExNuma)
            {
                base_address = pVirtualAllocExNuma(GetCurrentProcess(), NULL, 
                                                  size, MEM_RESERVE | MEM_COMMIT, 
                                                  PAGE_READWRITE, numa_node);
                if (base_address)
                {
                    // 检查对齐要求
                    if (((uintptr_t)base_address & (alignment - 1)) == 0)
                        return base_address;
                    
                    // 如果不满足对齐要求，释放并回退到标准分配
                    VirtualFree(base_address, 0, MEM_RELEASE);
                }
            }
        }
    }
    
    // 标准分配
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    
    size_t actual_alignment = (alignment > sys_info.dwAllocationGranularity) ? 
                              alignment : sys_info.dwAllocationGranularity;
    
    // 分配对齐的内存
    size_t total_size = size + actual_alignment - 1 + sizeof(void*);
    base_address = VirtualAlloc(NULL, total_size, flags, PAGE_READWRITE);
    
    if (!base_address)
        return NULL;
    
    // 计算对齐地址
    uintptr_t raw_address = (uintptr_t)base_address;
    uintptr_t aligned_address = (raw_address + sizeof(void*) + actual_alignment - 1) & 
                                ~(actual_alignment - 1);
    
    // 在地址前面存储原始指针以便释放
    void** prefix = (void**)(aligned_address - sizeof(void*));
    *prefix = base_address;
    
    // 锁住内存防止交换
    if (flags & MEM_LOCK_PAGES)
        VirtualLock((void*)aligned_address, size);
    
    return (void*)aligned_address;
}

static BOOL PB_InitializeMemoryConfig(PB_CopyContext* ctx)
{
    if (!ctx)
        return FALSE;
    
    // 获取系统信息
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    
    // 获取大页大小
    size_t large_page_size = GetLargePageMinimum();
    
    // 配置内存参数
    ctx->memory_config.page_size = sys_info.dwPageSize;
    ctx->memory_config.large_page_size = large_page_size > 0 ? large_page_size : PB_LARGE_PAGE_SIZE;
    ctx->memory_config.use_large_pages = (large_page_size > 0);
    ctx->memory_config.lock_pages = TRUE;
    ctx->memory_config.allocation_flags = MEM_RESERVE | MEM_COMMIT;
    
    if (ctx->memory_config.use_large_pages)
        ctx->memory_config.allocation_flags |= MEM_LARGE_PAGES;
    
    return TRUE;
}

static void PB_InitializeBufferPool(PB_StaticBufferPool* pool, size_t buffer_size, 
                                   size_t count, DWORD numa_node)
{
    if (!pool)
        return;
    
    // 对齐缓冲区大小
    size_t aligned_buffer_size = PB_ALIGN_UP(buffer_size, PB_DEFAULT_SECTOR_SIZE);
    
    pool->buffer_size = aligned_buffer_size;
    pool->buffer_count = count;
    pool->numa_node = numa_node;
    pool->heap = GetProcessHeap();
    atomic_init(&pool->free_count, count);
    
    // 创建缓冲区描述符数组
    pool->buffers = PB_CreateBufferDescriptors(count, numa_node);
    if (!pool->buffers)
        return;
    
    // 初始化每个缓冲区
    for (size_t i = 0; i < count; i++)
    {
        PB_BufferDesc* desc = &pool->buffers[i];
        
        // 分配对齐的内存
        desc->address = PB_AllocateAligned(aligned_buffer_size, 
                                          PB_DEFAULT_SECTOR_SIZE, 
                                          numa_node);
        desc->size = aligned_buffer_size;
        desc->numa_node = numa_node;
        desc->alignment_mask = PB_DEFAULT_SECTOR_SIZE - 1;
        atomic_init(&desc->state, PB_BUFFER_FREE);
        
        // 构建空闲链表
        if (i < count - 1)
            desc->next = &pool->buffers[i + 1];
        else
            desc->next = NULL;
    }
    
    // 初始化空闲列表头指针
    atomic_store(&pool->free_list, (uintptr_t)&pool->buffers[0]);
}

static PB_BufferDesc* PB_CreateBufferDescriptors(size_t count, DWORD numa_node)
{
    // 使用对齐分配确保缓存行对齐
    size_t aligned_size = PB_ALIGN_UP(sizeof(PB_BufferDesc) * count, PB_CACHE_LINE_SIZE);
    return (PB_BufferDesc*)PB_AllocateAligned(aligned_size, PB_CACHE_LINE_SIZE, numa_node);
}

// ============================================================================
// 无锁队列实现
// ============================================================================

static BOOL PB_InitializeQueue(PB_LockFreeQueue* queue, size_t capacity)
{
    if (!queue)
        return FALSE;
    
    queue->capacity = capacity;
    atomic_init(&queue->count, 0);
    atomic_init(&queue->head, 0);
    atomic_init(&queue->tail, 0);
    
    // 分配节点数组（缓存行对齐）
    size_t nodes_size = sizeof(PB_LockFreeNode) * capacity;
    queue->nodes = (PB_LockFreeNode*)PB_AllocateAligned(nodes_size, PB_CACHE_LINE_SIZE, 0);
    
    if (!queue->nodes)
        return FALSE;
    
    // 初始化节点
    for (size_t i = 0; i < capacity; i++)
    {
        atomic_init(&queue->nodes[i].next, 0);
        queue->nodes[i].data = NULL;
    }
    
    return TRUE;
}

static BOOL PB_Enqueue(PB_LockFreeQueue* queue, void* data)
{
    if (!queue || !data)
        return FALSE;
    
    size_t current_count = atomic_load(&queue->count);
    if (current_count >= queue->capacity)
        return FALSE;  // 队列已满
    
    // 获取尾节点索引
    uintptr_t tail_idx = atomic_load(&queue->tail);
    PB_LockFreeNode* tail_node = &queue->nodes[tail_idx % queue->capacity];
    
    // 设置数据
    tail_node->data = data;
    
    // 发布内存屏障确保数据对其他线程可见
    atomic_thread_fence(memory_order_release);
    
    // 更新尾指针
    atomic_fetch_add(&queue->tail, 1);
    atomic_fetch_add(&queue->count, 1);
    
    return TRUE;
}

static void* PB_Dequeue(PB_LockFreeQueue* queue)
{
    if (!queue)
        return NULL;
    
    size_t current_count = atomic_load(&queue->count);
    if (current_count == 0)
        return NULL;  // 队列为空
    
    // 获取头节点索引
    uintptr_t head_idx = atomic_load(&queue->head);
    PB_LockFreeNode* head_node = &queue->nodes[head_idx % queue->capacity];
    
    // 等待数据可用
    while (!head_node->data)
    {
        // 短暂自旋等待
        YieldProcessor();
    }
    
    // 获取数据
    void* data = head_node->data;
    
    // 消费内存屏障
    atomic_thread_fence(memory_order_acquire);
    
    // 清空节点数据
    head_node->data = NULL;
    
    // 更新头指针
    atomic_fetch_add(&queue->head, 1);
    atomic_fetch_sub(&queue->count, 1);
    
    return data;
}

static void PB_DestroyQueue(PB_LockFreeQueue* queue)
{
    if (!queue)
        return;
    
    if (queue->nodes)
        PB_FreeAligned(queue->nodes);
    
    queue->nodes = NULL;
    queue->capacity = 0;
}

// ============================================================================
// 线程管理实现
// ============================================================================

static DWORD WINAPI PB_WorkerThread(LPVOID param)
{
    PB_ThreadContext* ctx = (PB_ThreadContext*)param;
    if (!ctx)
        return 0;
    
    // 初始化本地缓冲区池
    DWORD numa_node_count = PB_GetNumaNodeCount();
    DWORD local_numa_node = ctx->numa_node % numa_node_count;
    
    // 获取本地缓冲区池
    ctx->local_buffer_pool = NULL;  // 实际应用中应从上下文中获取
    
    // 性能计数器初始化
    atomic_init(&ctx->local_perf.copied_bytes, 0);
    atomic_init(&ctx->local_perf.file_count, 0);
    atomic_init(&ctx->local_perf.io_operations, 0);
    atomic_init(&ctx->local_perf.total_time_ns, 0);
    
    // 主循环
    while (atomic_load(&ctx->running))
    {
        // 从任务队列获取任务
        // PB_TransferTask* task = PB_Dequeue(...);
        
        // 处理IOCP完成通知
        DWORD bytes_transferred = 0;
        ULONG_PTR completion_key = 0;
        OVERLAPPED* overlapped = NULL;
        
        BOOL io_result = GetQueuedCompletionStatus(
            ctx->iocp,
            &bytes_transferred,
            &completion_key,
            &overlapped,
            100  // 100ms超时
        );
        
        if (!overlapped)
        {
            // 超时或错误，继续循环
            continue;
        }
        
        // 处理完成的I/O操作
        PB_AsyncIOContext* io_ctx = CONTAINING_RECORD(overlapped, PB_AsyncIOContext, overlapped);
        
        if (io_result)
        {
            // I/O成功完成
            PB_CompleteAsyncOperation(io_ctx, bytes_transferred);
            
            // 更新性能统计
            atomic_fetch_add(&ctx->local_perf.io_operations, 1);
            atomic_fetch_add(&ctx->local_perf.copied_bytes, bytes_transferred);
        }
        else
        {
            // I/O失败
            io_ctx->last_error = GetLastError();
            io_ctx->state = PB_ASYNC_STATE_ERROR;
        }
        
        // 处理下一个状态
        // PB_ProcessAsyncState(..., io_ctx);
    }
    
    return 0;
}

static BOOL PB_SetThreadAffinity(HANDLE thread, DWORD processor_core)
{
    DWORD_PTR affinity_mask = 1ULL << (processor_core % 64);
    return SetThreadAffinityMask(thread, affinity_mask);
}

static BOOL PB_SetThreadPriorityEx(HANDLE thread, int priority)
{
    return SetThreadPriority(thread, priority);
}

// ============================================================================
// I/O操作实现
// ============================================================================

static BOOL PB_OpenFileHandle(PB_CopyContext* ctx, const WCHAR* path, 
                             HANDLE* handle, DWORD access, DWORD flags)
{
    if (!ctx || !path || !handle)
        return FALSE;
    
    UNICODE_STRING uni_path;
    OBJECT_ATTRIBUTES obj_attr;
    IO_STATUS_BLOCK io_status;
    
    // 转换路径为UNICODE_STRING
    RtlInitUnicodeString(&uni_path, path);
    
    // 初始化对象属性
    InitializeObjectAttributes(&obj_attr, &uni_path, 
                              OBJ_CASE_INSENSITIVE, NULL, NULL);
    
    // 创建文件句柄
    NTSTATUS status = ctx->NtCreateFile(
        handle,
        access,
        &obj_attr,
        &io_status,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        flags,
        NULL,
        0
    );
    
    return NT_SUCCESS(status);
}

static BOOL PB_ReadFileAsync(PB_AsyncIOContext* ctx, HANDLE file, 
                            LARGE_INTEGER offset, DWORD length)
{
    if (!ctx || !file || !ctx->buffer)
        return FALSE;
    
    // 设置OVERLAPPED结构
    ctx->overlapped.Offset = offset.LowPart;
    ctx->overlapped.OffsetHigh = offset.HighPart;
    
    IO_STATUS_BLOCK io_status;
    
    // 异步读取
    NTSTATUS status = ((PFN_NT_READ_FILE)GetProcAddress(hNtdll, "NtReadFile"))(
        file,
        NULL,                    // 事件
        NULL,                    // APC例程
        NULL,                    // APC上下文
        &io_status,
        ctx->buffer->address,
        length,
        &offset,
        NULL                     // 键
    );
    
    return (status == STATUS_PENDING || NT_SUCCESS(status));
}

static BOOL PB_WriteFileAsync(PB_AsyncIOContext* ctx, HANDLE file, 
                             LARGE_INTEGER offset, DWORD length)
{
    if (!ctx || !file || !ctx->buffer)
        return FALSE;
    
    // 设置OVERLAPPED结构
    ctx->overlapped.Offset = offset.LowPart;
    ctx->overlapped.OffsetHigh = offset.HighPart;
    
    IO_STATUS_BLOCK io_status;
    
    // 异步写入
    NTSTATUS status = ((PFN_NT_WRITE_FILE)GetProcAddress(hNtdll, "NtWriteFile"))(
        file,
        NULL,                    // 事件
        NULL,                    // APC例程
        NULL,                    // APC上下文
        &io_status,
        ctx->buffer->address,
        length,
        &offset,
        NULL                     // 键
    );
    
    return (status == STATUS_PENDING || NT_SUCCESS(status));
}

static BOOL PB_CloneFileBlocks(PB_CopyContext* ctx, HANDLE src, HANDLE dst, 
                              LARGE_INTEGER file_size)
{
    if (!ctx || !src || !dst || file_size.QuadPart == 0)
        return FALSE;
    
    // 检查文件系统是否支持块克隆
    DWORD bytes_returned;
    BOOL result;
    
    // 尝试ReFS块克隆
    DUPLICATE_EXTENTS_DATA dup_extents;
    dup_extents.FileHandle = src;
    dup_extents.SourceFileOffset.QuadPart = 0;
    dup_extents.TargetFileOffset.QuadPart = 0;
    dup_extents.ByteCount.QuadPart = file_size.QuadPart;
    
    result = DeviceIoControl(
        dst,
        FSCTL_DUPLICATE_EXTENTS,
        &dup_extents,
        sizeof(dup_extents),
        NULL,
        0,
        &bytes_returned,
        NULL
    );
    
    if (!result && GetLastError() == ERROR_INVALID_FUNCTION)
    {
        // 尝试NTFS稀疏文件克隆
        FILE_ZERO_DATA_INFORMATION zero_info;
        zero_info.FileOffset.QuadPart = 0;
        zero_info.BeyondFinalZero.QuadPart = file_size.QuadPart;
        
        result = DeviceIoControl(
            dst,
            FSCTL_SET_ZERO_DATA,
            &zero_info,
            sizeof(zero_info),
            NULL,
            0,
            &bytes_returned,
            NULL
        );
    }
    
    return result;
}

// ============================================================================
// 状态机处理
// ============================================================================

static BOOL PB_ProcessAsyncState(PB_CopyContext* ctx, PB_AsyncIOContext* io_ctx)
{
    if (!ctx || !io_ctx)
        return FALSE;
    
    BOOL result = FALSE;
    
    switch (io_ctx->state)
    {
    case PB_ASYNC_STATE_OPEN_SRC:
        // 打开源文件
        result = PB_OpenFileHandle(ctx, 
                                  io_ctx->overlapped.hEvent ? 
                                  (const WCHAR*)io_ctx->overlapped.hEvent : L"",
                                  &io_ctx->src_handle,
                                  GENERIC_READ,
                                  FILE_FLAG_OVERLAPPED | 
                                  FILE_FLAG_NO_BUFFERING |
                                  FILE_FLAG_SEQUENTIAL_SCAN);
        if (result)
        {
            io_ctx->state = PB_ASYNC_STATE_OPEN_DST;
        }
        break;
        
    case PB_ASYNC_STATE_OPEN_DST:
        // 打开目标文件
        result = PB_OpenFileHandle(ctx, 
                                  (const WCHAR*)io_ctx->user_context,
                                  &io_ctx->dst_handle,
                                  GENERIC_WRITE,
                                  FILE_FLAG_OVERLAPPED | 
                                  FILE_FLAG_NO_BUFFERING |
                                  FILE_FLAG_WRITE_THROUGH);
        if (result)
        {
            io_ctx->state = PB_ASYNC_STATE_READ;
        }
        break;
        
    case PB_ASYNC_STATE_READ:
        // 读取数据
        result = PB_ReadFileAsync(io_ctx, 
                                 io_ctx->src_handle,
                                 io_ctx->bytes_transferred,
                                 (DWORD)min(io_ctx->file_size.QuadPart - 
                                           io_ctx->bytes_transferred.QuadPart,
                                           (LONGLONG)PB_MAX_BUFFER_SIZE));
        if (result)
        {
            io_ctx->state = PB_ASYNC_STATE_WRITE;
        }
        break;
        
    case PB_ASYNC_STATE_WRITE:
        // 写入数据
        result = PB_WriteFileAsync(io_ctx, 
                                  io_ctx->dst_handle,
                                  io_ctx->bytes_transferred,
                                  (DWORD)io_ctx->buffer->size);
        if (result)
        {
            io_ctx->bytes_transferred.QuadPart += io_ctx->buffer->size;
            
            if (io_ctx->bytes_transferred.QuadPart >= io_ctx->file_size.QuadPart)
            {
                io_ctx->state = PB_ASYNC_STATE_CLOSE;
            }
            else
            {
                io_ctx->state = PB_ASYNC_STATE_READ;
            }
        }
        break;
        
    case PB_ASYNC_STATE_CLOSE:
        // 关闭文件句柄
        if (io_ctx->src_handle)
            CloseHandle(io_ctx->src_handle);
        if (io_ctx->dst_handle)
            CloseHandle(io_ctx->dst_handle);
        
        io_ctx->state = PB_ASYNC_STATE_COMPLETE;
        result = TRUE;
        break;
        
    case PB_ASYNC_STATE_COMPLETE:
        // 完成处理
        result = TRUE;
        break;
        
    case PB_ASYNC_STATE_ERROR:
        // 错误处理
        if (io_ctx->src_handle)
            CloseHandle(io_ctx->src_handle);
        if (io_ctx->dst_handle)
            CloseHandle(io_ctx->dst_handle);
        result = FALSE;
        break;
        
    default:
        io_ctx->state = PB_ASYNC_STATE_ERROR;
        result = FALSE;
        break;
    }
    
    return result;
}

static BOOL PB_CompleteAsyncOperation(PB_AsyncIOContext* io_ctx, DWORD bytes_transferred)
{
    if (!io_ctx)
        return FALSE;
    
    // 根据当前状态处理完成的操作
    switch (io_ctx->state)
    {
    case PB_ASYNC_STATE_READ:
        // 读取完成，更新状态
        io_ctx->buffer->size = bytes_transferred;
        break;
        
    case PB_ASYNC_STATE_WRITE:
        // 写入完成
        atomic_fetch_add(&io_ctx->bytes_transferred.QuadPart, bytes_transferred);
        break;
        
    default:
        // 其他状态不处理字节数
        break;
    }
    
    return TRUE;
}

// ============================================================================
// 策略选择实现
// ============================================================================

static PB_IO_Strategy PB_SelectIOStrategy(LARGE_INTEGER file_size, 
                                         const WCHAR* src_vol, const WCHAR* dst_vol)
{
    LONGLONG size = file_size.QuadPart;
    
    // 极小文件使用内联策略
    if (size <= PB_INLINE_THRESHOLD)
        return PB_IO_STRATEGY_INLINE;
    
    // 小文件使用内存映射
    if (size <= PB_MMAP_THRESHOLD)
        return PB_IO_STRATEGY_MMAP;
    
    // 大文件检查是否可以块克隆
    if (size >= PB_BLOCK_CLONE_THRESHOLD)
    {
        // 检查是否在同一ReFS卷上
        if (PB_IsReFSVolume(src_vol) && PB_IsReFSVolume(dst_vol) &&
            PB_PathIsOnSameVolume(src_vol, dst_vol))
        {
            return PB_IO_STRATEGY_BLOCK_CLONE;
        }
    }
    
    // 默认使用异步I/O
    return PB_IO_STRATEGY_ASYNC;
}

static BOOL PB_ShouldUseBlockClone(LARGE_INTEGER file_size, 
                                  const WCHAR* src_path, const WCHAR* dst_path)
{
    // 文件大小检查
    if (file_size.QuadPart < PB_BLOCK_CLONE_THRESHOLD)
        return FALSE;
    
    // 文件系统检查
    if (!PB_IsReFSVolume(src_path) || !PB_IsReFSVolume(dst_path))
        return FALSE;
    
    // 卷检查
    return PB_PathIsOnSameVolume(src_path, dst_path);
}

// ============================================================================
// 辅助函数实现
// ============================================================================

static void PB_GetVolumePath(const WCHAR* file_path, WCHAR* volume_path, size_t size)
{
    if (!file_path || !volume_path || size == 0)
        return;
    
    // 提取驱动器号
    if (file_path[1] == L':')
    {
        volume_path[0] = file_path[0];
        volume_path[1] = L':';
        volume_path[2] = L'\\';
        volume_path[3] = L'\0';
    }
    else
    {
        // UNC路径处理
        const WCHAR* share_start = wcsstr(file_path, L"\\\\");
        if (share_start)
        {
            const WCHAR* share_end = wcschr(share_start + 2, L'\\');
            if (share_end)
            {
                size_t len = min(share_end - file_path + 1, (ptrdiff_t)size - 1);
                wcsncpy_s(volume_path, size, file_path, len);
                volume_path[len] = L'\0';
            }
        }
    }
}

static BOOL PB_PathIsOnSameVolume(const WCHAR* path1, const WCHAR* path2)
{
    if (!path1 || !path2)
        return FALSE;
    
    // 简单检查：比较驱动器号
    if (path1[1] == L':' && path2[1] == L':')
        return (towupper(path1[0]) == towupper(path2[0]));
    
    // 对于UNC路径，需要更复杂的检查
    return FALSE;
}

static size_t PB_AlignToSector(size_t size, size_t sector_size)
{
    if (sector_size == 0)
        sector_size = PB_DEFAULT_SECTOR_SIZE;
    
    return PB_ALIGN_UP(size, sector_size);
}