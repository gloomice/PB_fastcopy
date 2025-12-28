// ==============================================
// PB级小文件复制定时任务管理器 v10
// 极致性能优化版本 - 实现文件
// ==============================================

#include "PB_fastcopy_task_manager_v10.h"
#include <assert.h>
#include <stdarg.h>

// ==============================================
// 全局变量
// ==============================================

static char g_error_buffer[1024];
static CRITICAL_SECTION g_error_cs;
static volatile LONG g_error_initialized = 0;

// ==============================================
// 初始化与清理
// ==============================================

PB_TASK_MANAGER* pb_task_manager_create(const char* config_path) {
    // 初始化错误处理
    if (InterlockedCompareExchange(&g_error_initialized, 1, 0) == 0) {
        InitializeCriticalSection(&g_error_cs);
    }
    
    // 分配管理器内存（使用大页内存）
    PB_TASK_MANAGER* manager = (PB_TASK_MANAGER*)pb_malloc_large_page(sizeof(PB_TASK_MANAGER));
    if (!manager) {
        pb_error_log("Failed to allocate manager memory");
        return NULL;
    }
    
    // 清零内存
    ZeroMemory(manager, sizeof(PB_TASK_MANAGER));
    
    // 初始化同步原语
    InitializeSRWLock(&manager->manager_lock);
    InitializeConditionVariable(&manager->work_available);
    
    // 获取NTAPI函数
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
        manager->pNtCreateFile = (PNtCreateFile)GetProcAddress(ntdll, "NtCreateFile");
    }
    
    // 检测系统能力
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    
    // 检测I/O Ring支持
    manager->enable_io_ring = false;
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (kernel32) {
        // 检查是否存在I/O Ring相关函数
        FARPROC pCreateIoRing = GetProcAddress(kernel32, "CreateIoRing");
        if (pCreateIoRing) {
            manager->enable_io_ring = true;
        }
    }
    
    // 初始化NUMA支持
    if (!pb_task_manager_init_numa(manager)) {
        pb_error_log("Failed to initialize NUMA support");
        pb_free_large_page(manager, sizeof(PB_TASK_MANAGER));
        return NULL;
    }
    
    // 加载配置
    if (config_path) {
        pb_config_load(manager, config_path);
    } else {
        // 默认配置
        manager->max_worker_threads = DEFAULT_MAX_WORKER_THREADS;
        manager->max_scanner_threads = DEFAULT_MAX_SCANNER_THREADS;
        manager->io_ring_size = DEFAULT_IO_RING_SIZE;
        manager->max_batch_size = DEFAULT_MAX_TASKS_PER_BATCH;
        manager->batch_timeout_ms = DEFAULT_BATCH_TIMEOUT_MS;
        manager->use_large_pages = true;
        manager->enable_ntapi = true;
        manager->enable_handle_cache = true;
    }
    
    // 创建缓存系统
    if (manager->enable_handle_cache) {
        manager->handle_cache = pb_handle_cache_create(DEFAULT_HANDLE_CACHE_SIZE);
        if (!manager->handle_cache) {
            pb_error_log("Failed to create handle cache");
            pb_free_large_page(manager, sizeof(PB_TASK_MANAGER));
            return NULL;
        }
    }
    
    manager->metadata_cache = pb_metadata_cache_create(DEFAULT_METADATA_CACHE_SIZE);
    
    // 创建I/O批次
    manager->io_batch_count = manager->numa_node_count;
    manager->io_batches = (PB_IO_BATCH*)pb_malloc_aligned(
        sizeof(PB_IO_BATCH) * manager->io_batch_count, 
        CACHE_LINE_SIZE
    );
    
    for (uint32_t i = 0; i < manager->io_batch_count; i++) {
        if (!pb_io_batch_create(manager, i)) {
            pb_error_log("Failed to create I/O batch for NUMA node %u", i);
            pb_free_large_page(manager, sizeof(PB_TASK_MANAGER));
            return NULL;
        }
    }
    
    // 启动工作线程
    if (!pb_start_worker_threads(manager)) {
        pb_error_log("Failed to start worker threads");
        pb_free_large_page(manager, sizeof(PB_TASK_MANAGER));
        return NULL;
    }
    
    // 启动扫描线程
    if (!pb_start_scanner_threads(manager)) {
        pb_error_log("Failed to start scanner threads");
        pb_free_large_page(manager, sizeof(PB_TASK_MANAGER));
        return NULL;
    }
    
    // 启动定时器
    manager->schedule_timer = CreateWaitableTimer(NULL, FALSE, NULL);
    if (manager->schedule_timer) {
        HANDLE scheduler_thread = CreateThread(
            NULL, 0, pb_scheduler_thread, manager, 0, NULL
        );
        CloseHandle(scheduler_thread);
    }
    
    // 初始化统计信息
    manager->start_time = pb_get_time_ns();
    manager->last_report_time = manager->start_time;
    
    return manager;
}

bool pb_task_manager_destroy(PB_TASK_MANAGER* manager) {
    PB_CHECK_NULL(manager);
    
    // 设置关闭标志
    InterlockedExchange(&manager->is_shutdown, 1);
    
    // 唤醒所有等待的线程
    WakeAllConditionVariable(&manager->work_available);
    
    // 等待工作线程退出
    for (uint32_t i = 0; i < manager->worker_count; i++) {
        if (manager->worker_threads[i]) {
            WaitForSingleObject(manager->worker_threads[i], 5000);
            CloseHandle(manager->worker_threads[i]);
        }
    }
    
    // 等待扫描线程退出
    for (uint32_t i = 0; i < manager->scanner_count; i++) {
        if (manager->scanner_threads[i]) {
            WaitForSingleObject(manager->scanner_threads[i], 5000);
            CloseHandle(manager->scanner_threads[i]);
        }
    }
    
    // 清理I/O批次
    for (uint32_t i = 0; i < manager->io_batch_count; i++) {
        pb_io_batch_destroy(manager, i);
    }
    pb_free_aligned(manager->io_batches);
    
    // 清理NUMA队列
    for (uint32_t i = 0; i < manager->numa_node_count; i++) {
        if (manager->numa_queues[i]) {
            pb_free_aligned(manager->numa_queues[i]->tasks);
            pb_free_aligned(manager->numa_queues[i]);
        }
    }
    
    // 清理缓存
    if (manager->handle_cache) {
        pb_handle_cache_clear(manager->handle_cache);
        pb_free_aligned(manager->handle_cache);
    }
    
    if (manager->metadata_cache) {
        // 注意：metadata_cache的清理在pb_metadata_cache_create中实现
    }
    
    // 清理定时器
    if (manager->schedule_timer) {
        CloseHandle(manager->schedule_timer);
    }
    
    // 释放内存
    pb_free_large_page(manager, sizeof(PB_TASK_MANAGER));
    
    return true;
}

bool pb_task_manager_init_numa(PB_TASK_MANAGER* manager) {
    // 获取NUMA节点数量
    ULONG highest_node_number;
    if (!GetNumaHighestNodeNumber(&highest_node_number)) {
        manager->numa_node_count = 1;
    } else {
        manager->numa_node_count = highest_node_number + 1;
        if (manager->numa_node_count > MAX_NUMA_NODES) {
            manager->numa_node_count = MAX_NUMA_NODES;
        }
    }
    
    // 初始化CPU核心信息
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    
    DWORD_PTR process_affinity, system_affinity;
    GetProcessAffinityMask(GetCurrentProcess(), &process_affinity, &system_affinity);
    
    uint32_t core_index = 0;
    for (uint32_t i = 0; i < sizeof(DWORD_PTR) * 8; i++) {
        if (process_affinity & ((DWORD_PTR)1 << i)) {
            if (core_index < MAX_CPU_CORES) {
                manager->cpu_cores[core_index].core_id = i;
                manager->cpu_cores[core_index].numa_node = 
                    pb_get_numa_node_for_cpu(i);
                manager->cpu_cores[core_index].hyper_thread = false; // 简化处理
                manager->cpu_cores[core_index].utilization = 0;
                core_index++;
            }
        }
    }
    
    // 创建NUMA队列
    for (uint32_t i = 0; i < manager->numa_node_count; i++) {
        manager->numa_queues[i] = (PB_NUMA_QUEUE*)pb_malloc_aligned(
            sizeof(PB_NUMA_QUEUE), 
            CACHE_LINE_SIZE
        );
        
        if (!manager->numa_queues[i]) {
            pb_error_log("Failed to allocate NUMA queue %u", i);
            return false;
        }
        
        ZeroMemory(manager->numa_queues[i], sizeof(PB_NUMA_QUEUE));
        manager->numa_queues[i]->numa_node = i;
        InitializeSRWLock(&manager->numa_queues[i]->lock);
        
        // 分配任务数组（环形缓冲区）
        manager->numa_queues[i]->capacity = 65536; // 64K个任务
        manager->numa_queues[i]->tasks = (PB_TASK**)pb_malloc_aligned(
            sizeof(PB_TASK*) * manager->numa_queues[i]->capacity,
            CACHE_LINE_SIZE
        );
        
        if (!manager->numa_queues[i]->tasks) {
            pb_error_log("Failed to allocate task array for NUMA node %u", i);
            return false;
        }
        
        manager->numa_queues[i]->watermark_high = 
            manager->numa_queues[i]->capacity * 3 / 4;
        manager->numa_queues[i]->watermark_low = 
            manager->numa_queues[i]->capacity / 4;
    }
    
    return true;
}

// ==============================================
// 任务管理
// ==============================================

bool pb_task_add(PB_TASK_MANAGER* manager, const char* source, const char* target, uint8_t priority) {
    PB_CHECK_NULL(manager);
    PB_CHECK_NULL(source);
    PB_CHECK_NULL(target);
    
    // 分配任务内存
    PB_TASK* task = (PB_TASK*)pb_malloc_aligned(sizeof(PB_TASK), CACHE_LINE_SIZE);
    if (!task) {
        pb_error_log("Failed to allocate task memory");
        return false;
    }
    
    ZeroMemory(task, sizeof(PB_TASK));
    
    // 设置任务属性
    static volatile LONG g_task_id = 0;
    task->task_id = InterlockedIncrement(&g_task_id);
    task->priority = priority;
    
    // 复制路径
    strncpy_s(task->source_path, sizeof(task->source_path), source, _TRUNCATE);
    strncpy_s(task->target_path, sizeof(task->target_path), target, _TRUNCATE);
    
    // 计算哈希
    task->source_path_hash = pb_hash_string(source);
    task->target_path_hash = pb_hash_string(target);
    
    // 选择NUMA节点（基于哈希）
    task->numa_node = task->source_path_hash % manager->numa_node_count;
    
    // 推入队列
    if (!pb_task_push(manager, task)) {
        pb_free_aligned(task);
        return false;
    }
    
    // 更新统计
    InterlockedIncrement(&manager->total_tasks);
    InterlockedIncrement(&manager->pending_tasks);
    
    // 通知工作线程
    WakeConditionVariable(&manager->work_available);
    
    return true;
}

bool pb_task_add_batch(PB_TASK_MANAGER* manager, const char** sources, 
                      const char** targets, uint32_t count, uint8_t priority) {
    PB_CHECK_NULL(manager);
    PB_CHECK_NULL(sources);
    PB_CHECK_NULL(targets);
    
    // 批量添加任务
    uint32_t success_count = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (pb_task_add(manager, sources[i], targets[i], priority)) {
            success_count++;
        }
    }
    
    return success_count > 0;
}

PB_TASK* pb_task_pop(PB_TASK_MANAGER* manager, uint32_t numa_node, uint32_t timeout_ms) {
    PB_CHECK_NULL(manager);
    
    if (numa_node >= manager->numa_node_count) {
        numa_node = 0;
    }
    
    PB_NUMA_QUEUE* queue = manager->numa_queues[numa_node];
    if (!queue) {
        return NULL;
    }
    
    // 快速路径检查
    if (queue->count == 0) {
        return NULL;
    }
    
    PB_ENTER_CRITICAL_SECTION(queue->lock);
    
    // 再次检查（因为可能有竞争）
    if (queue->count == 0) {
        PB_LEAVE_CRITICAL_SECTION(queue->lock);
        return NULL;
    }
    
    // 从环形缓冲区头部获取任务
    uint32_t head = queue->head;
    PB_TASK* task = queue->tasks[head];
    
    // 更新头部指针
    queue->head = (head + 1) % queue->capacity;
    InterlockedDecrement(&queue->count);
    
    // 检查水位线
    if (queue->count <= queue->watermark_low) {
        // 可以通知扫描线程添加更多任务
        WakeConditionVariable(&manager->work_available);
    }
    
    PB_LEAVE_CRITICAL_SECTION(queue->lock);
    
    // 更新统计
    InterlockedDecrement(&manager->pending_tasks);
    InterlockedIncrement(&queue->total_processed);
    
    return task;
}

bool pb_task_push(PB_TASK_MANAGER* manager, PB_TASK* task) {
    PB_CHECK_NULL(manager);
    PB_CHECK_NULL(task);
    
    uint32_t numa_node = task->numa_node;
    if (numa_node >= manager->numa_node_count) {
        numa_node = 0;
    }
    
    PB_NUMA_QUEUE* queue = manager->numa_queues[numa_node];
    if (!queue) {
        return false;
    }
    
    PB_ENTER_CRITICAL_SECTION(queue->lock);
    
    // 检查队列是否已满
    if (queue->count >= queue->capacity) {
        // 扩展队列容量
        uint32_t new_capacity = queue->capacity * 2;
        PB_TASK** new_tasks = (PB_TASK**)pb_malloc_aligned(
            sizeof(PB_TASK*) * new_capacity,
            CACHE_LINE_SIZE
        );
        
        if (new_tasks) {
            // 复制现有任务
            for (uint32_t i = 0; i < queue->count; i++) {
                uint32_t idx = (queue->head + i) % queue->capacity;
                new_tasks[i] = queue->tasks[idx];
            }
            
            // 释放旧数组
            pb_free_aligned(queue->tasks);
            
            // 更新队列状态
            queue->tasks = new_tasks;
            queue->capacity = new_capacity;
            queue->head = 0;
            queue->tail = queue->count;
        } else {
            // 扩展失败，放弃任务
            PB_LEAVE_CRITICAL_SECTION(queue->lock);
            pb_error_log("Queue is full and cannot expand");
            return false;
        }
    }
    
    // 插入任务（根据优先级）
    uint32_t insert_pos = queue->tail;
    
    // 简单优先级插入（实际应该用优先级队列）
    queue->tasks[insert_pos] = task;
    queue->tail = (insert_pos + 1) % queue->capacity;
    InterlockedIncrement(&queue->count);
    
    PB_LEAVE_CRITICAL_SECTION(queue->lock);
    
    return true;
}

// ==============================================
// I/O操作
// ==============================================

bool pb_io_batch_create(PB_TASK_MANAGER* manager, uint32_t numa_node) {
    PB_CHECK_NULL(manager);
    
    if (numa_node >= manager->io_batch_count) {
        return false;
    }
    
    PB_IO_BATCH* batch = &manager->io_batches[numa_node];
    ZeroMemory(batch, sizeof(PB_IO_BATCH));
    
    batch->batch_id = numa_node;
    batch->numa_node = numa_node;
    batch->task_count = 0;
    batch->submitted_count = 0;
    
    // 创建I/O Ring
    if (manager->enable_io_ring) {
        IORING_CREATE_FLAGS flags;
        ZeroMemory(&flags, sizeof(flags));
        flags.Required = IORING_CREATE_REQUIRED_FLAGS_NONE;
        flags.Advisory = IORING_CREATE_ADVISORY_FLAGS_NONE;
        
        HIORING io_ring;
        IORING_CREATE_INPUT input;
        ZeroMemory(&input, sizeof(input));
        input.NumberOfEntries = manager->io_ring_size;
        
        HRESULT hr = CreateIoRing(IORING_VERSION_3, flags, &input, NULL, &io_ring);
        if (SUCCEEDED(hr)) {
            batch->io_ring = io_ring;
        } else {
            pb_error_log("Failed to create I/O Ring for NUMA node %u: 0x%08X", 
                        numa_node, hr);
        }
    }
    
    // 分配批次数组
    batch->tasks = (PB_TASK**)pb_malloc_aligned(
        sizeof(PB_TASK*) * manager->max_batch_size,
        CACHE_LINE_SIZE
    );
    
    batch->handle_refs = (IORING_HANDLE_REF*)pb_malloc_aligned(
        sizeof(IORING_HANDLE_REF) * manager->max_batch_size,
        CACHE_LINE_SIZE
    );
    
    batch->buffer_refs = (IORING_BUFFER_REF*)pb_malloc_aligned(
        sizeof(IORING_BUFFER_REF) * manager->max_batch_size,
        CACHE_LINE_SIZE
    );
    
    batch->overlappeds = (OVERLAPPED*)pb_malloc_aligned(
        sizeof(OVERLAPPED) * manager->max_batch_size,
        CACHE_LINE_SIZE
    );
    
    // 分配缓冲区内存（对齐到4KB）
    size_t buffer_size = manager->max_batch_size * 65536; // 每个任务最大64KB
    batch->buffers = pb_malloc_aligned(buffer_size, 4096);
    
    if (!batch->tasks || !batch->handle_refs || !batch->buffer_refs || 
        !batch->overlappeds || !batch->buffers) {
        pb_error_log("Failed to allocate batch memory for NUMA node %u", numa_node);
        return false;
    }
    
    ZeroMemory(batch->tasks, sizeof(PB_TASK*) * manager->max_batch_size);
    ZeroMemory(batch->handle_refs, sizeof(IORING_HANDLE_REF) * manager->max_batch_size);
    ZeroMemory(batch->buffer_refs, sizeof(IORING_BUFFER_REF) * manager->max_batch_size);
    ZeroMemory(batch->overlappeds, sizeof(OVERLAPPED) * manager->max_batch_size);
    ZeroMemory(batch->buffers, buffer_size);
    
    return true;
}

bool pb_io_batch_submit(PB_TASK_MANAGER* manager, uint32_t batch_id, 
                       PB_TASK** tasks, uint32_t count) {
    PB_CHECK_NULL(manager);
    PB_CHECK_NULL(tasks);
    
    if (batch_id >= manager->io_batch_count || count == 0) {
        return false;
    }
    
    PB_IO_BATCH* batch = &manager->io_batches[batch_id];
    
    if (!manager->enable_io_ring || batch->io_ring == NULL) {
        // 回退到传统异步I/O
        return pb_file_read_batch(manager, tasks, count);
    }
    
    // 使用I/O Ring批量提交
    batch->task_count = count;
    batch->submitted_count = 0;
    
    // 复制任务指针
    memcpy(batch->tasks, tasks, sizeof(PB_TASK*) * count);
    
    // 准备I/O Ring提交
    IORING_HANDLE_REF* handle_refs = batch->handle_refs;
    IORING_BUFFER_REF* buffer_refs = batch->buffer_refs;
    
    for (uint32_t i = 0; i < count; i++) {
        PB_TASK* task = tasks[i];
        if (!task) continue;
        
        // 打开源文件
        HANDLE src_handle = pb_file_open_nt(
            task->source_path,
            GENERIC_READ,
            FILE_SHARE_READ,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | FILE_FLAG_SEQUENTIAL_SCAN
        );
        
        if (src_handle == INVALID_HANDLE_VALUE) {
            task->status = STATUS_NOT_FOUND;
            continue;
        }
        
        task->source_handle = src_handle;
        
        // 设置I/O Ring句柄引用
        handle_refs[i].Kind = IORING_REF_RAW;
        handle_refs[i].Handle = src_handle;
        
        // 分配缓冲区
        task->buffer = (char*)batch->buffers + (i * 65536);
        task->buffer_size = min(task->file_size, 65536);
        
        // 设置缓冲区引用
        buffer_refs[i].Kind = IORING_REF_RAW;
        buffer_refs[i].Buffer = task->buffer;
        buffer_refs[i].Length = task->buffer_size;
        
        // 设置OVERLAPPED
        batch->overlappeds[i].Offset = 0;
        batch->overlappeds[i].OffsetHigh = 0;
        batch->overlappeds[i].hEvent = NULL;
        
        // 构建读请求
        HRESULT hr = BuildIoRingReadFile(
            batch->io_ring,
            handle_refs + i,
            buffer_refs + i,
            1,  // NumberOfEntries
            0,  // FileOffset
            batch->overlappeds + i,
            IOSQE_FLAGS_NONE
        );
        
        if (SUCCEEDED(hr)) {
            batch->submitted_count++;
        } else {
            task->status = STATUS_IO_DEVICE_ERROR;
            CloseHandle(src_handle);
        }
    }
    
    // 提交批次
    if (batch->submitted_count > 0) {
        HRESULT hr = SubmitIoRing(batch->io_ring, 0, 0, NULL);
        if (FAILED(hr)) {
            pb_error_log("Failed to submit I/O Ring batch: 0x%08X", hr);
            return false;
        }
        return true;
    }
    
    return false;
}

bool pb_io_batch_wait(PB_TASK_MANAGER* manager, uint32_t batch_id, uint32_t timeout_ms) {
    PB_CHECK_NULL(manager);
    
    if (batch_id >= manager->io_batch_count) {
        return false;
    }
    
    PB_IO_BATCH* batch = &manager->io_batches[batch_id];
    
    if (!manager->enable_io_ring || batch->io_ring == NULL) {
        // 回退到传统等待
        return pb_file_write_batch(manager, batch->tasks, batch->task_count);
    }
    
    if (batch->submitted_count == 0) {
        return true;
    }
    
    // 等待I/O完成
    IORING_CQ_WAIT_FLAGS wait_flags = {0};
    HRESULT hr = GetIoRingInfo(batch->io_ring);
    
    // 处理完成的任务
    uint32_t completed = 0;
    for (uint32_t i = 0; i < batch->task_count; i++) {
        PB_TASK* task = batch->tasks[i];
        if (!task) continue;
        
        // 检查I/O是否完成
        if (HasOverlappedIoCompleted(&batch->overlappeds[i])) {
            completed++;
            
            // 创建目标文件并写入
            HANDLE dst_handle = pb_file_open_nt(
                task->target_path,
                GENERIC_WRITE,
                0,
                CREATE_ALWAYS,
                FILE_FLAG_OVERLAPPED | FILE_FLAG_SEQUENTIAL_SCAN
            );
            
            if (dst_handle != INVALID_HANDLE_VALUE) {
                // 写入文件
                DWORD bytes_written = 0;
                BOOL write_result = WriteFile(
                    dst_handle,
                    task->buffer,
                    (DWORD)task->file_size,
                    &bytes_written,
                    NULL
                );
                
                if (write_result && bytes_written == task->file_size) {
                    task->status = STATUS_SUCCESS;
                } else {
                    task->status = STATUS_IO_DEVICE_ERROR;
                }
                
                CloseHandle(dst_handle);
            } else {
                task->status = STATUS_ACCESS_DENIED;
            }
            
            // 清理源句柄
            CloseHandle(task->source_handle);
            
            // 更新统计
            InterlockedIncrement(&manager->total_files_processed);
            InterlockedAdd64(&manager->total_bytes_processed, task->file_size);
            
            if (task->status != STATUS_SUCCESS) {
                InterlockedIncrement(&manager->total_errors);
            }
            
            // 释放任务内存
            pb_free_aligned(task);
            batch->tasks[i] = NULL;
        }
    }
    
    return completed == batch->task_count;
}

bool pb_io_batch_destroy(PB_TASK_MANAGER* manager, uint32_t batch_id) {
    PB_CHECK_NULL(manager);
    
    if (batch_id >= manager->io_batch_count) {
        return false;
    }
    
    PB_IO_BATCH* batch = &manager->io_batches[batch_id];
    
    // 关闭I/O Ring
    if (batch->io_ring) {
        CloseIoRing(batch->io_ring);
        batch->io_ring = NULL;
    }
    
    // 释放内存
    pb_free_aligned(batch->tasks);
    pb_free_aligned(batch->handle_refs);
    pb_free_aligned(batch->buffer_refs);
    pb_free_aligned(batch->overlappeds);
    pb_free_aligned(batch->buffers);
    
    ZeroMemory(batch, sizeof(PB_IO_BATCH));
    
    return true;
}

// ==============================================
// 文件操作（NTAPI优化）
// ==============================================

HANDLE pb_file_open_nt(const char* path, DWORD access, DWORD share, 
                      DWORD disposition, DWORD flags) {
    if (!path) return INVALID_HANDLE_VALUE;
    
    // 转换路径格式
    WCHAR wide_path[MAX_PATH];
    if (!MultiByteToWideChar(CP_UTF8, 0, path, -1, wide_path, MAX_PATH)) {
        return INVALID_HANDLE_VALUE;
    }
    
    // 使用NTAPI创建文件
    UNICODE_STRING uni_path;
    uni_path.Length = (USHORT)(wcslen(wide_path) * sizeof(WCHAR));
    uni_path.MaximumLength = uni_path.Length + sizeof(WCHAR);
    uni_path.Buffer = wide_path;
    
    OBJECT_ATTRIBUTES obj_attr;
    InitializeObjectAttributes(&obj_attr, &uni_path, OBJ_CASE_INSENSITIVE, NULL, NULL);
    
    IO_STATUS_BLOCK io_status;
    HANDLE file_handle = NULL;
    
    // 尝试使用NTAPI
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    PNtCreateFile pNtCreateFile = (PNtCreateFile)GetProcAddress(ntdll, "NtCreateFile");
    
    if (pNtCreateFile) {
        NTSTATUS status = pNtCreateFile(
            &file_handle,
            access,
            &obj_attr,
            &io_status,
            NULL,
            0,
            share,
            disposition,
            flags,
            NULL,
            0
        );
        
        if (NT_SUCCESS(status)) {
            return file_handle;
        }
    }
    
    // 回退到标准API
    return CreateFileW(
        wide_path,
        access,
        share,
        NULL,
        disposition,
        flags,
        NULL
    );
}

bool pb_file_copy_nt(PB_TASK_MANAGER* manager, PB_TASK* task) {
    PB_CHECK_NULL(manager);
    PB_CHECK_NULL(task);
    
    // 获取文件元数据
    uint64_t file_size = 0;
    uint64_t creation_time = 0;
    uint64_t last_write_time = 0;
    
    if (!pb_metadata_cache_get(manager->metadata_cache, 
                               task->source_path,
                               &file_size,
                               &creation_time,
                               &last_write_time)) {
        // 查询文件信息
        HANDLE hFile = pb_file_open_nt(
            task->source_path,
            GENERIC_READ,
            FILE_SHARE_READ,
            OPEN_EXISTING,
            FILE_FLAG_SEQUENTIAL_SCAN
        );
        
        if (hFile == INVALID_HANDLE_VALUE) {
            return false;
        }
        
        // 获取文件大小
        LARGE_INTEGER size;
        if (!GetFileSizeEx(hFile, &size)) {
            CloseHandle(hFile);
            return false;
        }
        file_size = size.QuadPart;
        
        // 获取文件时间
        FILETIME ftCreate, ftAccess, ftWrite;
        if (GetFileTime(hFile, &ftCreate, &ftAccess, &ftWrite)) {
            creation_time = ((uint64_t)ftCreate.dwHighDateTime << 32) | ftCreate.dwLowDateTime;
            last_write_time = ((uint64_t)ftWrite.dwHighDateTime << 32) | ftWrite.dwLowDateTime;
        }
        
        CloseHandle(hFile);
        
        // 缓存元数据
        pb_metadata_cache_put(manager->metadata_cache,
                             task->source_path,
                             file_size,
                             creation_time,
                             last_write_time);
    }
    
    task->file_size = file_size;
    task->creation_time = creation_time;
    task->last_write_time = last_write_time;
    
    return true;
}

bool pb_file_read_batch(PB_TASK_MANAGER* manager, PB_TASK** tasks, uint32_t count) {
    PB_CHECK_NULL(manager);
    PB_CHECK_NULL(tasks);
    
    if (count == 0) return true;
    
    // 准备异步读取
    HANDLE* events = (HANDLE*)alloca(sizeof(HANDLE) * count);
    OVERLAPPED* overlappeds = (OVERLAPPED*)alloca(sizeof(OVERLAPPED) * count);
    
    for (uint32_t i = 0; i < count; i++) {
        PB_TASK* task = tasks[i];
        if (!task || task->file_size == 0) {
            events[i] = NULL;
            continue;
        }
        
        // 打开源文件
        HANDLE src_handle = pb_file_open_nt(
            task->source_path,
            GENERIC_READ,
            FILE_SHARE_READ,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | FILE_FLAG_SEQUENTIAL_SCAN
        );
        
        if (src_handle == INVALID_HANDLE_VALUE) {
            events[i] = NULL;
            continue;
        }
        
        task->source_handle = src_handle;
        
        // 分配缓冲区
        task->buffer = pb_malloc_aligned((size_t)task->file_size, 4096);
        task->buffer_size = (size_t)task->file_size;
        
        // 准备异步读取
        events[i] = CreateEvent(NULL, TRUE, FALSE, NULL);
        ZeroMemory(&overlappeds[i], sizeof(OVERLAPPED));
        overlappeds[i].hEvent = events[i];
        
        // 开始异步读取
        DWORD bytes_read = 0;
        BOOL read_result = ReadFile(
            src_handle,
            task->buffer,
            (DWORD)task->file_size,
            &bytes_read,
            &overlappeds[i]
        );
        
        if (!read_result && GetLastError() != ERROR_IO_PENDING) {
            CloseHandle(src_handle);
            pb_free_aligned(task->buffer);
            CloseHandle(events[i]);
            events[i] = NULL;
        }
    }
    
    // 等待所有读取完成
    bool success = true;
    for (uint32_t i = 0; i < count; i++) {
        if (events[i]) {
            DWORD wait_result = WaitForSingleObject(events[i], INFINITE);
            if (wait_result == WAIT_OBJECT_0) {
                // 读取成功
                PB_TASK* task = tasks[i];
                
                // 获取实际读取的字节数
                DWORD bytes_transferred = 0;
                if (GetOverlappedResult(task->source_handle, &overlappeds[i], 
                                       &bytes_transferred, FALSE)) {
                    if (bytes_transferred != task->file_size) {
                        success = false;
                    }
                } else {
                    success = false;
                }
            } else {
                success = false;
            }
            
            CloseHandle(events[i]);
        }
    }
    
    return success;
}

bool pb_file_write_batch(PB_TASK_MANAGER* manager, PB_TASK** tasks, uint32_t count) {
    PB_CHECK_NULL(manager);
    PB_CHECK_NULL(tasks);
    
    if (count == 0) return true;
    
    bool overall_success = true;
    
    for (uint32_t i = 0; i < count; i++) {
        PB_TASK* task = tasks[i];
        if (!task) continue;
        
        // 打开目标文件
        HANDLE dst_handle = pb_file_open_nt(
            task->target_path,
            GENERIC_WRITE,
            0,
            CREATE_ALWAYS,
            FILE_FLAG_SEQUENTIAL_SCAN
        );
        
        if (dst_handle == INVALID_HANDLE_VALUE) {
            overall_success = false;
            task->status = STATUS_ACCESS_DENIED;
            continue;
        }
        
        // 写入文件
        DWORD bytes_written = 0;
        BOOL write_result = WriteFile(
            dst_handle,
            task->buffer,
            (DWORD)task->buffer_size,
            &bytes_written,
            NULL
        );
        
        if (write_result && bytes_written == task->buffer_size) {
            task->status = STATUS_SUCCESS;
            
            // 设置文件时间
            FILETIME ftCreate, ftWrite;
            ftCreate.dwLowDateTime = (DWORD)(task->creation_time & 0xFFFFFFFF);
            ftCreate.dwHighDateTime = (DWORD)(task->creation_time >> 32);
            ftWrite.dwLowDateTime = (DWORD)(task->last_write_time & 0xFFFFFFFF);
            ftWrite.dwHighDateTime = (DWORD)(task->last_write_time >> 32);
            
            SetFileTime(dst_handle, &ftCreate, NULL, &ftWrite);
        } else {
            overall_success = false;
            task->status = STATUS_IO_DEVICE_ERROR;
        }
        
        CloseHandle(dst_handle);
        
        // 清理源句柄
        if (task->source_handle != INVALID_HANDLE_VALUE) {
            CloseHandle(task->source_handle);
        }
        
        // 释放缓冲区
        if (task->buffer) {
            pb_free_aligned(task->buffer);
        }
        
        // 更新统计
        InterlockedIncrement(&manager->total_files_processed);
        InterlockedAdd64(&manager->total_bytes_processed, task->file_size);
        
        if (task->status != STATUS_SUCCESS) {
            InterlockedIncrement(&manager->total_errors);
        }
        
        // 释放任务内存
        pb_free_aligned(task);
        tasks[i] = NULL;
    }
    
    return overall_success;
}

// ==============================================
// 缓存管理
// ==============================================

PB_HANDLE_CACHE* pb_handle_cache_create(uint32_t size) {
    PB_HANDLE_CACHE* cache = (PB_HANDLE_CACHE*)pb_malloc_aligned(
        sizeof(PB_HANDLE_CACHE), 
        CACHE_LINE_SIZE
    );
    
    if (!cache) return NULL;
    
    ZeroMemory(cache, sizeof(PB_HANDLE_CACHE));
    
    cache->bucket_count = size / 16; // 每个桶平均16个条目
    if (cache->bucket_count < 64) cache->bucket_count = 64;
    
    cache->buckets = (PB_HANDLE_CACHE_ENTRY**)pb_malloc_aligned(
        sizeof(PB_HANDLE_CACHE_ENTRY*) * cache->bucket_count,
        CACHE_LINE_SIZE
    );
    
    if (!cache->buckets) {
        pb_free_aligned(cache);
        return NULL;
    }
    
    ZeroMemory(cache->buckets, sizeof(PB_HANDLE_CACHE_ENTRY*) * cache->bucket_count);
    cache->max_size = size;
    InitializeSRWLock(&cache->lock);
    
    return cache;
}

HANDLE pb_handle_cache_get(PB_HANDLE_CACHE* cache, const char* path, 
                          DWORD access, DWORD share, DWORD flags) {
    PB_CHECK_NULL(cache);
    PB_CHECK_NULL(path);
    
    uint32_t hash = pb_hash_string(path);
    uint32_t bucket = hash % cache->bucket_count;
    
    PB_ENTER_SHARED_SECTION(cache->lock);
    
    PB_HANDLE_CACHE_ENTRY* entry = cache->buckets[bucket];
    while (entry) {
        if (strcmp(entry->path, path) == 0) {
            // 检查句柄是否仍然有效
            DWORD dwFlags = 0;
            if (GetHandleInformation(entry->handle, &dwFlags)) {
                // 句柄有效，更新访问时间并返回
                entry->last_access = pb_get_time_ns();
                entry->access_count++;
                
                InterlockedIncrement64(&cache->hit_count);
                
                HANDLE result = entry->handle;
                PB_LEAVE_SHARED_SECTION(cache->lock);
                
                // 需要复制句柄，因为原始句柄可能被关闭
                HANDLE dup_handle;
                if (DuplicateHandle(
                    GetCurrentProcess(), result,
                    GetCurrentProcess(), &dup_handle,
                    0, FALSE, DUPLICATE_SAME_ACCESS)) {
                    return dup_handle;
                }
                return INVALID_HANDLE_VALUE;
            } else {
                // 句柄无效，从缓存中移除
                break;
            }
        }
        entry = entry->next;
    }
    
    PB_LEAVE_SHARED_SECTION(cache->lock);
    
    InterlockedIncrement64(&cache->miss_count);
    
    // 缓存未命中，创建新句柄
    HANDLE handle = pb_file_open_nt(path, access, share, OPEN_EXISTING, flags);
    if (handle != INVALID_HANDLE_VALUE) {
        pb_handle_cache_put(cache, path, handle);
    }
    
    return handle;
}

bool pb_handle_cache_put(PB_HANDLE_CACHE* cache, const char* path, HANDLE handle) {
    PB_CHECK_NULL(cache);
    PB_CHECK_NULL(path);
    
    if (handle == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    uint32_t hash = pb_hash_string(path);
    uint32_t bucket = hash % cache->bucket_count;
    
    PB_ENTER_CRITICAL_SECTION(cache->lock);
    
    // 检查是否已存在
    PB_HANDLE_CACHE_ENTRY** pentry = &cache->buckets[bucket];
    while (*pentry) {
        if (strcmp((*pentry)->path, path) == 0) {
            // 更新现有条目
            CloseHandle((*pentry)->handle);
            (*pentry)->handle = handle;
            (*pentry)->last_access = pb_get_time_ns();
            (*pentry)->access_count++;
            
            PB_LEAVE_CRITICAL_SECTION(cache->lock);
            return true;
        }
        pentry = &(*pentry)->next;
    }
    
    // 创建新条目
    PB_HANDLE_CACHE_ENTRY* new_entry = (PB_HANDLE_CACHE_ENTRY*)malloc(
        sizeof(PB_HANDLE_CACHE_ENTRY)
    );
    
    if (!new_entry) {
        PB_LEAVE_CRITICAL_SECTION(cache->lock);
        return false;
    }
    
    strncpy_s(new_entry->path, sizeof(new_entry->path), path, _TRUNCATE);
    new_entry->handle = handle;
    new_entry->last_access = pb_get_time_ns();
    new_entry->access_count = 1;
    new_entry->next = cache->buckets[bucket];
    
    cache->buckets[bucket] = new_entry;
    cache->current_size++;
    
    // 如果缓存已满，淘汰最旧的条目
    if (cache->current_size > cache->max_size) {
        // 简化：淘汰链表末尾的条目
        // 实际应该实现LRU算法
        PB_HANDLE_CACHE_ENTRY* prev = NULL;
        PB_HANDLE_CACHE_ENTRY* curr = cache->buckets[bucket];
        PB_HANDLE_CACHE_ENTRY* oldest_prev = NULL;
        PB_HANDLE_CACHE_ENTRY* oldest = curr;
        uint64_t oldest_time = curr->last_access;
        
        while (curr) {
            if (curr->last_access < oldest_time) {
                oldest_time = curr->last_access;
                oldest = curr;
                oldest_prev = prev;
            }
            prev = curr;
            curr = curr->next;
        }
        
        if (oldest) {
            if (oldest_prev) {
                oldest_prev->next = oldest->next;
            } else {
                cache->buckets[bucket] = oldest->next;
            }
            
            CloseHandle(oldest->handle);
            free(oldest);
            cache->current_size--;
        }
    }
    
    PB_LEAVE_CRITICAL_SECTION(cache->lock);
    return true;
}

bool pb_handle_cache_clear(PB_HANDLE_CACHE* cache) {
    PB_CHECK_NULL(cache);
    
    PB_ENTER_CRITICAL_SECTION(cache->lock);
    
    for (uint32_t i = 0; i < cache->bucket_count; i++) {
        PB_HANDLE_CACHE_ENTRY* entry = cache->buckets[i];
        while (entry) {
            PB_HANDLE_CACHE_ENTRY* next = entry->next;
            CloseHandle(entry->handle);
            free(entry);
            entry = next;
        }
        cache->buckets[i] = NULL;
    }
    
    cache->current_size = 0;
    cache->hit_count = 0;
    cache->miss_count = 0;
    
    PB_LEAVE_CRITICAL_SECTION(cache->lock);
    
    return true;
}

PB_METADATA_CACHE* pb_metadata_cache_create(uint32_t size) {
    PB_METADATA_CACHE* cache = (PB_METADATA_CACHE*)pb_malloc_aligned(
        sizeof(PB_METADATA_CACHE), 
        CACHE_LINE_SIZE
    );
    
    if (!cache) return NULL;
    
    ZeroMemory(cache, sizeof(PB_METADATA_CACHE));
    
    cache->bucket_count = size / 4; // 每个桶平均4个条目
    if (cache->bucket_count < 256) cache->bucket_count = 256;
    
    cache->buckets = (PB_METADATA_CACHE_ENTRY**)pb_malloc_aligned(
        sizeof(PB_METADATA_CACHE_ENTRY*) * cache->bucket_count,
        CACHE_LINE_SIZE
    );
    
    if (!cache->buckets) {
        pb_free_aligned(cache);
        return NULL;
    }
    
    ZeroMemory(cache->buckets, sizeof(PB_METADATA_CACHE_ENTRY*) * cache->bucket_count);
    InitializeSRWLock(&cache->lock);
    
    return cache;
}

bool pb_metadata_cache_get(PB_METADATA_CACHE* cache, const char* path,
                          uint64_t* size, uint64_t* creation, uint64_t* last_write) {
    PB_CHECK_NULL(cache);
    PB_CHECK_NULL(path);
    
    if (!size || !creation || !last_write) {
        return false;
    }
    
    uint32_t hash = pb_hash_string(path);
    uint32_t bucket = hash % cache->bucket_count;
    
    PB_ENTER_SHARED_SECTION(cache->lock);
    
    PB_METADATA_CACHE_ENTRY* entry = cache->buckets[bucket];
    while (entry) {
        if (strcmp(entry->path, path) == 0) {
            *size = entry->file_size;
            *creation = entry->creation_time;
            *last_write = entry->last_write_time;
            
            InterlockedIncrement64(&cache->hit_count);
            PB_LEAVE_SHARED_SECTION(cache->lock);
            return true;
        }
        entry = entry->next;
    }
    
    PB_LEAVE_SHARED_SECTION(cache->lock);
    
    InterlockedIncrement64(&cache->miss_count);
    return false;
}

bool pb_metadata_cache_put(PB_METADATA_CACHE* cache, const char* path,
                          uint64_t size, uint64_t creation, uint64_t last_write) {
    PB_CHECK_NULL(cache);
    PB_CHECK_NULL(path);
    
    uint32_t hash = pb_hash_string(path);
    uint32_t bucket = hash % cache->bucket_count;
    
    PB_ENTER_CRITICAL_SECTION(cache->lock);
    
    // 检查是否已存在
    PB_METADATA_CACHE_ENTRY** pentry = &cache->buckets[bucket];
    while (*pentry) {
        if (strcmp((*pentry)->path, path) == 0) {
            // 更新现有条目
            (*pentry)->file_size = size;
            (*pentry)->creation_time = creation;
            (*pentry)->last_write_time = last_write;
            PB_LEAVE_CRITICAL_SECTION(cache->lock);
            return true;
        }
        pentry = &(*pentry)->next;
    }
    
    // 创建新条目
    PB_METADATA_CACHE_ENTRY* new_entry = (PB_METADATA_CACHE_ENTRY*)malloc(
        sizeof(PB_METADATA_CACHE_ENTRY)
    );
    
    if (!new_entry) {
        PB_LEAVE_CRITICAL_SECTION(cache->lock);
        return false;
    }
    
    strncpy_s(new_entry->path, sizeof(new_entry->path), path, _TRUNCATE);
    new_entry->file_size = size;
    new_entry->creation_time = creation;
    new_entry->last_write_time = last_write;
    new_entry->path_hash = hash;
    new_entry->next = cache->buckets[bucket];
    
    cache->buckets[bucket] = new_entry;
    
    PB_LEAVE_CRITICAL_SECTION(cache->lock);
    return true;
}

// ==============================================
// 线程函数
// ==============================================

DWORD WINAPI pb_worker_thread(LPVOID param) {
    PB_TASK_MANAGER* manager = (PB_TASK_MANAGER*)param;
    if (!manager) return 0;
    
    // 设置线程亲和性（根据NUMA节点）
    uint32_t thread_id = GetCurrentThreadId();
    uint32_t numa_node = thread_id % manager->numa_node_count;
    
    DWORD_PTR affinity_mask = 1ULL << (thread_id % 64);
    SetThreadAffinityMask(GetCurrentThread(), affinity_mask);
    
    // 设置线程优先级
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    
    // 工作循环
    while (!pb_is_shutdown(manager)) {
        // 收集批次任务
        PB_TASK* batch_tasks[DEFAULT_MAX_TASKS_PER_BATCH];
        uint32_t batch_count = 0;
        
        for (uint32_t i = 0; i < pb_get_optimal_batch_size(manager, numa_node); i++) {
            PB_TASK* task = pb_task_pop(manager, numa_node, 10); // 10ms超时
            if (task) {
                batch_tasks[batch_count++] = task;
            } else {
                break;
            }
        }
        
        if (batch_count == 0) {
            // 等待新任务
            PB_ENTER_CRITICAL_SECTION(manager->manager_lock);
            SleepConditionVariableSRW(&manager->work_available, 
                                     &manager->manager_lock, 100, 0);
            PB_LEAVE_CRITICAL_SECTION(manager->manager_lock);
            continue;
        }
        
        // 处理批次
        bool batch_success = false;
        
        if (manager->enable_io_ring) {
            // 使用I/O Ring批量处理
            if (pb_io_batch_submit(manager, numa_node, batch_tasks, batch_count)) {
                batch_success = pb_io_batch_wait(manager, numa_node, 
                                                manager->batch_timeout_ms);
            }
        } else {
            // 传统异步I/O处理
            if (pb_file_read_batch(manager, batch_tasks, batch_count)) {
                batch_success = pb_file_write_batch(manager, batch_tasks, batch_count);
            }
        }
        
        if (!batch_success) {
            // 失败重试逻辑
            for (uint32_t i = 0; i < batch_count; i++) {
                PB_TASK* task = batch_tasks[i];
                if (task && task->status != STATUS_SUCCESS) {
                    if (task->retry_count < 3) {
                        task->retry_count++;
                        pb_task_push(manager, task);
                    } else {
                        // 重试次数耗尽，记录失败
                        pb_error_log("Task %llu failed after %d retries: %s -> %s",
                                    task->task_id, task->retry_count,
                                    task->source_path, task->target_path);
                        pb_free_aligned(task);
                    }
                }
            }
        }
    }
    
    return 0;
}

DWORD WINAPI pb_scanner_thread(LPVOID param) {
    PB_TASK_MANAGER* manager = (PB_TASK_MANAGER*)param;
    if (!manager) return 0;
    
    // 设置线程亲和性
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
    
    // 扫描循环
    while (!pb_is_shutdown(manager)) {
        // 检查各队列水位
        for (uint32_t i = 0; i < manager->numa_node_count; i++) {
            PB_NUMA_QUEUE* queue = manager->numa_queues[i];
            if (!queue) continue;
            
            // 如果队列水位低于低水位线，添加更多任务
            if (queue->count < queue->watermark_low) {
                // 这里可以添加从数据库或文件列表加载任务的逻辑
                // 简化实现：休眠一段时间
                Sleep(100);
            }
        }
        
        // 休眠以避免过度占用CPU
        Sleep(50);
    }
    
    return 0;
}

DWORD WINAPI pb_scheduler_thread(LPVOID param) {
    PB_TASK_MANAGER* manager = (PB_TASK_MANAGER*)param;
    if (!manager) return 0;
    
    // 设置定时器，每分钟检查一次
    LARGE_INTEGER due_time;
    due_time.QuadPart = -600000000; // 60秒
    
    while (!pb_is_shutdown(manager)) {
        // 等待定时器
        WaitForSingleObject(manager->schedule_timer, INFINITE);
        
        // 获取当前时间
        SYSTEMTIME current_time;
        GetLocalTime(&current_time);
        
        // 检查所有定时任务
        pb_schedule_check(manager, &current_time);
        
        // 重新设置定时器
        SetWaitableTimer(manager->schedule_timer, &due_time, 0, NULL, NULL, FALSE);
    }
    
    return 0;
}

// ==============================================
// 定时任务
// ==============================================

bool pb_schedule_add(PB_TASK_MANAGER* manager, const PB_SCHEDULE_CONFIG* config) {
    PB_CHECK_NULL(manager);
    PB_CHECK_NULL(config);
    
    // 分配新数组
    uint32_t new_count = manager->schedule_count + 1;
    PB_SCHEDULE_CONFIG* new_schedules = (PB_SCHEDULE_CONFIG*)realloc(
        manager->schedules, sizeof(PB_SCHEDULE_CONFIG) * new_count
    );
    
    if (!new_schedules) {
        return false;
    }
    
    manager->schedules = new_schedules;
    manager->schedules[manager->schedule_count] = *config;
    manager->schedule_count = new_count;
    
    return true;
}

bool pb_schedule_remove(PB_TASK_MANAGER* manager, uint32_t schedule_id) {
    PB_CHECK_NULL(manager);
    
    if (schedule_id >= manager->schedule_count) {
        return false;
    }
    
    // 移动后续元素
    for (uint32_t i = schedule_id; i < manager->schedule_count - 1; i++) {
        manager->schedules[i] = manager->schedules[i + 1];
    }
    
    manager->schedule_count--;
    
    // 缩小数组
    if (manager->schedule_count > 0) {
        PB_SCHEDULE_CONFIG* new_schedules = (PB_SCHEDULE_CONFIG*)realloc(
            manager->schedules, sizeof(PB_SCHEDULE_CONFIG) * manager->schedule_count
        );
        
        if (new_schedules) {
            manager->schedules = new_schedules;
        }
    } else {
        free(manager->schedules);
        manager->schedules = NULL;
    }
    
    return true;
}

bool pb_schedule_check(PB_TASK_MANAGER* manager, SYSTEMTIME* current_time) {
    PB_CHECK_NULL(manager);
    PB_CHECK_NULL(current_time);
    
    for (uint32_t i = 0; i < manager->schedule_count; i++) {
        PB_SCHEDULE_CONFIG* schedule = &manager->schedules[i];
        
        if (!schedule->enabled) {
            continue;
        }
        
        bool should_execute = true;
        
        // 检查月份
        if (schedule->month != 0 && schedule->month != current_time->wMonth) {
            should_execute = false;
        }
        
        // 检查日期
        if (schedule->day_of_month != 0 && schedule->day_of_month != current_time->wDay) {
            should_execute = false;
        }
        
        // 检查星期
        if (schedule->day_of_week != 0xFFFFFFFF) { // 0xFFFFFFFF表示所有天
            if (!(schedule->day_of_week & (1 << current_time->wDayOfWeek))) {
                should_execute = false;
            }
        }
        
        // 检查小时
        if (schedule->hour != current_time->wHour) {
            should_execute = false;
        }
        
        // 检查分钟
        if (schedule->minute != current_time->wMinute) {
            should_execute = false;
        }
        
        if (should_execute) {
            pb_schedule_execute(manager, i);
        }
    }
    
    return true;
}

bool pb_schedule_execute(PB_TASK_MANAGER* manager, uint32_t schedule_id) {
    PB_CHECK_NULL(manager);
    
    if (schedule_id >= manager->schedule_count) {
        return false;
    }
    
    // 这里可以执行定时任务，例如从配置文件加载任务列表
    // 简化实现：记录日志
    pb_error_log("Schedule %u executed at %llu", schedule_id, pb_get_time_ns());
    
    return true;
}

// ==============================================
// 监控与统计
// ==============================================

bool pb_stats_get(PB_TASK_MANAGER* manager, uint64_t* files_processed,
                  uint64_t* bytes_processed, uint64_t* errors,
                  uint32_t* queue_depth, uint32_t* active_workers) {
    PB_CHECK_NULL(manager);
    
    if (files_processed) {
        *files_processed = InterlockedCompareExchange64(
            (LONG64*)&manager->total_files_processed, 0, 0
        );
    }
    
    if (bytes_processed) {
        *bytes_processed = InterlockedCompareExchange64(
            (LONG64*)&manager->total_bytes_processed, 0, 0
        );
    }
    
    if (errors) {
        *errors = InterlockedCompareExchange64(
            (LONG64*)&manager->total_errors, 0, 0
        );
    }
    
    if (queue_depth) {
        *queue_depth = InterlockedCompareExchange(&manager->pending_tasks, 0, 0);
    }
    
    if (active_workers) {
        *active_workers = manager->worker_count;
    }
    
    return true;
}

void pb_stats_report(PB_TASK_MANAGER* manager, FILE* output) {
    if (!manager || !output) return;
    
    uint64_t current_time = pb_get_time_ns();
    uint64_t elapsed_ns = current_time - manager->start_time;
    double elapsed_seconds = elapsed_ns / 1e9;
    
    fprintf(output, "\n=== PB Task Manager Statistics ===\n");
    fprintf(output, "Uptime: %.2f seconds\n", elapsed_seconds);
    fprintf(output, "Total tasks processed: %llu\n", manager->total_files_processed);
    fprintf(output, "Total bytes processed: %llu (%.2f GB)\n", 
            manager->total_bytes_processed,
            manager->total_bytes_processed / (1024.0 * 1024.0 * 1024.0));
    fprintf(output, "Total errors: %llu\n", manager->total_errors);
    fprintf(output, "Pending tasks: %d\n", manager->pending_tasks);
    fprintf(output, "Active workers: %u\n", manager->worker_count);
    fprintf(output, "Active scanners: %u\n", manager->scanner_count);
    
    if (elapsed_seconds > 0) {
        double files_per_second = manager->total_files_processed / elapsed_seconds;
        double bytes_per_second = manager->total_bytes_processed / elapsed_seconds;
        double mb_per_second = bytes_per_second / (1024.0 * 1024.0);
        
        fprintf(output, "Throughput: %.2f files/sec\n", files_per_second);
        fprintf(output, "Bandwidth: %.2f MB/sec\n", mb_per_second);
    }
    
    // NUMA队列统计
    fprintf(output, "\nNUMA Queue Statistics:\n");
    for (uint32_t i = 0; i < manager->numa_node_count; i++) {
        PB_NUMA_QUEUE* queue = manager->numa_queues[i];
        if (queue) {
            fprintf(output, "  Node %u: %d tasks, %llu processed, %llu failed\n",
                    i, queue->count, queue->total_processed, queue->total_failed);
        }
    }
    
    // 缓存统计
    if (manager->handle_cache) {
        fprintf(output, "\nHandle Cache Statistics:\n");
        fprintf(output, "  Hits: %llu, Misses: %llu, Hit Rate: %.2f%%\n",
                manager->handle_cache->hit_count,
                manager->handle_cache->miss_count,
                manager->handle_cache->hit_count * 100.0 / 
                (manager->handle_cache->hit_count + manager->handle_cache->miss_count + 1));
    }
    
    if (manager->metadata_cache) {
        fprintf(output, "\nMetadata Cache Statistics:\n");
        fprintf(output, "  Hits: %llu, Misses: %llu, Hit Rate: %.2f%%\n",
                manager->metadata_cache->hit_count,
                manager->metadata_cache->miss_count,
                manager->metadata_cache->hit_count * 100.0 / 
                (manager->metadata_cache->hit_count + manager->metadata_cache->miss_count + 1));
    }
    
    fprintf(output, "===================================\n\n");
}

bool pb_monitor_start(PB_TASK_MANAGER* manager, uint32_t interval_seconds) {
    PB_CHECK_NULL(manager);
    
    // 创建监控线程
    HANDLE monitor_thread = CreateThread(
        NULL, 0, 
        [](LPVOID param) -> DWORD {
            PB_TASK_MANAGER* mgr = (PB_TASK_MANAGER*)param;
            uint32_t interval = *(uint32_t*)param;
            
            while (!pb_is_shutdown(mgr)) {
                // 生成报告
                pb_stats_report(mgr, stdout);
                
                // 休眠指定间隔
                Sleep(interval * 1000);
            }
            
            return 0;
        },
        &interval_seconds, 0, NULL
    );
    
    if (monitor_thread) {
        CloseHandle(monitor_thread);
        return true;
    }
    
    return false;
}

bool pb_monitor_stop(PB_TASK_MANAGER* manager) {
    // 监控线程通过设置shutdown标志自动退出
    return true;
}

// ==============================================
// 内存管理
// ==============================================

void* pb_malloc_aligned(size_t size, size_t alignment) {
    if (alignment < sizeof(void*)) {
        alignment = sizeof(void*);
    }
    
    void* ptr = _aligned_malloc(size, alignment);
    if (ptr) {
        ZeroMemory(ptr, size);
    }
    
    return ptr;
}

void pb_free_aligned(void* ptr) {
    if (ptr) {
        _aligned_free(ptr);
    }
}

void* pb_malloc_large_page(size_t size) {
    // 检查是否支持大页内存
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        LookupPrivilegeValue(NULL, SE_LOCK_MEMORY_NAME, &tp.Privileges[0].Luid);
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        
        AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
        CloseHandle(hToken);
    }
    
    // 获取大页大小
    size_t large_page_size = GetLargePageMinimum();
    if (large_page_size == 0) {
        large_page_size = 2 * 1024 * 1024; // 2MB默认值
    }
    
    // 对齐到整页
    size = (size + large_page_size - 1) & ~(large_page_size - 1);
    
    // 分配大页内存
    void* ptr = VirtualAlloc(
        NULL,
        size,
        MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES,
        PAGE_READWRITE
    );
    
    if (ptr) {
        ZeroMemory(ptr, size);
    }
    
    return ptr;
}

void pb_free_large_page(void* ptr, size_t size) {
    if (ptr) {
        VirtualFree(ptr, 0, MEM_RELEASE);
    }
}

// ==============================================
// 工具函数
// ==============================================

uint32_t pb_hash_string(const char* str) {
    // FNV-1a哈希算法
    uint32_t hash = 2166136261u;
    
    while (*str) {
        hash ^= (uint8_t)*str++;
        hash *= 16777619u;
    }
    
    return hash;
}

uint32_t pb_get_numa_node_for_cpu(uint32_t cpu_id) {
    ULONG numa_node = 0;
    if (!GetNumaProcessorNode((UCHAR)cpu_id, &numa_node)) {
        return 0;
    }
    return numa_node;
}

uint32_t pb_get_optimal_batch_size(PB_TASK_MANAGER* manager, uint32_t numa_node) {
    if (!manager || numa_node >= manager->numa_node_count) {
        return DEFAULT_MAX_TASKS_PER_BATCH;
    }
    
    // 根据队列深度动态调整批次大小
    PB_NUMA_QUEUE* queue = manager->numa_queues[numa_node];
    if (!queue) {
        return DEFAULT_MAX_TASKS_PER_BATCH;
    }
    
    uint32_t queue_size = queue->count;
    
    if (queue_size > 10000) {
        return manager->max_batch_size * 2;
    } else if (queue_size > 1000) {
        return manager->max_batch_size;
    } else if (queue_size > 100) {
        return manager->max_batch_size / 2;
    } else {
        return 16; // 小批量
    }
}

bool pb_set_thread_affinity(HANDLE thread, uint32_t cpu_mask) {
    return SetThreadAffinityMask(thread, cpu_mask) != 0;
}

bool pb_set_thread_priority_class(HANDLE thread, int priority) {
    return SetThreadPriority(thread, priority) != 0;
}

// ==============================================
// 配置管理
// ==============================================

bool pb_config_load(PB_TASK_MANAGER* manager, const char* path) {
    PB_CHECK_NULL(manager);
    PB_CHECK_NULL(path);
    
    // 简化实现：从INI文件加载配置
    // 实际应该使用更健壮的配置解析器
    
    char buffer[256];
    DWORD bytes_read;
    
    HANDLE hFile = CreateFileA(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    while (ReadFile(hFile, buffer, sizeof(buffer) - 1, &bytes_read, NULL) && bytes_read > 0) {
        buffer[bytes_read] = '\0';
        
        // 简单解析（实际应该用INI解析库）
        if (strstr(buffer, "max_worker_threads=")) {
            sscanf_s(strstr(buffer, "=") + 1, "%u", &manager->max_worker_threads);
        } else if (strstr(buffer, "io_ring_size=")) {
            sscanf_s(strstr(buffer, "=") + 1, "%u", &manager->io_ring_size);
        } else if (strstr(buffer, "use_large_pages=")) {
            char value[16];
            sscanf_s(strstr(buffer, "=") + 1, "%15s", value, (unsigned)_countof(value));
            manager->use_large_pages = (strcmp(value, "true") == 0);
        }
        // ... 解析其他配置项
    }
    
    CloseHandle(hFile);
    return true;
}

bool pb_config_save(PB_TASK_MANAGER* manager, const char* path) {
    PB_CHECK_NULL(manager);
    PB_CHECK_NULL(path);
    
    HANDLE hFile = CreateFileA(
        path,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    char buffer[512];
    DWORD bytes_written;
    
    // 写入配置
    sprintf_s(buffer, sizeof(buffer), 
              "max_worker_threads=%u\n"
              "max_scanner_threads=%u\n"
              "io_ring_size=%u\n"
              "max_batch_size=%u\n"
              "batch_timeout_ms=%u\n"
              "use_large_pages=%s\n"
              "enable_io_ring=%s\n"
              "enable_ntapi=%s\n"
              "enable_handle_cache=%s\n",
              manager->max_worker_threads,
              manager->max_scanner_threads,
              manager->io_ring_size,
              manager->max_batch_size,
              manager->batch_timeout_ms,
              manager->use_large_pages ? "true" : "false",
              manager->enable_io_ring ? "true" : "false",
              manager->enable_ntapi ? "true" : "false",
              manager->enable_handle_cache ? "true" : "false");
    
    WriteFile(hFile, buffer, (DWORD)strlen(buffer), &bytes_written, NULL);
    CloseHandle(hFile);
    
    return true;
}

bool pb_config_set(PB_TASK_MANAGER* manager, const char* key, const char* value) {
    PB_CHECK_NULL(manager);
    PB_CHECK_NULL(key);
    PB_CHECK_NULL(value);
    
    if (strcmp(key, "max_worker_threads") == 0) {
        manager->max_worker_threads = atoi(value);
        return true;
    } else if (strcmp(key, "io_ring_size") == 0) {
        manager->io_ring_size = atoi(value);
        return true;
    } else if (strcmp(key, "use_large_pages") == 0) {
        manager->use_large_pages = (strcmp(value, "true") == 0);
        return true;
    }
    // ... 处理其他配置项
    
    return false;
}

// ==============================================
// 错误处理
// ==============================================

const char* pb_error_to_string(int error_code) {
    static char buffer[256];
    
    FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        error_code,
        MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
        buffer,
        sizeof(buffer),
        NULL
    );
    
    return buffer;
}

bool pb_error_log(const char* format, ...) {
    EnterCriticalSection(&g_error_cs);
    
    va_list args;
    va_start(args, format);
    
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    char timestamp[64];
    sprintf_s(timestamp, sizeof(timestamp), 
              "[%04d-%02d-%02d %02d:%02d:%02d] ",
              st.wYear, st.wMonth, st.wDay,
              st.wHour, st.wMinute, st.wSecond);
    
    char message[1024];
    vsprintf_s(message, sizeof(message), format, args);
    
    printf("%s%s\n", timestamp, message);
    
    // 也可以写入日志文件
    FILE* log_file = fopen("pb_fastcopy.log", "a");
    if (log_file) {
        fprintf(log_file, "%s%s\n", timestamp, message);
        fclose(log_file);
    }
    
    va_end(args);
    LeaveCriticalSection(&g_error_cs);
    
    return true;
}

bool pb_error_set_last(int error_code) {
    // Windows错误代码已通过GetLastError()获取
    // 这里主要用于记录自定义错误
    return true;
}

// ==============================================
// 辅助函数（不在头文件中声明）
// ==============================================

static bool pb_start_worker_threads(PB_TASK_MANAGER* manager) {
    PB_CHECK_NULL(manager);
    
    // 根据CPU核心数创建工作线程
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    
    uint32_t worker_count = min(manager->max_worker_threads, 
                               (uint32_t)sys_info.dwNumberOfProcessors);
    
    for (uint32_t i = 0; i < worker_count; i++) {
        manager->worker_threads[i] = CreateThread(
            NULL, 0, pb_worker_thread, manager, 0, NULL
        );
        
        if (!manager->worker_threads[i]) {
            pb_error_log("Failed to create worker thread %u", i);
            return false;
        }
        
        manager->worker_count++;
    }
    
    pb_error_log("Started %u worker threads", manager->worker_count);
    return true;
}

static bool pb_start_scanner_threads(PB_TASK_MANAGER* manager) {
    PB_CHECK_NULL(manager);
    
    for (uint32_t i = 0; i < manager->max_scanner_threads; i++) {
        manager->scanner_threads[i] = CreateThread(
            NULL, 0, pb_scanner_thread, manager, 0, NULL
        );
        
        if (!manager->scanner_threads[i]) {
            pb_error_log("Failed to create scanner thread %u", i);
            return false;
        }
        
        manager->scanner_count++;
    }
    
    pb_error_log("Started %u scanner threads", manager->scanner_count);
    return true;
}