#include "PB_fastcopy_engine.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

// ============================================================================
// 引擎内部结构定义
// ============================================================================
struct FastCopyEngine {
    // 状态和配置
    EngineState state;
    EngineConfig config;
    EngineStatistics stats;
    
    // 模块实例
    PB_FileHandlePool* file_pool;
    PB_Logger* logger;
    PB_NetworkMgr* network_mgr;
    PB_TaskManager* task_manager;
    
    // 内部队列和缓冲区
    PB_RingBuffer* task_queue;
    PB_RingBuffer* event_queue;
    
    // 线程和同步
    HANDLE scheduler_thread;
    HANDLE io_worker_threads[4];
    HANDLE network_worker_threads[2];
    CRITICAL_SECTION engine_lock;
    CONDITION_VARIABLE task_available;
    
    // 资源管理
    uint64_t current_memory_usage;
    uint32_t active_task_count;
    
    // 时间戳
    uint64_t engine_start_time;
    LARGE_INTEGER qpc_frequency;
};

// ============================================================================
// 内部函数声明
// ============================================================================
static DWORD WINAPI engine_scheduler_thread(LPVOID param);
static DWORD WINAPI engine_io_worker_thread(LPVOID param);
static DWORD WINAPI engine_network_worker_thread(LPVOID param);
static int engine_process_task(FastCopyEngine* engine, EngineTask* task);
static void engine_update_statistics(FastCopyEngine* engine);
static void engine_log_event(FastCopyEngine* engine, const char* message, int level);

// ============================================================================
// 引擎创建和初始化
// ============================================================================
FastCopyEngine* engine_create(const EngineConfig* config)
{
    if (!config) {
        return NULL;
    }
    
    // 分配引擎内存
    FastCopyEngine* engine = (FastCopyEngine*)calloc(1, sizeof(FastCopyEngine));
    if (!engine) {
        return NULL;
    }
    
    // 初始化引擎结构
    engine->state = ENGINE_STATE_UNINITIALIZED;
    memcpy(&engine->config, config, sizeof(EngineConfig));
    
    // 初始化性能计数器
    QueryPerformanceFrequency(&engine->qpc_frequency);
    QueryPerformanceCounter((LARGE_INTEGER*)&engine->engine_start_time);
    
    // 初始化锁和条件变量
    InitializeCriticalSection(&engine->engine_lock);
    InitializeConditionVariable(&engine->task_available);
    
    // 初始化统计信息
    memset(&engine->stats, 0, sizeof(EngineStatistics));
    engine->stats.start_time = engine->engine_start_time;
    
    return engine;
}

int engine_initialize(FastCopyEngine* engine)
{
    if (!engine || engine->state != ENGINE_STATE_UNINITIALIZED) {
        return ENGINE_ERROR_INVALID_STATE;
    }
    
    int result = ENGINE_SUCCESS;
    
    // 设置状态为初始化中
    engine->state = ENGINE_STATE_INITIALIZED;
    
    // 1. 初始化日志模块
    PB_LoggerConfig logger_config;
    memset(&logger_config, 0, sizeof(logger_config));
    
    // 构建日志文件名
    char log_filename[MAX_PATH];
    snprintf(log_filename, sizeof(log_filename), "%s\\fastcopy_engine_%lld.log",
             engine->config.work_directory, (long long)time(NULL));
    
    // 转换为宽字符（Windows需要）
    wchar_t log_filename_w[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, log_filename, -1, log_filename_w, MAX_PATH);
    
    wcscpy_s(logger_config.filename, PB_LOG_MAX_FILENAME_LEN, log_filename_w);
    logger_config.buffer_count = 4;
    logger_config.buffer_size = 4 * 1024 * 1024; // 4MB缓冲区
    logger_config.preallocate_size = 100 * 1024 * 1024; // 预分配100MB
    
    engine->logger = pb_logger_create(&logger_config);
    if (!engine->logger) {
        engine_log_event(engine, "Failed to initialize logger module", PB_LOG_LEVEL_ERROR);
        result = ENGINE_ERROR_MODULE_INIT_FAILED;
        goto cleanup;
    }
    
    engine_log_event(engine, "Logger module initialized successfully", PB_LOG_LEVEL_INFO);
    
    // 2. 初始化文件操作模块
    PB_FileOpsConfig file_ops_config;
    memset(&file_ops_config, 0, sizeof(file_ops_config));
    file_ops_config.enable_direct_io = engine->config.enable_direct_io;
    file_ops_config.enable_write_through = engine->config.enable_write_through;
    file_ops_config.buffer_size_kb = engine->config.buffer_size_kb;
    file_ops_config.max_open_files = 1024;
    
    engine->file_pool = pb_filehandlepool_create(&file_ops_config);
    if (!engine->file_pool) {
        engine_log_event(engine, "Failed to initialize file operations module", PB_LOG_LEVEL_ERROR);
        result = ENGINE_ERROR_MODULE_INIT_FAILED;
        goto cleanup;
    }
    
    engine_log_event(engine, "File operations module initialized successfully", PB_LOG_LEVEL_INFO);
    
    // 3. 初始化网络模块
    PB_NetworkConfig network_config;
    memset(&network_config, 0, sizeof(network_config));
    network_config.max_concurrent_connections = engine->config.max_network_connections;
    network_config.timeout_ms = engine->config.network_timeout_ms;
    network_config.retry_count = engine->config.network_retry_count;
    network_config.enable_iocp = true;
    network_config.iocp_thread_count = engine->config.network_thread_count;
    
    engine->network_mgr = pb_networkmgr_create(&network_config);
    if (!engine->network_mgr) {
        engine_log_event(engine, "Failed to initialize network module", PB_LOG_LEVEL_ERROR);
        result = ENGINE_ERROR_MODULE_INIT_FAILED;
        goto cleanup;
    }
    
    engine_log_event(engine, "Network module initialized successfully", PB_LOG_LEVEL_INFO);
    
    // 4. 初始化任务管理器
    PB_TaskManagerConfig taskmgr_config;
    memset(&taskmgr_config, 0, sizeof(taskmgr_config));
    taskmgr_config.max_concurrent_tasks = engine->config.max_concurrent_tasks;
    taskmgr_config.enable_task_history = true;
    taskmgr_config.history_size = 10000;
    taskmgr_config.task_timeout_ms = 3600000; // 1小时超时
    
    engine->task_manager = pb_taskmgr_create(&taskmgr_config);
    if (!engine->task_manager) {
        engine_log_event(engine, "Failed to initialize task manager module", PB_LOG_LEVEL_ERROR);
        result = ENGINE_ERROR_MODULE_INIT_FAILED;
        goto cleanup;
    }
    
    engine_log_event(engine, "Task manager module initialized successfully", PB_LOG_LEVEL_INFO);
    
    // 5. 创建任务队列（无锁环形缓冲区）
    engine->task_queue = pb_ringbuffer_create(
        64 * 1024 * 1024, // 64MB缓冲区
        sizeof(EngineTask),
        1                  // 生产者ID
    );
    
    if (!engine->task_queue) {
        engine_log_event(engine, "Failed to create task queue", PB_LOG_LEVEL_ERROR);
        result = ENGINE_ERROR_INTERNAL;
        goto cleanup;
    }
    
    // 6. 创建事件队列
    engine->event_queue = pb_ringbuffer_create(
        4 * 1024 * 1024, // 4MB缓冲区
        256,              // 最大事件大小
        1
    );
    
    // 7. 创建工作线程
    // 调度器线程
    engine->scheduler_thread = CreateThread(
        NULL,                   // 默认安全属性
        0,                      // 默认堆栈大小
        engine_scheduler_thread,
        engine,                 // 线程参数
        0,                      // 创建标志
        NULL                    // 线程ID
    );
    
    if (!engine->scheduler_thread) {
        engine_log_event(engine, "Failed to create scheduler thread", PB_LOG_LEVEL_ERROR);
        result = ENGINE_ERROR_INTERNAL;
        goto cleanup;
    }
    
    // I/O工作线程
    for (int i = 0; i < min(4, engine->config.io_thread_count); i++) {
        engine->io_worker_threads[i] = CreateThread(
            NULL,
            0,
            engine_io_worker_thread,
            engine,
            0,
            NULL
        );
        
        if (!engine->io_worker_threads[i]) {
            engine_log_event(engine, "Failed to create I/O worker thread", PB_LOG_LEVEL_WARNING);
        }
    }
    
    // 网络工作线程
    for (int i = 0; i < min(2, engine->config.network_thread_count); i++) {
        engine->network_worker_threads[i] = CreateThread(
            NULL,
            0,
            engine_network_worker_thread,
            engine,
            0,
            NULL
        );
        
        if (!engine->network_worker_threads[i]) {
            engine_log_event(engine, "Failed to create network worker thread", PB_LOG_LEVEL_WARNING);
        }
    }
    
    engine_log_event(engine, "Engine initialized successfully", PB_LOG_LEVEL_INFO);
    
    return ENGINE_SUCCESS;
    
cleanup:
    // 清理已分配的资源
    if (engine->logger) {
        pb_logger_destroy(engine->logger);
        engine->logger = NULL;
    }
    
    if (engine->file_pool) {
        pb_filehandlepool_destroy(engine->file_pool);
        engine->file_pool = NULL;
    }
    
    if (engine->network_mgr) {
        pb_networkmgr_destroy(engine->network_mgr);
        engine->network_mgr = NULL;
    }
    
    if (engine->task_manager) {
        pb_taskmgr_destroy(engine->task_manager);
        engine->task_manager = NULL;
    }
    
    engine->state = ENGINE_STATE_ERROR;
    return result;
}

// ============================================================================
// 调度器线程函数
// ============================================================================
static DWORD WINAPI engine_scheduler_thread(LPVOID param)
{
    FastCopyEngine* engine = (FastCopyEngine*)param;
    if (!engine) {
        return 1;
    }
    
    engine_log_event(engine, "Scheduler thread started", PB_LOG_LEVEL_DEBUG);
    
    while (engine->state == ENGINE_STATE_RUNNING || 
           engine->state == ENGINE_STATE_PAUSED) {
        
        EnterCriticalSection(&engine->engine_lock);
        
        // 检查是否有任务
        if (engine->active_task_count >= engine->config.max_concurrent_tasks ||
            engine->state == ENGINE_STATE_PAUSED) {
            // 等待任务可用或状态改变
            SleepConditionVariableCS(&engine->task_available, &engine->engine_lock, 100);
            LeaveCriticalSection(&engine->engine_lock);
            continue;
        }
        
        // 从任务队列获取任务
        EngineTask task;
        if (pb_ringbuffer_read(engine->task_queue, &task, sizeof(task))) {
            // 增加活动任务计数
            engine->active_task_count++;
            engine->stats.queued_tasks--;
            
            LeaveCriticalSection(&engine->engine_lock);
            
            // 处理任务
            int result = engine_process_task(engine, &task);
            
            EnterCriticalSection(&engine->engine_lock);
            engine->active_task_count--;
            
            // 更新统计信息
            if (result == ENGINE_SUCCESS) {
                engine->stats.total_tasks_completed++;
            } else {
                engine->stats.total_tasks_failed++;
            }
            
            // 如果有回调函数，调用它
            if (engine->config.progress_callback) {
                // 这里可以发送完成通知
            }
            
            LeaveCriticalSection(&engine->engine_lock);
            
            // 更新统计
            engine_update_statistics(engine);
        } else {
            // 没有任务，等待
            LeaveCriticalSection(&engine->engine_lock);
            Sleep(10); // 短暂休眠避免CPU空转
        }
    }
    
    engine_log_event(engine, "Scheduler thread stopped", PB_LOG_LEVEL_DEBUG);
    return 0;
}

// ============================================================================
// 任务处理函数
// ============================================================================
static int engine_process_task(FastCopyEngine* engine, EngineTask* task)
{
    if (!engine || !task) {
        return ENGINE_ERROR_INVALID_PARAM;
    }
    
    int result = ENGINE_SUCCESS;
    
    // 记录任务开始
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Processing task %s, type: %d", 
             task->task_id, task->type);
    engine_log_event(engine, log_msg, PB_LOG_LEVEL_INFO);
    
    // 根据任务类型选择适配器
    switch (task->type) {
        case TASK_TYPE_FILE_COPY:
        case TASK_TYPE_FILE_MOVE:
        case TASK_TYPE_BATCH_OPERATION: {
            FileCopyAdapter adapter;
            result = adapter_file_copy_init(&adapter, engine, task);
            if (result == ENGINE_SUCCESS) {
                result = adapter_file_copy_execute(&adapter);
                adapter_file_copy_cleanup(&adapter);
            }
            break;
        }
        
        case TASK_TYPE_NETWORK_UPLOAD:
        case TASK_TYPE_NETWORK_DOWNLOAD: {
            NetworkTransferAdapter adapter;
            result = adapter_network_transfer_init(&adapter, engine, task);
            if (result == ENGINE_SUCCESS) {
                result = adapter_network_transfer_execute(&adapter);
                adapter_network_transfer_cleanup(&adapter);
            }
            break;
        }
        
        default:
            result = ENGINE_ERROR_INVALID_PARAM;
            break;
    }
    
    // 记录任务完成
    snprintf(log_msg, sizeof(log_msg), "Task %s completed with result: %d", 
             task->task_id, result);
    engine_log_event(engine, log_msg, 
                     result == ENGINE_SUCCESS ? PB_LOG_LEVEL_INFO : PB_LOG_LEVEL_ERROR);
    
    return result;
}