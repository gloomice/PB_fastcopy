#include "PB_fastcopy_engine.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

// ============================================================================
// 文件操作适配器
// ============================================================================

typedef struct {
    FastCopyEngine* engine;
    EngineTask* engine_task;
    PB_FileBatch* file_batch;
    uint64_t total_size;
    uint64_t processed_size;
    time_t start_time;
} FileCopyAdapter;

static int adapter_file_copy_init(FileCopyAdapter* adapter, 
                                 FastCopyEngine* engine, 
                                 const EngineTask* task)
{
    if (!adapter || !engine || !task) {
        return ENGINE_ERROR_INVALID_PARAM;
    }
    
    // 初始化适配器结构
    adapter->engine = engine;
    adapter->engine_task = (EngineTask*)task;
    adapter->total_size = 0;
    adapter->processed_size = 0;
    adapter->start_time = time(NULL);
    
    // 创建文件批次
    adapter->file_batch = pb_filebatch_create();
    if (!adapter->file_batch) {
        return ENGINE_ERROR_MEMORY_ALLOC;
    }
    
    // 根据任务类型配置批次
    switch (task->type) {
        case TASK_TYPE_FILE_COPY:
            // 添加文件到批次（这里简化处理，实际需要遍历文件系统）
            if (pb_filebatch_add(adapter->file_batch, 
                                task->params.file_op.source_path,
                                task->params.file_op.destination_path) != 0) {
                pb_filebatch_destroy(adapter->file_batch);
                return ENGINE_ERROR_IO_FAILED;
            }
            break;
            
        case TASK_TYPE_BATCH_OPERATION:
            // 批量操作需要特殊处理
            // 这里可以调用文件系统枚举函数
            break;
            
        default:
            pb_filebatch_destroy(adapter->file_batch);
            return ENGINE_ERROR_INVALID_PARAM;
    }
    
    // 计算总大小
    adapter->total_size = pb_filebatch_get_total_size(adapter->file_batch);
    
    return ENGINE_SUCCESS;
}

static void adapter_file_copy_cleanup(FileCopyAdapter* adapter)
{
    if (adapter && adapter->file_batch) {
        pb_filebatch_destroy(adapter->file_batch);
    }
}

static int adapter_file_copy_execute(FileCopyAdapter* adapter)
{
    if (!adapter || !adapter->engine || !adapter->file_batch) {
        return ENGINE_ERROR_INVALID_PARAM;
    }
    
    FastCopyEngine* engine = adapter->engine;
    
    // 获取文件句柄池
    PB_FileHandlePool* pool = pb_filehandlepool_get_instance();
    if (!pool) {
        return ENGINE_ERROR_RESOURCE_LIMIT;
    }
    
    // 配置复制选项
    PB_CopyOptions options;
    memset(&options, 0, sizeof(options));
    options.enable_direct_io = engine->config.enable_direct_io;
    options.enable_write_through = engine->config.enable_write_through;
    options.buffer_size_kb = engine->config.buffer_size_kb;
    options.verify_after_copy = adapter->engine_task->verify_after_completion;
    options.preserve_attributes = adapter->engine_task->preserve_attributes;
    
    // 进度回调包装函数
    auto progress_wrapper = [](uint64_t bytes_copied, uint64_t bytes_total, void* context) -> bool {
        FileCopyAdapter* adapter = (FileCopyAdapter*)context;
        if (!adapter || !adapter->engine) return true;
        
        adapter->processed_size = bytes_copied;
        
        // 调用引擎进度回调
        if (adapter->engine->config.progress_callback) {
            float progress = (bytes_total > 0) ? 
                ((float)bytes_copied / bytes_total * 100.0f) : 0.0f;
            
            adapter->engine->config.progress_callback(
                adapter->engine_task->task_id,
                bytes_copied,
                bytes_total,
                progress,
                adapter->engine->config.callback_user_data
            );
        }
        
        // 检查是否应该停止
        return (adapter->engine->state != ENGINE_STATE_STOPPING);
    };
    
    // 执行文件复制
    NTSTATUS status = pb_copy_batch_direct(
        adapter->file_batch,
        pool,
        &options,
        progress_wrapper,
        adapter
    );
    
    // 转换NTSTATUS到引擎错误码
    if (status != STATUS_SUCCESS) {
        // 记录错误日志
        if (engine->logger) {
            char error_msg[256];
            snprintf(error_msg, sizeof(error_msg), 
                    "File copy failed with NTSTATUS: 0x%08X", status);
            pb_log_write(engine->logger, PB_LOG_LEVEL_ERROR, error_msg);
        }
        
        return ENGINE_ERROR_IO_FAILED;
    }
    
    return ENGINE_SUCCESS;
}

// ============================================================================
// 网络操作适配器
// ============================================================================

typedef struct {
    FastCopyEngine* engine;
    EngineTask* engine_task;
    PB_NetworkTransfer* transfer;
    uint64_t total_size;
    uint64_t transferred_size;
} NetworkTransferAdapter;

static int adapter_network_transfer_init(NetworkTransferAdapter* adapter,
                                        FastCopyEngine* engine,
                                        const EngineTask* task)
{
    if (!adapter || !engine || !task) {
        return ENGINE_ERROR_INVALID_PARAM;
    }
    
    // 验证任务类型
    if (task->type != TASK_TYPE_NETWORK_UPLOAD && 
        task->type != TASK_TYPE_NETWORK_DOWNLOAD) {
        return ENGINE_ERROR_INVALID_PARAM;
    }
    
    adapter->engine = engine;
    adapter->engine_task = (EngineTask*)task;
    adapter->total_size = 0;
    adapter->transferred_size = 0;
    
    // 创建网络传输对象
    PB_NetworkConfig net_config;
    memset(&net_config, 0, sizeof(net_config));
    net_config.max_concurrent_connections = engine->config.max_network_connections;
    net_config.timeout_ms = engine->config.network_timeout_ms;
    net_config.retry_count = engine->config.network_retry_count;
    net_config.enable_compression = true;
    net_config.enable_encryption = false; // 根据实际需求配置
    
    adapter->transfer = pb_network_transfer_create(&net_config);
    if (!adapter->transfer) {
        return ENGINE_ERROR_NETWORK_FAILED;
    }
    
    // 根据上传/下载配置传输
    if (task->type == TASK_TYPE_NETWORK_UPLOAD) {
        // 上传：本地文件 -> 远程URL
        if (pb_network_transfer_setup_upload(
                adapter->transfer,
                task->params.network_op.local_path,
                task->params.network_op.remote_url) != 0) {
            pb_network_transfer_destroy(adapter->transfer);
            return ENGINE_ERROR_NETWORK_FAILED;
        }
    } else {
        // 下载：远程URL -> 本地文件
        if (pb_network_transfer_setup_download(
                adapter->transfer,
                task->params.network_op.remote_url,
                task->params.network_op.local_path) != 0) {
            pb_network_transfer_destroy(adapter->transfer);
            return ENGINE_ERROR_NETWORK_FAILED;
        }
    }
    
    // 获取总大小
    adapter->total_size = pb_network_transfer_get_total_size(adapter->transfer);
    
    return ENGINE_SUCCESS;
}

static void adapter_network_transfer_cleanup(NetworkTransferAdapter* adapter)
{
    if (adapter && adapter->transfer) {
        pb_network_transfer_destroy(adapter->transfer);
    }
}

static int adapter_network_transfer_execute(NetworkTransferAdapter* adapter)
{
    if (!adapter || !adapter->engine || !adapter->transfer) {
        return ENGINE_ERROR_INVALID_PARAM;
    }
    
    FastCopyEngine* engine = adapter->engine;
    
    // 进度回调包装
    auto progress_callback = [](uint64_t transferred, uint64_t total, void* context) -> bool {
        NetworkTransferAdapter* adapter = (NetworkTransferAdapter*)context;
        if (!adapter || !adapter->engine) return true;
        
        adapter->transferred_size = transferred;
        
        if (adapter->engine->config.progress_callback) {
            float progress = (total > 0) ? 
                ((float)transferred / total * 100.0f) : 0.0f;
            
            adapter->engine->config.progress_callback(
                adapter->engine_task->task_id,
                transferred,
                total,
                progress,
                adapter->engine->config.callback_user_data
            );
        }
        
        return (adapter->engine->state != ENGINE_STATE_STOPPING);
    };
    
    // 执行网络传输
    int result = pb_network_transfer_execute(
        adapter->transfer,
        progress_callback,
        adapter
    );
    
    if (result != 0) {
        // 记录网络错误
        if (engine->logger) {
            const char* error_detail = pb_network_transfer_get_last_error(adapter->transfer);
            char error_msg[512];
            snprintf(error_msg, sizeof(error_msg),
                    "Network transfer failed: %s", error_detail ? error_detail : "Unknown error");
            pb_log_write(engine->logger, PB_LOG_LEVEL_ERROR, error_msg);
        }
        
        return ENGINE_ERROR_NETWORK_FAILED;
    }
    
    return ENGINE_SUCCESS;
}

// ============================================================================
// 任务管理器适配器
// ============================================================================

typedef struct {
    FastCopyEngine* engine;
    PB_TaskManager* task_manager;
    CRITICAL_SECTION lock;
} TaskManagerAdapter;

static TaskManagerAdapter* g_task_manager_adapter = NULL;

int task_manager_adapter_init(FastCopyEngine* engine)
{
    if (!engine) {
        return ENGINE_ERROR_INVALID_PARAM;
    }
    
    // 创建适配器实例
    g_task_manager_adapter = (TaskManagerAdapter*)calloc(1, sizeof(TaskManagerAdapter));
    if (!g_task_manager_adapter) {
        return ENGINE_ERROR_MEMORY_ALLOC;
    }
    
    g_task_manager_adapter->engine = engine;
    InitializeCriticalSection(&g_task_manager_adapter->lock);
    
    // 创建底层任务管理器
    PB_TaskManagerConfig tm_config;
    memset(&tm_config, 0, sizeof(tm_config));
    tm_config.max_concurrent_tasks = engine->config.max_concurrent_tasks;
    tm_config.enable_task_persistence = true;
    tm_config.task_history_size = 1000;
    
    g_task_manager_adapter->task_manager = pb_taskmgr_create(&tm_config);
    if (!g_task_manager_adapter->task_manager) {
        free(g_task_manager_adapter);
        return ENGINE_ERROR_MODULE_INIT_FAILED;
    }
    
    return ENGINE_SUCCESS;
}

void task_manager_adapter_cleanup(void)
{
    if (g_task_manager_adapter) {
        if (g_task_manager_adapter->task_manager) {
            pb_taskmgr_destroy(g_task_manager_adapter->task_manager);
        }
        DeleteCriticalSection(&g_task_manager_adapter->lock);
        free(g_task_manager_adapter);
        g_task_manager_adapter = NULL;
    }
}

int task_manager_adapter_submit_task(const EngineTask* task)
{
    if (!g_task_manager_adapter || !task) {
        return ENGINE_ERROR_INVALID_PARAM;
    }
    
    EnterCriticalSection(&g_task_manager_adapter->lock);
    
    // 将引擎任务转换为底层任务
    PB_Task pb_task;
    memset(&pb_task, 0, sizeof(pb_task));
    
    // 复制任务ID
    strncpy(pb_task.task_id, task->task_id, sizeof(pb_task.task_id) - 1);
    
    // 设置任务类型（映射）
    switch (task->type) {
        case TASK_TYPE_FILE_COPY:
            pb_task.task_type = PB_TASK_TYPE_FILE_COPY;
            break;
        case TASK_TYPE_NETWORK_UPLOAD:
            pb_task.task_type = PB_TASK_TYPE_NETWORK_UPLOAD;
            break;
        case TASK_TYPE_NETWORK_DOWNLOAD:
            pb_task.task_type = PB_TASK_TYPE_NETWORK_DOWNLOAD;
            break;
        default:
            pb_task.task_type = PB_TASK_TYPE_CUSTOM;
            break;
    }
    
    // 设置优先级
    switch (task->priority) {
        case TASK_PRIORITY_LOW:
            pb_task.priority = PB_TASK_PRIORITY_LOW;
            break;
        case TASK_PRIORITY_NORMAL:
            pb_task.priority = PB_TASK_PRIORITY_NORMAL;
            break;
        case TASK_PRIORITY_HIGH:
            pb_task.priority = PB_TASK_PRIORITY_HIGH;
            break;
        case TASK_PRIORITY_CRITICAL:
            pb_task.priority = PB_TASK_PRIORITY_CRITICAL;
            break;
    }
    
    // 设置参数
    pb_task.retry_count = task->retry_count;
    pb_task.timeout_ms = task->timeout_ms;
    
    // 提交任务
    int result = pb_taskmgr_submit(g_task_manager_adapter->task_manager, &pb_task);
    
    LeaveCriticalSection(&g_task_manager_adapter->lock);
    
    if (result != 0) {
        return ENGINE_ERROR_TASK_SUBMIT_FAILED;
    }
    
    return ENGINE_SUCCESS;
}