#ifndef PB_FASTCOPY_ENGINE_H
#define PB_FASTCOPY_ENGINE_H

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include "PB_fastcopy_file_operations_v10.h"
#include "PB_fastcopy_logging_v10.h"
#include "PB_fastcopy_network_v11.h"
#include "PB_fastcopy_task_manager_v10.h"

// ============================================================================
// 错误码定义
// ============================================================================
typedef enum {
    ENGINE_SUCCESS = 0,
    ENGINE_ERROR_INIT_FAILED = -1,
    ENGINE_ERROR_MODULE_INIT_FAILED = -2,
    ENGINE_ERROR_INVALID_PARAM = -3,
    ENGINE_ERROR_TASK_SUBMIT_FAILED = -4,
    ENGINE_ERROR_RESOURCE_LIMIT = -5,
    ENGINE_ERROR_IO_FAILED = -6,
    ENGINE_ERROR_NETWORK_FAILED = -7,
    ENGINE_ERROR_INVALID_STATE = -8,
    ENGINE_ERROR_TIMEOUT = -9,
    ENGINE_ERROR_MEMORY_ALLOC = -10,
    ENGINE_ERROR_INTERNAL = -100
} EngineErrorCode;

// ============================================================================
// 引擎状态枚举
// ============================================================================
typedef enum {
    ENGINE_STATE_UNINITIALIZED = 0,
    ENGINE_STATE_INITIALIZED,
    ENGINE_STATE_RUNNING,
    ENGINE_STATE_PAUSED,
    ENGINE_STATE_STOPPING,
    ENGINE_STATE_STOPPED,
    ENGINE_STATE_ERROR
} EngineState;

// ============================================================================
// 任务类型枚举
// ============================================================================
typedef enum {
    TASK_TYPE_FILE_COPY = 0,
    TASK_TYPE_FILE_MOVE,
    TASK_TYPE_FILE_DELETE,
    TASK_TYPE_FILE_SYNC,
    TASK_TYPE_NETWORK_UPLOAD,
    TASK_TYPE_NETWORK_DOWNLOAD,
    TASK_TYPE_BATCH_OPERATION
} TaskType;

// ============================================================================
// 任务优先级枚举
// ============================================================================
typedef enum {
    TASK_PRIORITY_LOW = 0,
    TASK_PRIORITY_NORMAL,
    TASK_PRIORITY_HIGH,
    TASK_PRIORITY_CRITICAL
} TaskPriority;

// ============================================================================
// 回调函数类型定义
// ============================================================================
typedef void (*EngineProgressCallback)(
    const char* task_id,
    uint64_t bytes_processed,
    uint64_t bytes_total,
    float progress_percent,
    void* user_data
);

typedef void (*EngineStatusCallback)(
    EngineState state,
    const char* status_message,
    void* user_data
);

typedef void (*EngineErrorCallback)(
    const char* task_id,
    int error_code,
    const char* error_message,
    void* user_data
);

// ============================================================================
// 引擎配置结构
// ============================================================================
typedef struct {
    // 通用配置
    uint32_t max_concurrent_tasks;
    uint64_t memory_limit_mb;
    uint32_t io_thread_count;
    uint32_t network_thread_count;
    
    // 性能优化配置
    bool enable_direct_io;
    bool enable_write_through;
    uint32_t buffer_size_kb;
    uint32_t batch_size;
    
    // 路径配置
    char work_directory[MAX_PATH];
    char temp_directory[MAX_PATH];
    
    // 网络配置
    uint32_t max_network_connections;
    uint32_t network_timeout_ms;
    uint32_t network_retry_count;
    
    // 回调函数配置
    EngineProgressCallback progress_callback;
    EngineStatusCallback status_callback;
    EngineErrorCallback error_callback;
    void* callback_user_data;
} EngineConfig;

// ============================================================================
// 任务描述结构
// ============================================================================
typedef struct {
    char task_id[64];
    TaskType type;
    TaskPriority priority;
    
    // 源和目标
    union {
        struct {
            char source_path[MAX_PATH * 4];  // 支持通配符
            char destination_path[MAX_PATH];
        } file_op;
        
        struct {
            char local_path[MAX_PATH];
            char remote_url[1024];
        } network_op;
        
        struct {
            char source_pattern[1024];
            char destination_base[MAX_PATH];
        } batch_op;
    } params;
    
    // 任务参数
    uint32_t retry_count;
    uint32_t timeout_ms;
    bool verify_after_completion;
    bool preserve_attributes;
    
    // 内部使用
    void* internal_data;
} EngineTask;

// ============================================================================
// 引擎统计信息
// ============================================================================
typedef struct {
    // 时间统计
    uint64_t start_time;
    uint64_t running_time_ms;
    
    // 任务统计
    uint64_t total_tasks_submitted;
    uint64_t total_tasks_completed;
    uint64_t total_tasks_failed;
    uint64_t total_tasks_cancelled;
    
    // 性能统计
    uint64_t total_bytes_processed;
    uint64_t total_files_processed;
    uint64_t peak_memory_usage_mb;
    float average_speed_mbps;
    
    // 当前状态
    uint32_t active_tasks;
    uint32_t queued_tasks;
    uint32_t paused_tasks;
} EngineStatistics;

// ============================================================================
// 引擎句柄结构（前向声明）
// ============================================================================
typedef struct FastCopyEngine FastCopyEngine;

// ============================================================================
// 公共API函数
// ============================================================================

#ifdef __cplusplus
extern "C" {
#endif

// 创建和销毁引擎
FASTCOPY_ENGINE_API FastCopyEngine* engine_create(const EngineConfig* config);
FASTCOPY_ENGINE_API int engine_initialize(FastCopyEngine* engine);
FASTCOPY_ENGINE_API int engine_destroy(FastCopyEngine* engine);

// 引擎控制
FASTCOPY_ENGINE_API int engine_start(FastCopyEngine* engine);
FASTCOPY_ENGINE_API int engine_pause(FastCopyEngine* engine);
FASTCOPY_ENGINE_API int engine_resume(FastCopyEngine* engine);
FASTCOPY_ENGINE_API int engine_stop(FastCopyEngine* engine, bool graceful);

// 任务管理
FASTCOPY_ENGINE_API int engine_submit_task(FastCopyEngine* engine, const EngineTask* task);
FASTCOPY_ENGINE_API int engine_cancel_task(FastCopyEngine* engine, const char* task_id);
FASTCOPY_ENGINE_API int engine_pause_task(FastCopyEngine* engine, const char* task_id);
FASTCOPY_ENGINE_API int engine_resume_task(FastCopyEngine* engine, const char* task_id);

// 状态查询
FASTCOPY_ENGINE_API EngineState engine_get_state(FastCopyEngine* engine);
FASTCOPY_ENGINE_API int engine_get_task_status(FastCopyEngine* engine, const char* task_id, 
                                              char* status_buffer, size_t buffer_size);
FASTCOPY_ENGINE_API int engine_get_statistics(FastCopyEngine* engine, EngineStatistics* stats);

// 配置管理
FASTCOPY_ENGINE_API int engine_reconfigure(FastCopyEngine* engine, const EngineConfig* new_config);
FASTCOPY_ENGINE_API int engine_save_config(FastCopyEngine* engine, const char* config_file);
FASTCOPY_ENGINE_API int engine_load_config(FastCopyEngine* engine, const char* config_file);

// 工具函数
FASTCOPY_ENGINE_API const char* engine_get_error_message(int error_code);
FASTCOPY_ENGINE_API uint64_t engine_get_version(void);

#ifdef __cplusplus
}
#endif

#endif // PB_FASTCOPY_ENGINE_H