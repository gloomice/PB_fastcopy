#ifndef CHECKPOINT_H
#define CHECKPOINT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 文件位置（用于大文件断点）
typedef struct {
    uint64_t file_id;         // 文件ID
    uint64_t position;        // 当前位置
    uint32_t checksum;        // 已传输数据的CRC32
    int completed;            // 是否完成
} FilePosition;

// 断点续传检查点
typedef struct {
    uint64_t checkpoint_id;    // 检查点ID
    uint64_t last_file_id;     // 最后处理的文件ID
    uint64_t processed_count;   // 已处理文件数
    uint64_t processed_bytes;   // 已处理字节数
    uint64_t total_files;       // 总文件数
    uint64_t total_bytes;       // 总字节数
    uint8_t checksum[32];       // SHA-256校验和
    uint64_t create_time;       // 创建时间
    uint64_t update_time;       // 更新时间
    
    FilePosition* positions;     // 大文件的断点位置
    uint32_t position_count;    // 断点位置数量
    uint32_t position_capacity; // 断点位置容量
    
    char source_path[512];     // 源路径
    char dest_path[512];       // 目标路径
} Checkpoint;

// 检查点管理器
typedef struct {
    Checkpoint* current_checkpoint;
    char checkpoint_dir[512];  // 检查点目录
    uint32_t save_interval;    // 保存间隔（文件数）
    uint64_t last_save_count;  // 上次保存时的文件数
    int auto_save;             // 自动保存标志
    pthread_mutex_t mutex;     // 互斥锁
} CheckpointManager;

// 重试策略
typedef enum {
    RETRY_IMMEDIATE = 0,     // 立即重试
    RETRY_DELAYED,           // 延迟重试
    RETRY_EXPONENTIAL,       // 指数退避
    RETRY_SKIP               // 跳过
} RetryStrategy;

// 重试配置
typedef struct {
    RetryStrategy strategy;    // 重试策略
    uint32_t max_attempts;   // 最大重试次数
    uint32_t initial_delay_ms; // 初始延迟（毫秒）
    uint32_t max_delay_ms;   // 最大延迟（毫秒）
    double backoff_factor;   // 退避因子
    int skip_on_failure;     // 失败时是否跳过
} RetryConfig;

// 错误恢复状态
typedef struct {
    uint64_t error_count;     // 错误计数
    uint64_t retry_count;    // 重试计数
    uint64_t skip_count;     // 跳过计数
    char last_error[512];    // 最后错误信息
} RecoveryStats;

// ============ 检查点管理 ============

// 初始化检查点管理器
CheckpointManager* checkpoint_manager_init(const char* checkpoint_dir, uint32_t save_interval);

// 销毁检查点管理器
void checkpoint_manager_destroy(CheckpointManager* manager);

// 创建新的检查点
Checkpoint* checkpoint_create(CheckpointManager* manager, const char* source_path, 
                             const char* dest_path, uint64_t total_files, uint64_t total_bytes);

// 加载检查点
Checkpoint* checkpoint_load(CheckpointManager* manager, uint64_t checkpoint_id);

// 保存检查点
int checkpoint_save(CheckpointManager* manager, Checkpoint* checkpoint);

// 更新检查点（更新处理进度）
int checkpoint_update(CheckpointManager* manager, Checkpoint* checkpoint, 
                     uint64_t file_id, uint64_t processed_bytes);

// 添加文件断点位置
int checkpoint_add_position(Checkpoint* checkpoint, FilePosition* position);

// 获取文件断点位置
FilePosition* checkpoint_get_position(Checkpoint* checkpoint, uint64_t file_id);

// 完成文件处理
int checkpoint_complete_file(Checkpoint* checkpoint, uint64_t file_id);

// 删除检查点
int checkpoint_delete(CheckpointManager* manager, uint64_t checkpoint_id);

// 列出所有检查点
Checkpoint** checkpoint_list(CheckpointManager* manager, uint32_t* count);

// 释放检查点列表
void checkpoint_free_list(Checkpoint** checkpoints, uint32_t count);

// 计算检查点校验和
void checkpoint_calculate_checksum(Checkpoint* checkpoint);

// 验证检查点完整性
int checkpoint_verify(Checkpoint* checkpoint);

// ============ 错误恢复 ============

// 执行重试（根据策略）
int retry_operation(RetryConfig* config, RecoveryStats* stats, 
                   int (*operation)(void*), void* arg);

// 等待重试（根据策略）
void retry_wait(RetryConfig* config, uint32_t attempt);

// 获取重试延迟
uint32_t get_retry_delay(RetryConfig* config, uint32_t attempt);

// 重置重试统计
void reset_recovery_stats(RecoveryStats* stats);

// 记录错误
void log_error(RecoveryStats* stats, const char* error_msg);

// ============ 断点续传 ============

// 从检查点恢复
int resume_from_checkpoint(CheckpointManager* manager, Checkpoint* checkpoint,
                          int (*process_file)(FilePosition*, void*), void* context);

// 验证已传输的数据
int verify_transferred_data(Checkpoint* checkpoint, const void* data, size_t size);

// 修复损坏的检查点
int repair_checkpoint(Checkpoint* checkpoint);

// 清理旧的检查点
int cleanup_old_checkpoints(CheckpointManager* manager, uint64_t keep_count);

#ifdef __cplusplus
}
#endif

#endif // CHECKPOINT_H
