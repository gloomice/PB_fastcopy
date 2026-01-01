#ifndef STREAMING_SCAN_H
#define STREAMING_SCAN_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

// 流式扫描配置
typedef struct {
    size_t queue_capacity;           // 队列容量
    size_t batch_size;               // 批次大小
    uint32_t backpressure_threshold;  // 背压阈值（队列占用百分比）
    uint32_t scan_threads;           // 扫描线程数
    int enable_streaming;             // 启用流式扫描
    int real_time_progress;          // 实时进度报告
} StreamingScanConfig;

// 文件扫描批次
typedef struct {
    uint64_t* file_ids;             // 文件ID数组
    char** paths;                    // 路径数组
    uint64_t* sizes;                // 大小数组
    uint32_t count;                 // 批次文件数
    uint32_t capacity;              // 容量
} FileScanBatch;

// 流式扫描器
typedef struct {
    StreamingScanConfig config;
    
    // 流式队列
    FileScanBatch** batch_queue;     // 批次队列
    size_t queue_head;              // 队列头
    size_t queue_tail;              // 队列尾
    size_t queue_count;             // 当前队列中的批次数
    
    // 当前批次
    FileScanBatch* current_batch;
    
    // 扫描线程
    pthread_t* scan_threads;
    int running;
    
    // 背压控制
    int backpressure_active;         // 背压激活标志
    pthread_cond_t backpressure_cond; // 背压条件变量
    pthread_mutex_t queue_mutex;      // 队列互斥锁
    
    // 统计信息
    uint64_t total_files;            // 总文件数
    uint64_t scanned_files;          // 已扫描文件数
    uint64_t processed_files;        // 已处理文件数
    uint64_t total_size;            // 总大小
    
    // 回调函数
    void (*progress_callback)(uint64_t scanned, uint64_t total, void* context);
    void* user_context;
    
    pthread_mutex_t stats_mutex;
} StreamingScanner;

// 创建流式扫描器
StreamingScanner* streaming_scanner_create(const StreamingScanConfig* config);

// 销毁流式扫描器
void streaming_scanner_destroy(StreamingScanner* scanner);

// 启动流式扫描
int streaming_scan_start(StreamingScanner* scanner, const char* directory);

// 停止流式扫描
void streaming_scan_stop(StreamingScanner* scanner);

// 获取下一个批次（阻塞，直到有数据或扫描完成）
FileScanBatch* streaming_scan_next_batch(StreamingScanner* scanner);

// 释放批次
void streaming_scan_release_batch(StreamingScanner* scanner, FileScanBatch* batch);

// 检查背压状态
int streaming_scan_backpressure(StreamingScanner* scanner);

// 等待背压解除
void streaming_scan_wait_backpressure(StreamingScanner* scanner);

// 获取扫描进度
void streaming_scan_get_progress(StreamingScanner* scanner, 
                                uint64_t* scanned, uint64_t* total);

// 获取统计信息
void streaming_scan_get_stats(StreamingScanner* scanner, char* buffer, size_t buffer_size);

// 重置扫描器
void streaming_scan_reset(StreamingScanner* scanner);

#ifdef __cplusplus
}
#endif

#endif // STREAMING_SCAN_H
