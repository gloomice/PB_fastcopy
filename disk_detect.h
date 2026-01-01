#ifndef DISK_DETECT_H
#define DISK_DETECT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 磁盘类型
typedef enum {
    DISK_TYPE_UNKNOWN = 0,
    DISK_TYPE_HDD = 1,     // 机械硬盘
    DISK_TYPE_SSD = 2,     // 固态硬盘
    DISK_TYPE_NVME = 3,     // NVMe SSD
    DISK_TYPE_HYBRID = 4,   // 混合硬盘
    DISK_TYPE_RAMDISK = 5    // 内存盘
} DiskType;

// 磁盘性能特征
typedef struct {
    DiskType type;
    uint32_t max_concurrent_ops;      // 最大并发I/O数
    uint32_t optimal_batch_size;       // 最优批次大小
    uint32_t optimal_queue_depth;      // 最优队列深度
    uint64_t sequential_read_speed;    // 顺序读速度 (MB/s)
    uint64_t sequential_write_speed;   // 顺序写速度 (MB/s)
    uint64_t random_read_speed;       // 随机读速度 (MB/s)
    uint64_t random_write_speed;      // 随机写速度 (MB/s)
    uint32_t rotation_speed;          // 转速 (RPM, 仅HDD)
    int write_cache_enabled;          // 写缓存是否启用
    int trim_support;                // TRIM支持 (SSD)
    char model[256];                 // 磁盘型号
    char serial[256];                // 序列号
    uint64_t total_capacity;         // 总容量
} DiskInfo;

// 自适应统计
typedef struct {
    uint64_t operation_count;         // 操作次数
    uint64_t total_bytes;           // 总字节数
    uint64_t total_latency_ns;      // 总延迟
    uint64_t total_errors;          // 总错误数
    
    // 移动窗口统计
    double avg_latency_ns;          // 平均延迟
    double p50_latency_ns;         // P50延迟
    double p95_latency_ns;         // P95延迟
    double p99_latency_ns;         // P99延迟
    double throughput_mbps;         // 吞吐量
    
    // 自适应参数
    uint32_t current_batch_size;     // 当前批次大小
    uint32_t optimal_batch_size;    // 最优批次大小
    uint32_t queue_depth;           // 当前队列深度
    uint32_t optimal_queue_depth;    // 最优队列深度
    
    // 性能趋势
    double performance_trend;        // 性能趋势 (-1到1)
    int last_direction;             // 最后调整方向
    uint64_t last_adjust_time;      // 最后调整时间
} AdaptiveStats;

// 检测磁盘类型
DiskType detect_disk_type(const char* path);

// 获取磁盘详细信息
int get_disk_info(const char* path, DiskInfo* info);

// 运行性能测试
int run_disk_benchmark(const char* path, DiskInfo* info);

// 初始化自适应统计
AdaptiveStats* adaptive_stats_init(const DiskInfo* disk_info);

// 更新自适应统计
void adaptive_stats_update(AdaptiveStats* stats, uint64_t bytes, uint64_t latency_ns);

// 获取最优批次大小（基于自适应统计）
uint32_t get_adaptive_batch_size(AdaptiveStats* stats);

// 获取最优队列深度
uint32_t get_adaptive_queue_depth(AdaptiveStats* stats);

// 调整参数（基于性能趋势）
void adaptive_adjust(AdaptiveStats* stats);

// 重置自适应统计
void adaptive_stats_reset(AdaptiveStats* stats);

// 销毁自适应统计
void adaptive_stats_destroy(AdaptiveStats* stats);

// 打印磁盘信息
void print_disk_info(const DiskInfo* info);

// 打印自适应统计
void print_adaptive_stats(const AdaptiveStats* stats);

#ifdef __cplusplus
}
#endif

#endif // DISK_DETECT_H
