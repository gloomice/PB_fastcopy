#ifndef PIPELINE_H
#define PIPELINE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 无锁环形队列（生产者-消费者）
typedef struct {
    void** buffer;           // 缓冲区
    size_t capacity;         // 容量
    size_t mask;             // 掩码（容量-1，必须为2的幂）
    volatile size_t head;    // 生产者索引
    volatile size_t tail;    // 消费者索引
    pthread_mutex_t mutex;   // 备用锁（用于非无锁场景）
} RingBuffer;

// 原子计数器
typedef struct {
    volatile uint64_t value;
    pthread_spinlock_t lock;
} AtomicCounter;

// 流水线阶段
typedef enum {
    STAGE_SCAN = 0,      // 扫描阶段
    STAGE_METADATA = 1,  // 元数据处理
    STAGE_COPY = 2,      // 复制阶段
    STAGE_VERIFY = 3     // 校验阶段
} PipelineStage;

// 流水线任务
typedef struct {
    PipelineStage stage;   // 任务阶段
    FileEntry* file;      // 文件条目
    void* data;           // 数据指针
    size_t size;          // 数据大小
    uint32_t checksum;    // 校验和
    int error;            // 错误码
    struct PipelineTask* next; // 链表指针
} PipelineTask;

// 流水线统计
typedef struct {
    uint64_t enqueued[4];        // 各阶段入队数量
    uint64_t dequeued[4];        // 各阶段出队数量
    uint64_t processed[4];        // 各阶段处理数量
    uint64_t errors[4];          // 各阶段错误数量
    uint64_t total_latency_ns;   // 总延迟
    uint64_t max_latency_ns;     // 最大延迟
    uint64_t min_latency_ns;     // 最小延迟
} PipelineStats;

// 流水线引擎
typedef struct {
    RingBuffer* scan_queue;       // 扫描队列（无锁，容量100K）
    RingBuffer* metadata_queue;  // 元数据队列
    RingBuffer* copy_queue;      // 复制队列
    RingBuffer* verify_queue;    // 校验队列
    
    AtomicCounter* stage_counters[4]; // 各阶段计数器
    
    pthread_t worker_threads[4][8]; // 四个阶段，每个最多8个工作线程
    uint32_t thread_counts[4];       // 各阶段线程数
    
    int running;                  // 运行标志
    PipelineStats stats;          // 统计信息
    pthread_mutex_t stats_mutex;  // 统计信息锁
    
    void* user_context;         // 用户上下文
} PipelineEngine;

// 流水线回调函数类型
typedef int (*ScanCallback)(const char* path, FileEntry* entry, void* context);
typedef int (*MetadataCallback)(FileEntry* entry, void* context);
typedef int (*CopyCallback)(FileEntry* entry, const void* data, void* context);
typedef int (*VerifyCallback)(FileEntry* entry, uint32_t checksum, void* context);

// 初始化环形缓冲区
RingBuffer* ring_buffer_create(size_t capacity);

// 销毁环形缓冲区
void ring_buffer_destroy(RingBuffer* rb);

// 无锁入队（生产者）
int ring_buffer_enqueue(RingBuffer* rb, void* item);

// 无锁出队（消费者）
int ring_buffer_dequeue(RingBuffer* rb, void** item);

// 批量入队
int ring_buffer_enqueue_batch(RingBuffer* rb, void** items, size_t count);

// 批量出队
int ring_buffer_dequeue_batch(RingBuffer* rb, void** items, size_t max_count);

// 获取队列大小
size_t ring_buffer_size(RingBuffer* rb);

// 初始化原子计数器
void atomic_counter_init(AtomicCounter* counter, uint64_t value);

// 增加计数器
uint64_t atomic_counter_add(AtomicCounter* counter, int64_t delta);

// 获取计数器值
uint64_t atomic_counter_get(AtomicCounter* counter);

// 初始化流水线引擎
PipelineEngine* pipeline_engine_create(
    size_t queue_capacity,
    const uint32_t thread_counts[4],
    void* user_context
);

// 启动流水线
int pipeline_engine_start(PipelineEngine* engine);

// 停止流水线
void pipeline_engine_stop(PipelineEngine* engine);

// 销毁流水线引擎
void pipeline_engine_destroy(PipelineEngine* engine);

// 提交任务到流水线
int pipeline_submit_task(PipelineEngine* engine, PipelineTask* task);

// 获取流水线统计信息
void pipeline_get_stats(PipelineEngine* engine, PipelineStats* stats);

// 重置统计信息
void pipeline_reset_stats(PipelineEngine* engine);

#ifdef __cplusplus
}
#endif

#endif // PIPELINE_H
