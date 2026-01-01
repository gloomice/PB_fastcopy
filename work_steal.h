#ifndef WORK_STEAL_H
#define WORK_STEAL_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

// 工作窃取双端队列（无锁）
typedef struct {
    void** buffer;              // 缓冲区
    size_t capacity;            // 容量
    size_t mask;                // 掩码（容量-1）
    volatile size_t top;        // 顶部索引（用于窃取）
    volatile size_t bottom;     // 底部索引（用于本地push/pop）
    pthread_mutex_t mutex;      // 备用锁
} Deque;

// 工作任务
typedef struct {
    void (*func)(void* arg);    // 任务函数
    void* arg;                  // 参数
    struct Task* next;          // 下一个任务（用于链表）
} Task;

// 工作线程
typedef struct {
    uint32_t thread_id;         // 线程ID
    pthread_t thread;          // 线程句柄
    Deque* local_queue;        // 本地队列
    
    uint64_t tasks_executed;   // 执行任务数
    uint64_t tasks_stolen;     // 窃取任务数
    uint64_t tasks_stolen_from; // 被窃取任务数
    uint64_t idle_time_ns;     // 空闲时间
    
    int running;                // 运行标志
} WorkerThread;

// 工作窃取线程池
typedef struct {
    WorkerThread* workers;      // 工作线程数组
    uint32_t num_workers;       // 工作线程数
    
    // 全局共享任务队列（用于初始任务分配）
    Task* global_task_queue;
    pthread_mutex_t global_queue_mutex;
    pthread_cond_t global_queue_cond;
    
    // 统计信息
    uint64_t total_tasks;       // 总任务数
    uint64_t completed_tasks;   // 完成任务数
    uint64_t stolen_tasks;      // 窃取任务总数
    uint64_t failed_steals;    // 窃取失败次数
    
    int running;                // 运行标志
    pthread_mutex_t stats_mutex; // 统计锁
} WorkStealingPool;

// 初始化双端队列
Deque* deque_create(size_t capacity);

// 销毁双端队列
void deque_destroy(Deque* deque);

// 本地push（无锁，仅所有者线程可调用）
int deque_push(Deque* deque, void* item);

// 本地pop（无锁，仅所有者线程可调用）
int deque_pop(Deque* deque, void** item);

// 窃取pop（无锁，其他线程可调用）
int deque_steal(Deque* deque, void** item);

// 获取队列大小
size_t deque_size(Deque* deque);

// 检查队列是否为空
int deque_is_empty(Deque* deque);

// ============ 工作窃取线程池 ============

// 创建工作窃取线程池
WorkStealingPool* work_stealing_pool_create(uint32_t num_workers, size_t queue_capacity);

// 销毁工作窃取线程池
void work_stealing_pool_destroy(WorkStealingPool* pool);

// 启动线程池
int work_stealing_pool_start(WorkStealingPool* pool);

// 停止线程池
void work_stealing_pool_stop(WorkStealingPool* pool);

// 提交任务到指定线程的本地队列
int work_stealing_submit_local(WorkStealingPool* pool, uint32_t worker_id, Task* task);

// 提交任务到全局队列（任意线程处理）
int work_stealing_submit_global(WorkStealingPool* pool, Task* task);

// 等待所有任务完成
int work_stealing_wait_all(WorkStealingPool* pool);

// 获取统计信息
void work_stealing_get_stats(WorkStealingPool* pool, char* buffer, size_t buffer_size);

// 重置统计信息
void work_stealing_reset_stats(WorkStealingPool* pool);

#ifdef __cplusplus
}
#endif

#endif // WORK_STEAL_H
