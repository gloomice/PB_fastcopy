#include "work_steal.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sched.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <malloc.h>
#define aligned_alloc(alignment, size) _aligned_malloc(size, alignment)
#define aligned_free _aligned_free
#else
#include <stdlib.h>
#define aligned_free free
#endif

#define DEFAULT_QUEUE_CAPACITY 4096
#define CACHE_LINE_SIZE 64
#define MAX_IDLE_SPINS 1000
#define STEAL_THRESHOLD 2  // 队列大于2个任务时才可被窃取

// ============ 双端队列实现（无锁）============

Deque* deque_create(size_t capacity) {
    // 容量必须是2的幂
    size_t real_capacity = 1;
    while (real_capacity < capacity) {
        real_capacity <<= 1;
    }
    
    Deque* deque = (Deque*)aligned_alloc(CACHE_LINE_SIZE, sizeof(Deque));
    if (!deque) return NULL;
    
    // 对齐缓冲区到缓存行
    deque->buffer = (void**)aligned_alloc(CACHE_LINE_SIZE, real_capacity * sizeof(void*));
    if (!deque->buffer) {
        free(deque);
        return NULL;
    }
    
    deque->capacity = real_capacity;
    deque->mask = real_capacity - 1;
    deque->top = 0;
    deque->bottom = 0;
    
    pthread_mutex_init(&deque->mutex, NULL);
    
    return deque;
}

void deque_destroy(Deque* deque) {
    if (!deque) return;
    
    if (deque->buffer) {
        free(deque->buffer);
    }
    
    pthread_mutex_destroy(&deque->mutex);
    free(deque);
}

// 本地push（所有者线程调用，无锁）
int deque_push(Deque* deque, void* item) {
    if (!deque || !item) return -1;
    
    size_t bottom = deque->bottom;
    size_t top = deque->top;
    
    // 检查是否需要扩容
    if (bottom - top >= deque->capacity - 1) {
        return -2;  // 队列满
    }
    
    deque->buffer[bottom & deque->mask] = item;
    
    // 内存屏障，确保写入完成
    __sync_synchronize();
    
    deque->bottom = bottom + 1;
    
    return 0;
}

// 本地pop（所有者线程调用，无锁）
int deque_pop(Deque* deque, void** item) {
    if (!deque || !item) return -1;
    
    size_t bottom = deque->bottom;
    
    if (bottom == deque->top) {
        return -2;  // 队列空
    }
    
    bottom--;
    deque->bottom = bottom;
    
    // 内存屏障，确保bottom更新完成
    __sync_synchronize();
    
    size_t top = deque->top;
    
    if (bottom < top) {
        // 有其他线程正在窃取，恢复
        deque->bottom = bottom + 1;
        return -2;  // 队列空
    }
    
    *item = deque->buffer[bottom & deque->mask];
    
    if (bottom > top) {
        return 0;  // 成功
    }
    
    // bottom == top，可能有并发窃取
    // 使用CAS操作确认
    int expected_top = (int)top;
    if (__sync_bool_compare_and_swap((int*)&deque->top, expected_top, expected_top + 1)) {
        deque->bottom = bottom + 1;
        return 0;
    } else {
        deque->bottom = bottom + 1;
        return -2;
    }
}

// 窃取pop（其他线程调用，无锁）
int deque_steal(Deque* deque, void** item) {
    if (!deque || !item) return -1;
    
    // 内存屏障，确保读取最新的top和bottom
    __sync_synchronize();
    
    size_t top = deque->top;
    size_t bottom = deque->bottom;
    
    if (top >= bottom) {
        return -2;  // 队列空
    }
    
    *item = deque->buffer[top & deque->mask];
    
    // 使用CAS操作更新top
    int expected_top = (int)top;
    if (__sync_bool_compare_and_swap((int*)&deque->top, expected_top, expected_top + 1)) {
        return 0;  // 成功窃取
    } else {
        return -2;  // 失败，有其他线程也在窃取
    }
}

size_t deque_size(Deque* deque) {
    if (!deque) return 0;
    
    size_t top = deque->top;
    size_t bottom = deque->bottom;
    
    if (bottom >= top) {
        return bottom - top;
    } else {
        return 0;
    }
}

int deque_is_empty(Deque* deque) {
    if (!deque) return 1;
    return deque->top == deque->bottom;
}

// ============ 工作窃取线程池实现 ============

// 工作线程主函数
static void* worker_thread_func(void* arg) {
    WorkerThread* worker = (WorkerThread*)arg;
    WorkStealingPool* pool = worker->pool;
    
    uint64_t idle_start = 0;
    int idle_spins = 0;
    
    while (worker->running) {
        Task* task = NULL;
        
        // 1. 尝试从本地队列获取任务
        void* item;
        if (deque_pop(worker->local_queue, &item) == 0) {
            task = (Task*)item;
            goto execute_task;
        }
        
        // 2. 本地队列空，尝试从全局队列获取
        pthread_mutex_lock(&pool->global_queue_mutex);
        if (pool->global_task_queue) {
            task = pool->global_task_queue;
            pool->global_task_queue = task->next;
            pthread_mutex_unlock(&pool->global_queue_mutex);
            
            if (deque_push(worker->local_queue, task) == 0) {
                // 加入本地队列后重新取出执行
                deque_pop(worker->local_queue, (void**)&task);
                goto execute_task;
            }
        } else {
            pthread_mutex_unlock(&pool->global_queue_mutex);
        }
        
        // 3. 尝试从其他线程窃取任务
        uint32_t steal_attempts = 0;
        for (uint32_t i = 0; i < pool->num_workers; i++) {
            uint32_t victim_id = (worker->thread_id + i) % pool->num_workers;
            
            if (victim_id == worker->thread_id) continue;
            
            Deque* victim_queue = pool->workers[victim_id].local_queue;
            
            // 只有当对方队列有足够任务时才窃取
            if (deque_size(victim_queue) > STEAL_THRESHOLD) {
                if (deque_steal(victim_queue, &item) == 0) {
                    task = (Task*)item;
                    
                    // 记录窃取
                    worker->tasks_stolen++;
                    pool->workers[victim_id].tasks_stolen_from++;
                    pool->stolen_tasks++;
                    
                    goto execute_task;
                } else {
                    pool->failed_steals++;
                }
            }
            
            steal_attempts++;
        }
        
        // 4. 无任务可执行，记录空闲时间
        if (idle_spins == 0) {
            idle_start = get_timestamp();
        }
        idle_spins++;
        
        if (idle_spins < MAX_IDLE_SPINS) {
            // 短暂自旋
            for (int i = 0; i < 100; i++) {
                __asm__ volatile("pause");
            }
        } else if (idle_spins < MAX_IDLE_SPINS * 2) {
            // 让出CPU
#ifdef _WIN32
            SwitchToThread();
#else
            sched_yield();
#endif
        } else {
            // 休眠1毫秒
#ifdef _WIN32
            Sleep(1);
#else
            struct timespec ts;
            ts.tv_sec = 0;
            ts.tv_nsec = 1000000;
            nanosleep(&ts, NULL);
#endif
        }
        
        // 检查是否有新任务
        pthread_mutex_lock(&pool->global_queue_mutex);
        int has_global_task = (pool->global_task_queue != NULL);
        pthread_mutex_unlock(&pool->global_queue_mutex);
        
        if (!has_global_task && pool->completed_tasks >= pool->total_tasks) {
            // 所有任务完成
            break;
        }
        
        continue;
        
execute_task:
        // 执行任务
        idle_spins = 0;
        if (idle_start > 0) {
            worker->idle_time_ns += get_timestamp() - idle_start;
            idle_start = 0;
        }
        
        worker->tasks_executed++;
        task->func(task->arg);
        
        // 释放任务
        free(task);
        
        pthread_mutex_lock(&pool->stats_mutex);
        pool->completed_tasks++;
        pthread_mutex_unlock(&pool->stats_mutex);
    }
    
    return NULL;
}

WorkStealingPool* work_stealing_pool_create(uint32_t num_workers, size_t queue_capacity) {
    if (num_workers == 0) {
        num_workers = 4;  // 默认4个工作线程
    }
    
    if (queue_capacity == 0) {
        queue_capacity = DEFAULT_QUEUE_CAPACITY;
    }
    
    WorkStealingPool* pool = (WorkStealingPool*)calloc(1, sizeof(WorkStealingPool));
    if (!pool) return NULL;
    
    pool->num_workers = num_workers;
    pool->workers = (WorkerThread*)calloc(num_workers, sizeof(WorkerThread));
    if (!pool->workers) {
        free(pool);
        return NULL;
    }
    
    // 为每个工作线程创建本地队列
    for (uint32_t i = 0; i < num_workers; i++) {
        pool->workers[i].thread_id = i;
        pool->workers[i].local_queue = deque_create(queue_capacity);
        pool->workers[i].tasks_executed = 0;
        pool->workers[i].tasks_stolen = 0;
        pool->workers[i].tasks_stolen_from = 0;
        pool->workers[i].idle_time_ns = 0;
        pool->workers[i].running = 0;
        
        if (!pool->workers[i].local_queue) {
            work_stealing_pool_destroy(pool);
            return NULL;
        }
    }
    
    pthread_mutex_init(&pool->global_queue_mutex, NULL);
    pthread_cond_init(&pool->global_queue_cond, NULL);
    pthread_mutex_init(&pool->stats_mutex, NULL);
    
    return pool;
}

void work_stealing_pool_destroy(WorkStealingPool* pool) {
    if (!pool) return;
    
    // 停止线程池
    work_stealing_pool_stop(pool);
    
    // 释放工作线程
    for (uint32_t i = 0; i < pool->num_workers; i++) {
        if (pool->workers[i].local_queue) {
            deque_destroy(pool->workers[i].local_queue);
        }
    }
    
    free(pool->workers);
    
    pthread_mutex_destroy(&pool->global_queue_mutex);
    pthread_cond_destroy(&pool->global_queue_cond);
    pthread_mutex_destroy(&pool->stats_mutex);
    
    free(pool);
}

int work_stealing_pool_start(WorkStealingPool* pool) {
    if (!pool) return -1;
    
    pool->running = 1;
    
    // 启动所有工作线程
    for (uint32_t i = 0; i < pool->num_workers; i++) {
        pool->workers[i].running = 1;
        pool->workers[i].pool = pool;
        
        if (pthread_create(&pool->workers[i].thread, NULL, 
                          worker_thread_func, &pool->workers[i]) != 0) {
            work_stealing_pool_stop(pool);
            return -1;
        }
    }
    
    return 0;
}

void work_stealing_pool_stop(WorkStealingPool* pool) {
    if (!pool) return;
    
    pool->running = 0;
    
    // 停止所有工作线程
    for (uint32_t i = 0; i < pool->num_workers; i++) {
        pool->workers[i].running = 0;
    }
    
    // 等待所有线程结束
    for (uint32_t i = 0; i < pool->num_workers; i++) {
        pthread_join(pool->workers[i].thread, NULL);
    }
}

int work_stealing_submit_local(WorkStealingPool* pool, uint32_t worker_id, Task* task) {
    if (!pool || !task) return -1;
    
    if (worker_id >= pool->num_workers) {
        return -2;
    }
    
    // 提交到指定线程的本地队列
    if (deque_push(pool->workers[worker_id].local_queue, task) != 0) {
        return -3;
    }
    
    pthread_mutex_lock(&pool->stats_mutex);
    pool->total_tasks++;
    pthread_mutex_unlock(&pool->stats_mutex);
    
    return 0;
}

int work_stealing_submit_global(WorkStealingPool* pool, Task* task) {
    if (!pool || !task) return -1;
    
    // 提交到全局队列
    pthread_mutex_lock(&pool->global_queue_mutex);
    
    task->next = pool->global_task_queue;
    pool->global_task_queue = task;
    
    pthread_mutex_unlock(&pool->global_queue_mutex);
    
    // 通知一个线程
    pthread_cond_signal(&pool->global_queue_cond);
    
    pthread_mutex_lock(&pool->stats_mutex);
    pool->total_tasks++;
    pthread_mutex_unlock(&pool->stats_mutex);
    
    return 0;
}

int work_stealing_wait_all(WorkStealingPool* pool) {
    if (!pool) return -1;
    
    while (1) {
        pthread_mutex_lock(&pool->stats_mutex);
        int all_done = (pool->completed_tasks >= pool->total_tasks);
        pthread_mutex_unlock(&pool->stats_mutex);
        
        if (all_done) break;
        
#ifdef _WIN32
        Sleep(10);
#else
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = 10000000;  // 10ms
        nanosleep(&ts, NULL);
#endif
    }
    
    return 0;
}

void work_stealing_get_stats(WorkStealingPool* pool, char* buffer, size_t buffer_size) {
    if (!pool || !buffer) return;
    
    pthread_mutex_lock(&pool->stats_mutex);
    
    uint64_t total_executed = 0;
    uint64_t total_stolen = 0;
    uint64_t total_stolen_from = 0;
    uint64_t total_idle = 0;
    
    for (uint32_t i = 0; i < pool->num_workers; i++) {
        total_executed += pool->workers[i].tasks_executed;
        total_stolen += pool->workers[i].tasks_stolen;
        total_stolen_from += pool->workers[i].tasks_stolen_from;
        total_idle += pool->workers[i].idle_time_ns;
    }
    
    snprintf(buffer, buffer_size,
        "Work Stealing Pool Statistics:\n"
        "  Total Workers: %u\n"
        "  Total Tasks: %llu\n"
        "  Completed Tasks: %llu\n"
        "  Stolen Tasks: %llu\n"
        "  Failed Steals: %llu\n"
        "\nWorker Details:\n"
        "  Total Executed: %llu\n"
        "  Total Stolen: %llu\n"
        "  Total Stolen From: %llu\n"
        "  Total Idle Time: %.2f seconds\n",
        pool->num_workers,
        (unsigned long long)pool->total_tasks,
        (unsigned long long)pool->completed_tasks,
        (unsigned long long)pool->stolen_tasks,
        (unsigned long long)pool->failed_steals,
        (unsigned long long)total_executed,
        (unsigned long long)total_stolen,
        (unsigned long long)total_stolen_from,
        total_idle / 1e9
    );
    
    pthread_mutex_unlock(&pool->stats_mutex);
}

void work_stealing_reset_stats(WorkStealingPool* pool) {
    if (!pool) return;
    
    pthread_mutex_lock(&pool->stats_mutex);
    
    pool->total_tasks = 0;
    pool->completed_tasks = 0;
    pool->stolen_tasks = 0;
    pool->failed_steals = 0;
    
    for (uint32_t i = 0; i < pool->num_workers; i++) {
        pool->workers[i].tasks_executed = 0;
        pool->workers[i].tasks_stolen = 0;
        pool->workers[i].tasks_stolen_from = 0;
        pool->workers[i].idle_time_ns = 0;
    }
    
    pthread_mutex_unlock(&pool->stats_mutex);
}
