#include "pipeline.h"
#include "async_io.h"
#include "storage.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <time.h>
#include <sched.h>

#ifdef _WIN32
#include <windows.h>
#include <malloc.h>
#define aligned_alloc(alignment, size) _aligned_malloc(size, alignment)
#define aligned_free _aligned_free
#else
#include <stdlib.h>
#define aligned_free free
#endif

#define DEFAULT_QUEUE_CAPACITY (100 * 1024)  // 100K队列容量
#define CACHE_LINE_SIZE 64

// ============ 无锁环形队列实现 ============

RingBuffer* ring_buffer_create(size_t capacity) {
    // 容量必须是2的幂
    size_t real_capacity = 1;
    while (real_capacity < capacity) {
        real_capacity <<= 1;
    }
    
    RingBuffer* rb = (RingBuffer*)aligned_alloc(CACHE_LINE_SIZE, sizeof(RingBuffer));
    if (!rb) return NULL;
    
    // 对齐缓冲区到缓存行
    rb->buffer = (void**)aligned_alloc(CACHE_LINE_SIZE, real_capacity * sizeof(void*));
    if (!rb->buffer) {
        free(rb);
        return NULL;
    }
    
    rb->capacity = real_capacity;
    rb->mask = real_capacity - 1;
    rb->head = 0;
    rb->tail = 0;
    
    pthread_mutex_init(&rb->mutex, NULL);
    
    return rb;
}

void ring_buffer_destroy(RingBuffer* rb) {
    if (!rb) return;
    
    if (rb->buffer) {
        free(rb->buffer);
    }
    
    pthread_mutex_destroy(&rb->mutex);
    free(rb);
}

// 无锁入队（单生产者）
int ring_buffer_enqueue(RingBuffer* rb, void* item) {
    if (!rb || !item) return -1;
    
    size_t head = rb->head;
    size_t next_head = (head + 1) & rb->mask;
    
    // 检查队列是否满
    if (next_head == rb->tail) {
        return -2;  // 队列满
    }
    
    rb->buffer[head] = item;
    rb->head = next_head;
    
    // 内存屏障，确保写入完成
    __sync_synchronize();
    
    return 0;
}

// 无锁出队（单消费者）
int ring_buffer_dequeue(RingBuffer* rb, void** item) {
    if (!rb || !item) return -1;
    
    // 内存屏障，确保读取最新数据
    __sync_synchronize();
    
    size_t tail = rb->tail;
    
    // 检查队列是否空
    if (tail == rb->head) {
        return -2;  // 队列空
    }
    
    *item = rb->buffer[tail];
    rb->tail = (tail + 1) & rb->mask;
    
    return 0;
}

// 批量入队（优化版）
int ring_buffer_enqueue_batch(RingBuffer* rb, void** items, size_t count) {
    if (!rb || !items || count == 0) return -1;
    
    size_t head = rb->head;
    size_t tail = rb->tail;
    size_t available;
    
    if (head >= tail) {
        available = rb->capacity - (head - tail) - 1;
    } else {
        available = tail - head - 1;
    }
    
    if (available < count) {
        return -2;  // 队列空间不足
    }
    
    // 批量写入
    size_t first_part = rb->capacity - head;
    if (first_part >= count) {
        // 一次写入即可
        memcpy(&rb->buffer[head], items, count * sizeof(void*));
    } else {
        // 需要分两次写入
        memcpy(&rb->buffer[head], items, first_part * sizeof(void*));
        memcpy(rb->buffer, &items[first_part], (count - first_part) * sizeof(void*));
    }
    
    rb->head = (head + count) & rb->mask;
    __sync_synchronize();
    
    return 0;
}

// 批量出队
int ring_buffer_dequeue_batch(RingBuffer* rb, void** items, size_t max_count) {
    if (!rb || !items || max_count == 0) return -1;
    
    size_t head = rb->head;
    size_t tail = rb->tail;
    size_t available;
    
    if (head >= tail) {
        available = head - tail;
    } else {
        available = rb->capacity - tail + head;
    }
    
    if (available == 0) {
        return -2;  // 队列空
    }
    
    size_t count = (available < max_count) ? available : max_count;
    
    // 批量读取
    size_t first_part = rb->capacity - tail;
    if (first_part >= count) {
        memcpy(items, &rb->buffer[tail], count * sizeof(void*));
    } else {
        memcpy(items, &rb->buffer[tail], first_part * sizeof(void*));
        memcpy(&items[first_part], rb->buffer, (count - first_part) * sizeof(void*));
    }
    
    rb->tail = (tail + count) & rb->mask;
    
    return (int)count;
}

size_t ring_buffer_size(RingBuffer* rb) {
    if (!rb) return 0;
    
    size_t head = rb->head;
    size_t tail = rb->tail;
    
    if (head >= tail) {
        return head - tail;
    } else {
        return rb->capacity - tail + head;
    }
}

// ============ 原子计数器实现 ============

void atomic_counter_init(AtomicCounter* counter, uint64_t value) {
    if (!counter) return;
    
    counter->value = value;
    pthread_spin_init(&counter->lock, PTHREAD_PROCESS_PRIVATE);
}

uint64_t atomic_counter_add(AtomicCounter* counter, int64_t delta) {
    if (!counter) return 0;
    
    pthread_spin_lock(&counter->lock);
    counter->value += delta;
    uint64_t result = counter->value;
    pthread_spin_unlock(&counter->lock);
    
    return result;
}

uint64_t atomic_counter_get(AtomicCounter* counter) {
    if (!counter) return 0;
    return counter->value;
}

// ============ 流水线引擎实现 ============

// 扫描阶段工作线程
static void* scan_worker_thread(void* arg) {
    PipelineEngine* engine = (PipelineEngine*)arg;
    
    while (engine->running) {
        PipelineTask* task = NULL;
        
        if (ring_buffer_dequeue(engine->scan_queue, (void**)&task) == 0) {
            uint64_t start_time = get_timestamp();
            
            // 执行扫描任务
            if (task && task->file) {
                // 这里可以添加实际的扫描逻辑
                // 例如：读取文件属性、检查文件大小等
                
                atomic_counter_add(engine->stage_counters[STAGE_SCAN], 1);
                
                // 提交到下一阶段
                task->stage = STAGE_METADATA;
                ring_buffer_enqueue(engine->metadata_queue, task);
            }
            
            uint64_t end_time = get_timestamp();
            uint64_t latency = end_time - start_time;
            
            pthread_mutex_lock(&engine->stats_mutex);
            engine->stats.dequeued[STAGE_SCAN]++;
            engine->stats.processed[STAGE_SCAN]++;
            engine->stats.total_latency_ns += latency;
            if (latency > engine->stats.max_latency_ns) {
                engine->stats.max_latency_ns = latency;
            }
            if (latency < engine->stats.min_latency_ns || engine->stats.min_latency_ns == 0) {
                engine->stats.min_latency_ns = latency;
            }
            pthread_mutex_unlock(&engine->stats_mutex);
        } else {
            // 队列为空，短暂休眠
#ifdef _WIN32
            SwitchToThread();
#else
            sched_yield();
#endif
        }
    }
    
    return NULL;
}

// 元数据处理阶段工作线程
static void* metadata_worker_thread(void* arg) {
    PipelineEngine* engine = (PipelineEngine*)arg;
    
    while (engine->running) {
        PipelineTask* task = NULL;
        
        if (ring_buffer_dequeue(engine->metadata_queue, (void**)&task) == 0) {
            uint64_t start_time = get_timestamp();
            
            // 执行元数据处理
            if (task && task->file) {
                // 获取文件元数据
                // 可以在这里调用存储API获取文件信息
                
                atomic_counter_add(engine->stage_counters[STAGE_METADATA], 1);
                
                // 提交到下一阶段
                task->stage = STAGE_COPY;
                ring_buffer_enqueue(engine->copy_queue, task);
            }
            
            uint64_t end_time = get_timestamp();
            
            pthread_mutex_lock(&engine->stats_mutex);
            engine->stats.dequeued[STAGE_METADATA]++;
            engine->stats.processed[STAGE_METADATA]++;
            engine->stats.total_latency_ns += (end_time - start_time);
            pthread_mutex_unlock(&engine->stats_mutex);
        } else {
#ifdef _WIN32
            SwitchToThread();
#else
            sched_yield();
#endif
        }
    }
    
    return NULL;
}

// 复制阶段工作线程
static void* copy_worker_thread(void* arg) {
    PipelineEngine* engine = (PipelineEngine*)arg;
    
    while (engine->running) {
        PipelineTask* task = NULL;
        
        if (ring_buffer_dequeue(engine->copy_queue, (void**)&task) == 0) {
            uint64_t start_time = get_timestamp();
            
            // 执行复制操作
            if (task && task->file) {
                // 根据文件大小选择复制策略
                IOStrategy strategy = select_optimal_strategy(task->file, ".");
                
                // 实际的复制逻辑
                // 这里可以集成异步I/O引擎
                
                atomic_counter_add(engine->stage_counters[STAGE_COPY], 1);
                
                // 提交到下一阶段
                task->stage = STAGE_VERIFY;
                ring_buffer_enqueue(engine->verify_queue, task);
            }
            
            uint64_t end_time = get_timestamp();
            
            pthread_mutex_lock(&engine->stats_mutex);
            engine->stats.dequeued[STAGE_COPY]++;
            engine->stats.processed[STAGE_COPY]++;
            engine->stats.total_latency_ns += (end_time - start_time);
            pthread_mutex_unlock(&engine->stats_mutex);
        } else {
#ifdef _WIN32
            SwitchToThread();
#else
            sched_yield();
#endif
        }
    }
    
    return NULL;
}

// 校验阶段工作线程
static void* verify_worker_thread(void* arg) {
    PipelineEngine* engine = (PipelineEngine*)arg;
    
    while (engine->running) {
        PipelineTask* task = NULL;
        
        if (ring_buffer_dequeue(engine->verify_queue, (void**)&task) == 0) {
            uint64_t start_time = get_timestamp();
            
            // 执行校验
            if (task && task->data && task->size > 0) {
                // 并行计算CRC32
                task->checksum = calculate_crc32_parallel(
                    task->data, task->size, 4
                );
                
                atomic_counter_add(engine->stage_counters[STAGE_VERIFY], 1);
            }
            
            uint64_t end_time = get_timestamp();
            
            pthread_mutex_lock(&engine->stats_mutex);
            engine->stats.dequeued[STAGE_VERIFY]++;
            engine->stats.processed[STAGE_VERIFY]++;
            engine->stats.total_latency_ns += (end_time - start_time);
            pthread_mutex_unlock(&engine->stats_mutex);
            
            // 任务完成，释放资源
            if (task) {
                free(task);
            }
        } else {
#ifdef _WIN32
            SwitchToThread();
#else
            sched_yield();
#endif
        }
    }
    
    return NULL;
}

PipelineEngine* pipeline_engine_create(
    size_t queue_capacity,
    const uint32_t thread_counts[4],
    void* user_context
) {
    if (queue_capacity == 0) {
        queue_capacity = DEFAULT_QUEUE_CAPACITY;
    }
    
    PipelineEngine* engine = (PipelineEngine*)calloc(1, sizeof(PipelineEngine));
    if (!engine) return NULL;
    
    // 创建队列
    engine->scan_queue = ring_buffer_create(queue_capacity);
    engine->metadata_queue = ring_buffer_create(queue_capacity);
    engine->copy_queue = ring_buffer_create(queue_capacity);
    engine->verify_queue = ring_buffer_create(queue_capacity);
    
    if (!engine->scan_queue || !engine->metadata_queue || 
        !engine->copy_queue || !engine->verify_queue) {
        pipeline_engine_destroy(engine);
        return NULL;
    }
    
    // 创建计数器
    for (int i = 0; i < 4; i++) {
        engine->stage_counters[i] = (AtomicCounter*)calloc(1, sizeof(AtomicCounter));
        atomic_counter_init(engine->stage_counters[i], 0);
        
        engine->thread_counts[i] = thread_counts ? thread_counts[i] : 4;
    }
    
    engine->user_context = user_context;
    pthread_mutex_init(&engine->stats_mutex, NULL);
    
    return engine;
}

int pipeline_engine_start(PipelineEngine* engine) {
    if (!engine) return -1;
    
    engine->running = 1;
    
    // 创建工作线程
    for (int stage = 0; stage < 4; stage++) {
        for (uint32_t i = 0; i < engine->thread_counts[stage]; i++) {
            void* (*worker_func)(void*);
            
            switch (stage) {
                case STAGE_SCAN:     worker_func = scan_worker_thread; break;
                case STAGE_METADATA: worker_func = metadata_worker_thread; break;
                case STAGE_COPY:     worker_func = copy_worker_thread; break;
                case STAGE_VERIFY:   worker_func = verify_worker_thread; break;
                default: continue;
            }
            
            pthread_create(&engine->worker_threads[stage][i], NULL, worker_func, engine);
        }
    }
    
    return 0;
}

void pipeline_engine_stop(PipelineEngine* engine) {
    if (!engine) return;
    
    engine->running = 0;
    
    // 等待所有线程结束
    for (int stage = 0; stage < 4; stage++) {
        for (uint32_t i = 0; i < engine->thread_counts[stage]; i++) {
            pthread_join(engine->worker_threads[stage][i], NULL);
        }
    }
}

void pipeline_engine_destroy(PipelineEngine* engine) {
    if (!engine) return;
    
    // 销毁队列
    if (engine->scan_queue) ring_buffer_destroy(engine->scan_queue);
    if (engine->metadata_queue) ring_buffer_destroy(engine->metadata_queue);
    if (engine->copy_queue) ring_buffer_destroy(engine->copy_queue);
    if (engine->verify_queue) ring_buffer_destroy(engine->verify_queue);
    
    // 销毁计数器
    for (int i = 0; i < 4; i++) {
        if (engine->stage_counters[i]) {
            pthread_spin_destroy(&engine->stage_counters[i]->lock);
            free(engine->stage_counters[i]);
        }
    }
    
    pthread_mutex_destroy(&engine->stats_mutex);
    free(engine);
}

int pipeline_submit_task(PipelineEngine* engine, PipelineTask* task) {
    if (!engine || !task) return -1;
    
    // 根据任务阶段提交到对应队列
    RingBuffer* queue = NULL;
    switch (task->stage) {
        case STAGE_SCAN:     queue = engine->scan_queue; break;
        case STAGE_METADATA: queue = engine->metadata_queue; break;
        case STAGE_COPY:     queue = engine->copy_queue; break;
        case STAGE_VERIFY:   queue = engine->verify_queue; break;
        default: return -2;
    }
    
    int result = ring_buffer_enqueue(queue, task);
    if (result == 0) {
        atomic_counter_add(engine->stage_counters[task->stage], 1);
        
        pthread_mutex_lock(&engine->stats_mutex);
        engine->stats.enqueued[task->stage]++;
        pthread_mutex_unlock(&engine->stats_mutex);
    }
    
    return result;
}

void pipeline_get_stats(PipelineEngine* engine, PipelineStats* stats) {
    if (!engine || !stats) return;
    
    pthread_mutex_lock(&engine->stats_mutex);
    memcpy(stats, &engine->stats, sizeof(PipelineStats));
    pthread_mutex_unlock(&engine->stats_mutex);
}

void pipeline_reset_stats(PipelineEngine* engine) {
    if (!engine) return;
    
    pthread_mutex_lock(&engine->stats_mutex);
    memset(&engine->stats, 0, sizeof(PipelineStats));
    engine->stats.min_latency_ns = UINT64_MAX;
    pthread_mutex_unlock(&engine->stats_mutex);
}
