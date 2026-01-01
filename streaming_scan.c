#include "streaming_scan.h"
#include "directory_scan.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>

#ifndef _WIN32
#include <unistd.h>
#endif

#define DEFAULT_QUEUE_CAPACITY 100
#define DEFAULT_BATCH_SIZE 256
#define DEFAULT_BACKPRESSURE_THRESHOLD 80  // 80%

// ============ 文件批次管理 ============

static FileScanBatch* batch_create(uint32_t capacity) {
    FileScanBatch* batch = (FileScanBatch*)calloc(1, sizeof(FileScanBatch));
    if (!batch) return NULL;
    
    batch->file_ids = (uint64_t*)calloc(capacity, sizeof(uint64_t));
    batch->paths = (char**)calloc(capacity, sizeof(char*));
    batch->sizes = (uint64_t*)calloc(capacity, sizeof(uint64_t));
    batch->count = 0;
    batch->capacity = capacity;
    
    if (!batch->file_ids || !batch->paths || !batch->sizes) {
        batch_destroy(batch);
        return NULL;
    }
    
    return batch;
}

static int batch_add_file(FileScanBatch* batch, uint64_t file_id, 
                          const char* path, uint64_t size) {
    if (!batch || batch->count >= batch->capacity) {
        return -1;
    }
    
    batch->file_ids[batch->count] = file_id;
    batch->sizes[batch->count] = size;
    
    // 复制路径
    batch->paths[batch->count] = strdup(path);
    if (!batch->paths[batch->count]) {
        return -1;
    }
    
    batch->count++;
    return 0;
}

static void batch_destroy(FileScanBatch* batch) {
    if (!batch) return;
    
    if (batch->file_ids) free(batch->file_ids);
    if (batch->sizes) free(batch->sizes);
    
    if (batch->paths) {
        for (uint32_t i = 0; i < batch->count; i++) {
            if (batch->paths[i]) {
                free(batch->paths[i]);
            }
        }
        free(batch->paths);
    }
    
    free(batch);
}

// ============ 流式扫描器实现 ============

static void* scan_worker_thread(void* arg) {
    StreamingScanner* scanner = (StreamingScanner*)arg;
    
    // 执行实际扫描（简化版）
    // 实际实现应该使用directory_scan模块
    char* scan_path = (char*)scanner->user_context;
    
    DIR* dir = opendir(scan_path);
    if (!dir) {
        return NULL;
    }
    
    struct dirent* entry;
    uint64_t file_id = 0;
    
    while ((entry = readdir(dir)) != NULL && scanner->running) {
        // 跳过当前和父目录
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        // 构建完整路径
        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s/%s", scan_path, entry->d_name);
        
        // 获取文件信息
        struct stat st;
        if (stat(full_path, &st) != 0) {
            continue;
        }
        
        // 只处理普通文件
        if (!S_ISREG(st.st_mode)) {
            continue;
        }
        
        // 检查背压
        pthread_mutex_lock(&scanner->queue_mutex);
        
        while (scanner->backpressure_active && scanner->running) {
            // 队列满了，暂停扫描
            pthread_cond_wait(&scanner->backpressure_cond, &scanner->queue_mutex);
        }
        
        pthread_mutex_unlock(&scanner->queue_mutex);
        
        if (!scanner->running) {
            break;
        }
        
        // 获取或创建当前批次
        pthread_mutex_lock(&scanner->queue_mutex);
        
        if (!scanner->current_batch) {
            scanner->current_batch = batch_create(scanner->config.batch_size);
        }
        
        if (scanner->current_batch) {
            // 添加文件到当前批次
            if (batch_add_file(scanner->current_batch, file_id, full_path, st.st_size) == 0) {
                file_id++;
                
                pthread_mutex_lock(&scanner->stats_mutex);
                scanner->scanned_files++;
                scanner->total_size += st.st_size;
                pthread_mutex_unlock(&scanner->stats_mutex);
                
                // 批次满了，加入队列
                if (scanner->current_batch->count >= scanner->config.batch_size) {
                    size_t idx = (scanner->queue_tail + 1) % scanner->config.queue_capacity;
                    
                    if (idx != scanner->queue_head) {
                        scanner->batch_queue[scanner->queue_tail] = scanner->current_batch;
                        scanner->queue_tail = idx;
                        scanner->queue_count++;
                        scanner->current_batch = NULL;
                        
                        // 通知等待的消费者
                        pthread_cond_signal(&scanner->backpressure_cond);
                    }
                }
                
                // 进度回调
                if (scanner->progress_callback && 
                    scanner->scanned_files % 1000 == 0) {
                    pthread_mutex_lock(&scanner->stats_mutex);
                    scanner->progress_callback(scanner->scanned_files, 
                                            scanner->total_files, 
                                            scanner->user_context);
                    pthread_mutex_unlock(&scanner->stats_mutex);
                }
            }
        }
        
        pthread_mutex_unlock(&scanner->queue_mutex);
    }
    
    closedir(dir);
    
    // 将最后一个批次加入队列
    pthread_mutex_lock(&scanner->queue_mutex);
    
    if (scanner->current_batch && scanner->current_batch->count > 0) {
        size_t idx = (scanner->queue_tail + 1) % scanner->config.queue_capacity;
        if (idx != scanner->queue_head) {
            scanner->batch_queue[scanner->queue_tail] = scanner->current_batch;
            scanner->queue_tail = idx;
            scanner->queue_count++;
            scanner->current_batch = NULL;
        }
    }
    
    // 标记扫描完成
    scanner->total_files = file_id;
    pthread_cond_broadcast(&scanner->backpressure_cond);
    
    pthread_mutex_unlock(&scanner->queue_mutex);
    
    return NULL;
}

StreamingScanner* streaming_scanner_create(const StreamingScanConfig* config) {
    StreamingScanner* scanner = (StreamingScanner*)calloc(1, sizeof(StreamingScanner));
    if (!scanner) return NULL;
    
    if (config) {
        memcpy(&scanner->config, config, sizeof(StreamingScanConfig));
    } else {
        // 默认配置
        scanner->config.queue_capacity = DEFAULT_QUEUE_CAPACITY;
        scanner->config.batch_size = DEFAULT_BATCH_SIZE;
        scanner->config.backpressure_threshold = DEFAULT_BACKPRESSURE_THRESHOLD;
        scanner->config.scan_threads = 1;
        scanner->config.enable_streaming = 1;
        scanner->config.real_time_progress = 1;
    }
    
    // 初始化队列
    scanner->batch_queue = (FileScanBatch**)calloc(
        scanner->config.queue_capacity, sizeof(FileScanBatch*)
    );
    if (!scanner->batch_queue) {
        free(scanner);
        return NULL;
    }
    
    scanner->queue_head = 0;
    scanner->queue_tail = 0;
    scanner->queue_count = 0;
    scanner->current_batch = NULL;
    scanner->running = 0;
    scanner->backpressure_active = 0;
    
    pthread_mutex_init(&scanner->queue_mutex, NULL);
    pthread_cond_init(&scanner->backpressure_cond, NULL);
    pthread_mutex_init(&scanner->stats_mutex, NULL);
    
    return scanner;
}

void streaming_scanner_destroy(StreamingScanner* scanner) {
    if (!scanner) return;
    
    // 停止扫描
    streaming_scan_stop(scanner);
    
    // 释放队列中的批次
    pthread_mutex_lock(&scanner->queue_mutex);
    
    while (scanner->queue_head != scanner->queue_tail) {
        FileScanBatch* batch = scanner->batch_queue[scanner->queue_head];
        scanner->queue_head = (scanner->queue_head + 1) % scanner->config.queue_capacity;
        if (batch) {
            batch_destroy(batch);
        }
    }
    
    if (scanner->current_batch) {
        batch_destroy(scanner->current_batch);
    }
    
    pthread_mutex_unlock(&scanner->queue_mutex);
    
    if (scanner->batch_queue) {
        free(scanner->batch_queue);
    }
    
    if (scanner->scan_threads) {
        free(scanner->scan_threads);
    }
    
    pthread_mutex_destroy(&scanner->queue_mutex);
    pthread_cond_destroy(&scanner->backpressure_cond);
    pthread_mutex_destroy(&scanner->stats_mutex);
    
    free(scanner);
}

int streaming_scan_start(StreamingScanner* scanner, const char* directory) {
    if (!scanner || !directory) return -1;
    
    // 重置状态
    pthread_mutex_lock(&scanner->stats_mutex);
    scanner->total_files = 0;
    scanner->scanned_files = 0;
    scanner->processed_files = 0;
    scanner->total_size = 0;
    pthread_mutex_unlock(&scanner->stats_mutex);
    
    // 保存扫描路径到user_context
    scanner->user_context = (void*)strdup(directory);
    
    // 创建扫描线程
    scanner->scan_threads = (pthread_t*)calloc(scanner->config.scan_threads, sizeof(pthread_t));
    if (!scanner->scan_threads) {
        return -1;
    }
    
    scanner->running = 1;
    
    // 启动扫描线程
    for (uint32_t i = 0; i < scanner->config.scan_threads; i++) {
        pthread_create(&scanner->scan_threads[i], NULL, scan_worker_thread, scanner);
    }
    
    return 0;
}

void streaming_scan_stop(StreamingScanner* scanner) {
    if (!scanner) return;
    
    scanner->running = 0;
    
    // 等待所有扫描线程结束
    if (scanner->scan_threads) {
        for (uint32_t i = 0; i < scanner->config.scan_threads; i++) {
            pthread_join(scanner->scan_threads[i], NULL);
        }
        free(scanner->scan_threads);
        scanner->scan_threads = NULL;
    }
    
    // 释放扫描路径
    if (scanner->user_context) {
        free(scanner->user_context);
        scanner->user_context = NULL;
    }
}

FileScanBatch* streaming_scan_next_batch(StreamingScanner* scanner) {
    if (!scanner) return NULL;
    
    pthread_mutex_lock(&scanner->queue_mutex);
    
    while (scanner->queue_head == scanner->queue_tail && scanner->running) {
        // 队列为空，等待
        pthread_cond_wait(&scanner->backpressure_cond, &scanner->queue_mutex);
    }
    
    if (scanner->queue_head == scanner->queue_tail) {
        pthread_mutex_unlock(&scanner->queue_mutex);
        return NULL;  // 扫描完成
    }
    
    // 获取批次
    FileScanBatch* batch = scanner->batch_queue[scanner->queue_head];
    scanner->queue_head = (scanner->queue_head + 1) % scanner->config.queue_capacity;
    scanner->queue_count--;
    
    // 检查背压
    size_t queue_usage = (scanner->queue_count * 100) / scanner->config.queue_capacity;
    if (scanner->backpressure_active && queue_usage < scanner->config.backpressure_threshold) {
        scanner->backpressure_active = 0;
        pthread_cond_signal(&scanner->backpressure_cond);  // 通知扫描线程恢复
    }
    
    pthread_mutex_unlock(&scanner->queue_mutex);
    
    pthread_mutex_lock(&scanner->stats_mutex);
    scanner->processed_files += batch->count;
    pthread_mutex_unlock(&scanner->stats_mutex);
    
    return batch;
}

void streaming_scan_release_batch(StreamingScanner* scanner, FileScanBatch* batch) {
    if (!batch) return;
    
    // 释放批次中的内存（可选，根据需求）
    batch_destroy(batch);
}

int streaming_scan_backpressure(StreamingScanner* scanner) {
    if (!scanner) return 0;
    
    pthread_mutex_lock(&scanner->queue_mutex);
    int active = scanner->backpressure_active;
    pthread_mutex_unlock(&scanner->queue_mutex);
    
    return active;
}

void streaming_scan_wait_backpressure(StreamingScanner* scanner) {
    if (!scanner) return;
    
    pthread_mutex_lock(&scanner->queue_mutex);
    
    while (scanner->backpressure_active && scanner->running) {
        pthread_cond_wait(&scanner->backpressure_cond, &scanner->queue_mutex);
    }
    
    pthread_mutex_unlock(&scanner->queue_mutex);
}

void streaming_scan_get_progress(StreamingScanner* scanner, 
                                uint64_t* scanned, uint64_t* total) {
    if (!scanner) return;
    
    pthread_mutex_lock(&scanner->stats_mutex);
    
    if (scanned) *scanned = scanner->scanned_files;
    if (total) *total = scanner->total_files;
    
    pthread_mutex_unlock(&scanner->stats_mutex);
}

void streaming_scan_get_stats(StreamingScanner* scanner, char* buffer, size_t buffer_size) {
    if (!scanner || !buffer) return;
    
    pthread_mutex_lock(&scanner->stats_mutex);
    
    snprintf(buffer, buffer_size,
        "Streaming Scan Statistics:\n"
        "  Total Files: %llu\n"
        "  Scanned Files: %llu\n"
        "  Processed Files: %llu\n"
        "  Total Size: %.2f MB\n"
        "  Queue Count: %zu\n"
        "  Backpressure Active: %s\n",
        (unsigned long long)scanner->total_files,
        (unsigned long long)scanner->scanned_files,
        (unsigned long long)scanner->processed_files,
        scanner->total_size / (1024.0 * 1024.0),
        scanner->queue_count,
        scanner->backpressure_active ? "Yes" : "No"
    );
    
    pthread_mutex_unlock(&scanner->stats_mutex);
}

void streaming_scan_reset(StreamingScanner* scanner) {
    if (!scanner) return;
    
    streaming_scan_stop(scanner);
    
    pthread_mutex_lock(&scanner->queue_mutex);
    pthread_mutex_lock(&scanner->stats_mutex);
    
    // 清空队列
    while (scanner->queue_head != scanner->queue_tail) {
        FileScanBatch* batch = scanner->batch_queue[scanner->queue_head];
        scanner->queue_head = (scanner->queue_head + 1) % scanner->config.queue_capacity;
        if (batch) {
            batch_destroy(batch);
        }
    }
    
    if (scanner->current_batch) {
        batch_destroy(scanner->current_batch);
        scanner->current_batch = NULL;
    }
    
    scanner->queue_head = 0;
    scanner->queue_tail = 0;
    scanner->queue_count = 0;
    scanner->total_files = 0;
    scanner->scanned_files = 0;
    scanner->processed_files = 0;
    scanner->total_size = 0;
    scanner->backpressure_active = 0;
    
    pthread_mutex_unlock(&scanner->stats_mutex);
    pthread_mutex_unlock(&scanner->queue_mutex);
}
