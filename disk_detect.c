#include "disk_detect.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
    #include <windows.h>
    #include <winioctl.h>
#else
    #include <sys/statvfs.h>
    #include <fcntl.h>
    #include <unistd.h>
#endif

#define BENCHMARK_SIZE (64 * 1024 * 1024)  // 64MB基准测试
#define ADJUSTMENT_INTERVAL_MS 5000           // 5秒调整一次
#define MIN_ADJUSTMENT_INTERVAL_MS 1000      // 最小调整间隔1秒

// ============ 磁盘类型检测 ============

#ifdef _WIN32

static DiskType detect_disk_type_windows(const char* path) {
    char root[4];
    strncpy(root, path, 3);
    root[3] = '\0';
    
    char volume_path[MAX_PATH];
    snprintf(volume_path, sizeof(volume_path), "\\\\.\\%s", root);
    
    HANDLE handle = CreateFileA(
        volume_path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    
    if (handle == INVALID_HANDLE_VALUE) {
        return DISK_TYPE_UNKNOWN;
    }
    
    // 获取磁盘属性
    STORAGE_PROPERTY_QUERY query;
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;
    
    STORAGE_DEVICE_DESCRIPTOR* descriptor = NULL;
    DWORD bytes_returned = 0;
    
    // 首先获取所需大小
    DeviceIoControl(
        handle,
        IOCTL_STORAGE_QUERY_PROPERTY,
        &query,
        sizeof(query),
        NULL,
        0,
        &bytes_returned,
        NULL
    );
    
    descriptor = (STORAGE_DEVICE_DESCRIPTOR*)malloc(bytes_returned);
    
    BOOL result = DeviceIoControl(
        handle,
        IOCTL_STORAGE_QUERY_PROPERTY,
        &query,
        sizeof(query),
        descriptor,
        bytes_returned,
        &bytes_returned,
        NULL
    );
    
    DiskType type = DISK_TYPE_UNKNOWN;
    
    if (result) {
        // 检查TRIM支持
        if (descriptor->TrimEnabled) {
            type = DISK_TYPE_SSD;
            
            // 进一步检查是否为NVMe
            // 简化实现：假设TRIM启用即SSD
        }
        
        // 检查转速（HDD）
        // 可以通过SMART信息获取
    }
    
    free(descriptor);
    CloseHandle(handle);
    
    return type;
}

#else

static DiskType detect_disk_type_linux(const char* path) {
    // 获取设备路径
    struct statvfs fs;
    if (statvfs(path, &fs) != 0) {
        return DISK_TYPE_UNKNOWN;
    }
    
    // 简化实现：通过/sys/block/queue/rotational判断
    // 0表示SSD，1表示HDD
    
    // 获取设备名
    char device_path[256];
    snprintf(device_path, sizeof(device_path), "/proc/mounts");
    
    FILE* fp = fopen(device_path, "r");
    if (!fp) {
        return DISK_TYPE_UNKNOWN;
    }
    
    char line[1024];
    char device[256];
    char mount[256];
    
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, path)) {
            sscanf(line, "%s %s", device, mount);
            break;
        }
    }
    
    fclose(fp);
    
    // 检查设备是否为固态盘
    char rotational_path[512];
    snprintf(rotational_path, sizeof(rotational_path), "/sys/block/%s/queue/rotational", device);
    
    fp = fopen(rotational_path, "r");
    if (fp) {
        int rotational = 0;
        fscanf(fp, "%d", &rotational);
        fclose(fp);
        
        return (rotational == 0) ? DISK_TYPE_SSD : DISK_TYPE_HDD;
    }
    
    return DISK_TYPE_UNKNOWN;
}

#endif

DiskType detect_disk_type(const char* path) {
#ifdef _WIN32
    return detect_disk_type_windows(path);
#else
    return detect_disk_type_linux(path);
#endif
}

// ============ 磁盘信息获取 ============

int get_disk_info(const char* path, DiskInfo* info) {
    if (!info) return -1;
    
    memset(info, 0, sizeof(DiskInfo));
    
    info->type = detect_disk_type(path);
    
    // 设置默认参数
    switch (info->type) {
        case DISK_TYPE_HDD:
            info->max_concurrent_ops = 32;
            info->optimal_batch_size = 64;
            info->optimal_queue_depth = 16;
            info->sequential_read_speed = 150;  // MB/s
            info->sequential_write_speed = 150;
            info->random_read_speed = 1;
            info->random_write_speed = 1;
            info->rotation_speed = 7200;
            info->trim_support = 0;
            break;
            
        case DISK_TYPE_SSD:
            info->max_concurrent_ops = 128;
            info->optimal_batch_size = 256;
            info->optimal_queue_depth = 32;
            info->sequential_read_speed = 500;  // MB/s
            info->sequential_write_speed = 500;
            info->random_read_speed = 50;
            info->random_write_speed = 50;
            info->rotation_speed = 0;
            info->trim_support = 1;
            break;
            
        case DISK_TYPE_NVME:
            info->max_concurrent_ops = 256;
            info->optimal_batch_size = 512;
            info->optimal_queue_depth = 64;
            info->sequential_read_speed = 3000; // MB/s
            info->sequential_write_speed = 2500;
            info->random_read_speed = 200;
            info->random_write_speed = 150;
            info->rotation_speed = 0;
            info->trim_support = 1;
            break;
            
        default:
            info->max_concurrent_ops = 64;
            info->optimal_batch_size = 128;
            info->optimal_queue_depth = 32;
            info->sequential_read_speed = 100;
            info->sequential_write_speed = 100;
            break;
    }
    
    return 0;
}

// ============ 磁盘基准测试 ============

int run_disk_benchmark(const char* path, DiskInfo* info) {
    if (!info) return -1;
    
    printf("Running disk benchmark on: %s\n", path);
    printf("Benchmark size: %d MB\n", BENCHMARK_SIZE / (1024 * 1024));
    
    // 简化实现：仅设置典型值
    // 实际实现应该：
    // 1. 创建临时文件
    // 2. 执行顺序写测试
    // 3. 执行顺序读测试
    // 4. 执行随机写测试
    // 5. 执行随机读测试
    // 6. 计算平均延迟
    
    printf("Benchmark completed (simplified)\n");
    
    return 0;
}

// ============ 自适应统计 ============

AdaptiveStats* adaptive_stats_init(const DiskInfo* disk_info) {
    AdaptiveStats* stats = (AdaptiveStats*)calloc(1, sizeof(AdaptiveStats));
    if (!stats) return NULL;
    
    // 初始化为磁盘推荐值
    stats->optimal_batch_size = disk_info ? disk_info->optimal_batch_size : 256;
    stats->optimal_queue_depth = disk_info ? disk_info->optimal_queue_depth : 32;
    stats->current_batch_size = stats->optimal_batch_size;
    stats->queue_depth = stats->optimal_queue_depth;
    
    stats->last_direction = 0;
    stats->last_adjust_time = get_timestamp();
    stats->performance_trend = 0.0;
    
    return stats;
}

void adaptive_stats_update(AdaptiveStats* stats, uint64_t bytes, uint64_t latency_ns) {
    if (!stats) return;
    
    stats->operation_count++;
    stats->total_bytes += bytes;
    stats->total_latency_ns += latency_ns;
    
    // 更新平均延迟
    stats->avg_latency_ns = (double)stats->total_latency_ns / stats->operation_count;
    
    // 计算吞吐量 (MB/s)
    uint64_t current_time = get_timestamp();
    static uint64_t start_time = 0;
    if (start_time == 0) start_time = current_time;
    
    double elapsed_sec = (current_time - start_time) / 1e9;
    if (elapsed_sec > 0) {
        stats->throughput_mbps = (stats->total_bytes / (1024.0 * 1024.0)) / elapsed_sec;
    }
    
    // 定期调整参数
    if ((current_time - stats->last_adjust_time) > ADJUSTMENT_INTERVAL_MS * 1000000ULL) {
        adaptive_adjust(stats);
        stats->last_adjust_time = current_time;
    }
}

void adaptive_adjust(AdaptiveStats* stats) {
    if (!stats) return;
    
    // 简化的自适应算法
    // 基于性能趋势调整批次大小和队列深度
    
    if (stats->performance_trend > 0.1) {
        // 性能提升，增加批次大小
        if (stats->current_batch_size < 1024) {
            stats->current_batch_size = (uint32_t)(stats->current_batch_size * 1.2);
            stats->last_direction = 1;
        }
    } else if (stats->performance_trend < -0.1) {
        // 性能下降，减少批次大小
        if (stats->current_batch_size > 32) {
            stats->current_batch_size = (uint32_t)(stats->current_batch_size * 0.8);
            stats->last_direction = -1;
        }
    }
    
    // 调整队列深度
    if (stats->avg_latency_ns > 50000000) { // 50ms
        // 延迟高，减少队列深度
        if (stats->queue_depth > 4) {
            stats->queue_depth = (uint32_t)(stats->queue_depth * 0.9);
        }
    } else if (stats->avg_latency_ns < 1000000) { // 1ms
        // 延迟低，增加队列深度
        if (stats->queue_depth < 128) {
            stats->queue_depth = (uint32_t)(stats->queue_depth * 1.1);
        }
    }
    
    stats->optimal_batch_size = stats->current_batch_size;
    stats->optimal_queue_depth = stats->queue_depth;
}

uint32_t get_adaptive_batch_size(AdaptiveStats* stats) {
    if (!stats) return 256;
    return stats->optimal_batch_size;
}

uint32_t get_adaptive_queue_depth(AdaptiveStats* stats) {
    if (!stats) return 32;
    return stats->optimal_queue_depth;
}

void adaptive_stats_reset(AdaptiveStats* stats) {
    if (!stats) return;
    
    stats->operation_count = 0;
    stats->total_bytes = 0;
    stats->total_latency_ns = 0;
    stats->total_errors = 0;
    
    stats->avg_latency_ns = 0.0;
    stats->p50_latency_ns = 0.0;
    stats->p95_latency_ns = 0.0;
    stats->p99_latency_ns = 0.0;
    stats->throughput_mbps = 0.0;
    stats->performance_trend = 0.0;
}

void adaptive_stats_destroy(AdaptiveStats* stats) {
    if (stats) {
        free(stats);
    }
}

void print_disk_info(const DiskInfo* info) {
    if (!info) return;
    
    printf("Disk Information:\n");
    printf("  Type: ");
    switch (info->type) {
        case DISK_TYPE_HDD:    printf("HDD\n"); break;
        case DISK_TYPE_SSD:    printf("SSD\n"); break;
        case DISK_TYPE_NVME:   printf("NVMe\n"); break;
        case DISK_TYPE_HYBRID: printf("Hybrid\n"); break;
        case DISK_TYPE_RAMDISK: printf("RAMDisk\n"); break;
        default:               printf("Unknown\n"); break;
    }
    
    printf("  Max Concurrent Ops: %u\n", info->max_concurrent_ops);
    printf("  Optimal Batch Size: %u\n", info->optimal_batch_size);
    printf("  Optimal Queue Depth: %u\n", info->optimal_queue_depth);
    printf("  Sequential Read Speed: %llu MB/s\n", 
           (unsigned long long)info->sequential_read_speed);
    printf("  Sequential Write Speed: %llu MB/s\n", 
           (unsigned long long)info->sequential_write_speed);
    printf("  Random Read Speed: %llu MB/s\n", 
           (unsigned long long)info->random_read_speed);
    printf("  Random Write Speed: %llu MB/s\n", 
           (unsigned long long)info->random_write_speed);
    printf("  TRIM Support: %s\n", info->trim_support ? "Yes" : "No");
}

void print_adaptive_stats(const AdaptiveStats* stats) {
    if (!stats) return;
    
    printf("Adaptive Statistics:\n");
    printf("  Operations: %llu\n", (unsigned long long)stats->operation_count);
    printf("  Total Bytes: %.2f MB\n", 
           stats->total_bytes / (1024.0 * 1024.0));
    printf("  Avg Latency: %.2f ms\n", stats->avg_latency_ns / 1e6);
    printf("  Throughput: %.2f MB/s\n", stats->throughput_mbps);
    printf("  Current Batch Size: %u\n", stats->current_batch_size);
    printf("  Optimal Batch Size: %u\n", stats->optimal_batch_size);
    printf("  Queue Depth: %u\n", stats->queue_depth);
    printf("  Performance Trend: %.2f\n", stats->performance_trend);
}
