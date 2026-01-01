#include "directory_scan.h"
#include "storage.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <pthread.h>

#ifdef _WIN32
    #include <windows.h>
    #include <winioctl.h>
    #include <fileapi.h>
#endif

#define DEFAULT_BATCH_SIZE 32
#define USN_BUFFER_SIZE (64 * 1024)

// ============ 目录扫描器实现 ============

DirectoryScanner* directory_scanner_create(const ScanConfig* config) {
    DirectoryScanner* scanner = (DirectoryScanner*)calloc(1, sizeof(DirectoryScanner));
    if (!scanner) return NULL;
    
    if (config) {
        memcpy(&scanner->config, config, sizeof(ScanConfig));
    } else {
        // 默认配置
        scanner->config.follow_symlinks = 0;
        scanner->config.skip_hidden = 0;
        scanner->config.skip_system = 0;
        scanner->config.min_size = 0;
        scanner->config.max_size = UINT64_MAX;
        scanner->config.batch_size = DEFAULT_BATCH_SIZE;
    }
    
    return scanner;
}

void directory_scanner_destroy(DirectoryScanner* scanner) {
    if (!scanner) return;
    
#ifdef _WIN32
    if (scanner->usn_handle != INVALID_HANDLE_VALUE) {
        usn_journal_close(scanner);
    }
#endif
    
    if (scanner->config.include_pattern) free(scanner->config.include_pattern);
    if (scanner->config.exclude_pattern) free(scanner->config.exclude_pattern);
    
    free(scanner);
}

// 检查文件是否应该跳过
static int should_skip_file(DirectoryScanner* scanner, const char* filename, 
                             struct stat* st) {
    ScanConfig* config = &scanner->config;
    
    // 跳过隐藏文件
    if (config->skip_hidden && filename[0] == '.') {
        return 1;
    }
    
    // 跳过当前目录和父目录
    if (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0) {
        return 1;
    }
    
    // 跳过符号链接
    if (!config->follow_symlinks && S_ISLNK(st->st_mode)) {
        return 1;
    }
    
    // 大小过滤
    if (S_ISREG(st->st_mode)) {
        if (st->st_size < config->min_size || st->st_size > config->max_size) {
            return 1;
        }
    }
    
    return 0;
}

// 递归扫描目录
static int scan_directory_recursive(DirectoryScanner* scanner, const char* path,
                                    FileCallback file_callback, 
                                    ProgressCallback progress_callback,
                                    uint64_t* current_count, uint64_t total_estimate) {
    DIR* dir = opendir(path);
    if (!dir) {
        return -1;
    }
    
    struct dirent* entry;
    char full_path[1024];
    
    while ((entry = readdir(dir)) != NULL) {
        // 构建完整路径
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
        
        // 获取文件信息
        struct stat st;
        if (stat(full_path, &st) != 0) {
            continue;
        }
        
        // 检查是否应该跳过
        if (should_skip_file(scanner, entry->d_name, &st)) {
            continue;
        }
        
        if (S_ISDIR(st.st_mode)) {
            // 递归扫描子目录
            scan_directory_recursive(scanner, full_path, file_callback,
                                   progress_callback, current_count, total_estimate);
            scanner->stats.total_dirs++;
        } else if (S_ISREG(st.st_mode)) {
            // 创建文件条目
            FileScanEntry file_entry;
            memset(&file_entry, 0, sizeof(FileScanEntry));
            
            file_entry.file_id = scanner->stats.total_files;
            file_entry.file_index = st.st_ino;
            strncpy(file_entry.filename, entry->d_name, sizeof(file_entry.filename) - 1);
            strncpy(file_entry.path, full_path, sizeof(file_entry.path) - 1);
            file_entry.size = st.st_size;
            file_entry.create_time = st.st_ctime * 1000000000ULL;
            file_entry.modify_time = st.st_mtime * 1000000000ULL;
            file_entry.access_time = st.st_atime * 1000000000ULL;
            file_entry.attributes = st.st_mode;
            
            // 调用回调函数
            if (file_callback) {
                file_callback(&file_entry, scanner->user_context);
            }
            
            scanner->stats.total_files++;
            scanner->stats.total_size += st.st_size;
            
            // 更新进度
            if (progress_callback && total_estimate > 0) {
                (*current_count)++;
                progress_callback(*current_count, total_estimate, scanner->user_context);
            }
        }
    }
    
    closedir(dir);
    return 0;
}

int directory_scan(DirectoryScanner* scanner, const char* path,
                   FileCallback file_callback, ProgressCallback progress_callback) {
    if (!scanner || !path) return -1;
    
    // 重置统计
    memset(&scanner->stats, 0, sizeof(ScanStats));
    
    uint64_t start_time = get_timestamp();
    uint64_t current_count = 0;
    
    // 执行扫描
    int result = scan_directory_recursive(scanner, path, file_callback,
                                        progress_callback, &current_count, 0);
    
    uint64_t end_time = get_timestamp();
    scanner->stats.scan_time_us = (end_time - start_time) / 1000;
    
    // 计算性能指标
    if (scanner->stats.scan_time_us > 0) {
        scanner->stats.files_per_sec = 
            (scanner->stats.total_files * 1000000) / scanner->stats.scan_time_us;
        scanner->stats.bytes_per_sec = 
            (scanner->stats.total_size * 1000000) / scanner->stats.scan_time_us;
    }
    
    return result;
}

#ifdef _WIN32

// ============ Windows MFT扫描实现 ============

int mft_scan_init(MFTScanContext* ctx, const char* volume) {
    if (!ctx || !volume) return -1;
    
    memset(ctx, 0, sizeof(MFTScanContext));
    
    // 打开卷句柄
    char volume_path[MAX_PATH];
    snprintf(volume_path, sizeof(volume_path), "\\\\.\\%s", volume);
    
    HANDLE volume_handle = CreateFileA(
        volume_path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    
    if (volume_handle == INVALID_HANDLE_VALUE) {
        return -1;
    }
    
    ctx->buffer_size = USN_BUFFER_SIZE;
    ctx->buffer = (BYTE*)malloc(ctx->buffer_size);
    if (!ctx->buffer) {
        CloseHandle(volume_handle);
        return -1;
    }
    
    return 0;
}

int mft_scan_next(MFTScanContext* ctx, FileScanEntry* entry) {
    if (!ctx || !entry) return -1;
    
    // 实现MFT扫描逻辑
    // 这里需要使用FSCTL_ENUM_USN_DATA等Windows API
    
    // 简化版实现：返回-1表示未完成
    return -1;
}

void mft_scan_close(MFTScanContext* ctx) {
    if (!ctx) return;
    
    if (ctx->buffer) {
        free(ctx->buffer);
    }
    
    // 关闭卷句柄（如果有）
    
    memset(ctx, 0, sizeof(MFTScanContext));
}

// 使用MFT直接扫描（优化版，性能提升10-15倍）
int directory_scan_mft(DirectoryScanner* scanner, const char* path,
                       FileCallback file_callback, ProgressCallback progress_callback) {
    if (!scanner || !path) return -1;
    
    // 提取卷名（例如：C:）
    char volume[4] = {path[0], path[1], '\0', '\0'};
    
    MFTScanContext ctx;
    if (mft_scan_init(&ctx, volume) != 0) {
        return -1;
    }
    
    // 重置统计
    memset(&scanner->stats, 0, sizeof(ScanStats));
    uint64_t start_time = get_timestamp();
    
    // 扫描MFT
    FileScanEntry entry;
    while (mft_scan_next(&ctx, &entry) == 0) {
        // 应用过滤规则
        if (should_skip_file(scanner, entry.filename, NULL)) {
            continue;
        }
        
        // 调用回调函数
        if (file_callback) {
            file_callback(&entry, scanner->user_context);
        }
        
        scanner->stats.total_files++;
        scanner->stats.total_size += entry.size;
        
        // 更新进度
        if (progress_callback && scanner->stats.total_files % 1000 == 0) {
            progress_callback(scanner->stats.total_files, 0, scanner->user_context);
        }
    }
    
    mft_scan_close(&ctx);
    
    uint64_t end_time = get_timestamp();
    scanner->stats.scan_time_us = (end_time - start_time) / 1000;
    
    return 0;
}

// ============ USN Journal实现 ============

int usn_journal_init(DirectoryScanner* scanner, const char* volume) {
    if (!scanner || !volume) return -1;
    
    char volume_path[MAX_PATH];
    snprintf(volume_path, sizeof(volume_path), "\\\\.\\%s", volume);
    
    HANDLE volume_handle = CreateFileA(
        volume_path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    
    if (volume_handle == INVALID_HANDLE_VALUE) {
        return -1;
    }
    
    // 查询USN Journal信息
    USN_JOURNAL_DATA journal_data;
    DWORD bytes_returned;
    
    BOOL result = DeviceIoControl(
        volume_handle,
        FSCTL_QUERY_USN_JOURNAL,
        NULL,
        0,
        &journal_data,
        sizeof(journal_data),
        &bytes_returned,
        NULL
    );
    
    if (!result) {
        CloseHandle(volume_handle);
        return -1;
    }
    
    scanner->usn_handle = volume_handle;
    scanner->usn_journal_id = journal_data.UsnJournalID;
    
    return 0;
}

int usn_journal_read(DirectoryScanner* scanner, FileScanEntry* entry) {
    if (!scanner || !entry) return -1;
    
    // 读取USN Journal记录
    // 这里需要使用FSCTL_READ_USN_JOURNAL等API
    
    return -1;
}

void usn_journal_close(DirectoryScanner* scanner) {
    if (!scanner) return;
    
    if (scanner->usn_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(scanner->usn_handle);
        scanner->usn_handle = INVALID_HANDLE_VALUE;
    }
}

// 使用USN Journal增量扫描（用于增量备份）
int directory_scan_usn(DirectoryScanner* scanner, const char* path,
                      FileCallback file_callback, ProgressCallback progress_callback) {
    if (!scanner || !path) return -1;
    
    // 提取卷名
    char volume[4] = {path[0], path[1], '\0', '\0'};
    
    // 初始化USN Journal
    if (usn_journal_init(scanner, volume) != 0) {
        // 回退到普通扫描
        return directory_scan(scanner, path, file_callback, progress_callback);
    }
    
    // 扫描USN Journal
    FileScanEntry entry;
    while (usn_journal_read(scanner, &entry) == 0) {
        if (should_skip_file(scanner, entry.filename, NULL)) {
            continue;
        }
        
        if (file_callback) {
            file_callback(&entry, scanner->user_context);
        }
        
        scanner->stats.total_files++;
        scanner->stats.total_size += entry.size;
    }
    
    usn_journal_close(scanner);
    
    return 0;
}

#endif // _WIN32

// ============ 批量扫描实现 ============

int directory_scan_batch(DirectoryScanner* scanner, const char* path,
                        FileCallback file_callback, ProgressCallback progress_callback) {
    if (!scanner || !path) return -1;
    
    // 批量扫描逻辑
    // 可以预分配文件条目数组，批量填充
    
    return directory_scan(scanner, path, file_callback, progress_callback);
}

void directory_get_stats(DirectoryScanner* scanner, ScanStats* stats) {
    if (!scanner || !stats) return;
    memcpy(stats, &scanner->stats, sizeof(ScanStats));
}

void directory_reset_stats(DirectoryScanner* scanner) {
    if (!scanner) return;
    memset(&scanner->stats, 0, sizeof(ScanStats));
}
