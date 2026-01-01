#ifndef DIRECTORY_SCAN_H
#define DIRECTORY_SCAN_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 文件条目（用于目录扫描）
typedef struct {
    uint64_t file_id;         // 文件ID
    uint64_t file_index;      // 文件索引（MFT文件记录号）
    char filename[512];       // 文件名
    char path[1024];          // 完整路径
    uint64_t size;            // 文件大小
    uint64_t create_time;     // 创建时间
    uint64_t modify_time;     // 修改时间
    uint64_t access_time;     // 访问时间
    uint32_t attributes;      // 文件属性
    uint64_t file_reference;  // 文件引用号（NTFS）
} FileScanEntry;

// 目录扫描配置
typedef struct {
    int follow_symlinks;      // 是否跟踪符号链接
    int skip_hidden;          // 是否跳过隐藏文件
    int skip_system;          // 是否跳过系统文件
    uint64_t min_size;        // 最小文件大小过滤
    uint64_t max_size;        // 最大文件大小过滤
    char* include_pattern;    // 包含模式（正则表达式）
    char* exclude_pattern;    // 排除模式（正则表达式）
    int use_mft_scan;         // 是否使用MFT直接扫描（仅NTFS）
    int use_usn_journal;      // 是否使用USN Journal（仅NTFS）
    uint32_t batch_size;      // 批量读取大小
} ScanConfig;

// 目录扫描统计
typedef struct {
    uint64_t total_files;      // 总文件数
    uint64_t total_dirs;       // 总目录数
    uint64_t total_size;       // 总大小
    uint64_t scan_time_us;      // 扫描耗时（微秒）
    uint64_t files_per_sec;    // 每秒文件数
    uint64_t bytes_per_sec;    // 每秒字节数
} ScanStats;

// 目录扫描器
typedef struct {
    ScanConfig config;         // 扫描配置
    ScanStats stats;           // 统计信息
    int running;               // 运行标志
    void* user_context;        // 用户上下文
    
#ifdef _WIN32
    HANDLE usn_handle;         // USN Journal句柄
    uint64_t usn_journal_id;  // USN Journal ID
#endif
} DirectoryScanner;

// 文件回调函数类型
typedef int (*FileCallback)(FileScanEntry* entry, void* context);
typedef int (*ProgressCallback)(uint64_t current, uint64_t total, void* context);

// 初始化目录扫描器
DirectoryScanner* directory_scanner_create(const ScanConfig* config);

// 销毁目录扫描器
void directory_scanner_destroy(DirectoryScanner* scanner);

// 扫描目录
int directory_scan(DirectoryScanner* scanner, const char* path,
                   FileCallback file_callback, ProgressCallback progress_callback);

// 使用MFT直接扫描（Windows NTFS优化）
int directory_scan_mft(DirectoryScanner* scanner, const char* path,
                       FileCallback file_callback, ProgressCallback progress_callback);

// 使用USN Journal增量扫描（Windows NTFS优化）
int directory_scan_usn(DirectoryScanner* scanner, const char* path,
                      FileCallback file_callback, ProgressCallback progress_callback);

// 批量扫描目录（优化版）
int directory_scan_batch(DirectoryScanner* scanner, const char* path,
                        FileCallback file_callback, ProgressCallback progress_callback);

// 获取扫描统计信息
void directory_get_stats(DirectoryScanner* scanner, ScanStats* stats);

// 重置统计信息
void directory_reset_stats(DirectoryScanner* scanner);

#ifdef _WIN32
// Windows MFT扫描结构
typedef struct {
    USN_RECORD* usn_record;    // USN记录
    MFT_ENUM_DATA* mft_data;  // MFT枚举数据
    BYTE* buffer;              // 缓冲区
    DWORD buffer_size;         // 缓冲区大小
} MFTScanContext;

// 初始化MFT扫描
int mft_scan_init(MFTScanContext* ctx, const char* volume);

// 执行MFT扫描
int mft_scan_next(MFTScanContext* ctx, FileScanEntry* entry);

// 关闭MFT扫描
void mft_scan_close(MFTScanContext* ctx);

// 初始化USN Journal
int usn_journal_init(DirectoryScanner* scanner, const char* volume);

// 读取USN Journal
int usn_journal_read(DirectoryScanner* scanner, FileScanEntry* entry);

// 关闭USN Journal
void usn_journal_close(DirectoryScanner* scanner);
#endif

#ifdef __cplusplus
}
#endif

#endif // DIRECTORY_SCAN_H
