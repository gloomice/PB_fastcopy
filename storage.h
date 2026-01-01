#ifndef STORAGE_H
#define STORAGE_H

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
    #define STORAGE_API __declspec(dllexport)
#else
    #define STORAGE_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

// 文件元数据结构
typedef struct {
    uint64_t file_id;              // 文件唯一ID
    char path[512];               // 文件路径
    uint64_t size;                // 文件大小
    uint64_t offset;              // 在合并文件中的偏移量
    uint32_t block_id;            // 所属块ID
    uint64_t create_time;         // 创建时间戳
    uint64_t modify_time;         // 修改时间戳
    uint32_t checksum;            // CRC32校验和
    uint32_t flags;               // 标志位（压缩、加密等）
    uint64_t ref_count;           // 引用计数
} FileMetadata;

// 存储块结构
typedef struct {
    uint32_t block_id;            // 块ID
    uint64_t size;                // 块大小
    uint64_t used_size;           // 已使用大小
    uint32_t file_count;          // 包含文件数
    char filename[256];           // 块文件名
    uint64_t create_time;         // 创建时间
} StorageBlock;

// 系统统计信息
typedef struct {
    uint64_t total_files;         // 总文件数
    uint64_t total_blocks;        // 总块数
    uint64_t total_storage;       // 总存储空间
    uint64_t used_storage;        // 已使用存储
    uint64_t cache_hits;          // 缓存命中次数
    uint64_t cache_misses;        // 缓存未命中次数
    uint64_t read_count;          // 读操作次数
    uint64_t write_count;         // 写操作次数
    double avg_read_speed;        // 平均读取速度 (MB/s)
    double avg_write_speed;       // 平均写入速度 (MB/s)
} SystemStats;

// 错误代码
typedef enum {
    STORAGE_SUCCESS = 0,
    STORAGE_ERROR = -1,
    STORAGE_ERROR_NOT_FOUND = -2,
    STORAGE_ERROR_EXISTS = -3,
    STORAGE_ERROR_NO_SPACE = -4,
    STORAGE_ERROR_INVALID_PARAM = -5,
    STORAGE_ERROR_IO = -6,
    STORAGE_ERROR_LOCK = -7,
    STORAGE_ERROR_CHECKSUM = -8
} StorageError;

// 存储句柄
typedef void* StorageHandle;

// 初始化存储系统
STORAGE_API StorageError storage_init(const char* base_path, StorageHandle* handle);

// 关闭存储系统
STORAGE_API StorageError storage_close(StorageHandle handle);

// 写入文件
STORAGE_API StorageError storage_write_file(StorageHandle handle, const char* path,
                                             const void* data, size_t size, uint64_t* file_id);

// 读取文件
STORAGE_API StorageError storage_read_file(StorageHandle handle, uint64_t file_id,
                                            void* buffer, size_t size, size_t* bytes_read);

// 读取文件（按路径）
STORAGE_API StorageError storage_read_file_by_path(StorageHandle handle, const char* path,
                                                     void* buffer, size_t size, size_t* bytes_read);

// 删除文件
STORAGE_API StorageError storage_delete_file(StorageHandle handle, uint64_t file_id);

// 删除文件（按路径）
STORAGE_API StorageError storage_delete_file_by_path(StorageHandle handle, const char* path);

// 查询文件元数据
STORAGE_API StorageError storage_get_metadata(StorageHandle handle, uint64_t file_id,
                                               FileMetadata* metadata);

// 查询文件元数据（按路径）
STORAGE_API StorageError storage_get_metadata_by_path(StorageHandle handle, const char* path,
                                                       FileMetadata* metadata);

// 文件是否存在
STORAGE_API StorageError storage_file_exists(StorageHandle handle, const char* path,
                                               int* exists);

// 列出目录下的文件
STORAGE_API StorageError storage_list_directory(StorageHandle handle, const char* path,
                                                 FileMetadata** files, size_t* count);

// 释放文件列表内存
STORAGE_API void storage_free_list(FileMetadata* files);

// 搜索文件
STORAGE_API StorageError storage_search_files(StorageHandle handle, const char* pattern,
                                               FileMetadata** files, size_t* count);

// 获取系统统计信息
STORAGE_API StorageError storage_get_stats(StorageHandle handle, SystemStats* stats);

// 缓存控制
STORAGE_API StorageError storage_set_cache_size(StorageHandle handle, size_t size);
STORAGE_API StorageError storage_clear_cache(StorageHandle handle);

// 压缩存储
STORAGE_API StorageError storage_compact_storage(StorageHandle handle);

// 创建备份
STORAGE_API StorageError storage_create_backup(StorageHandle handle, const char* backup_path);

// 恢复备份
STORAGE_API StorageError storage_restore_backup(StorageHandle handle, const char* backup_path);

// 开始事务
STORAGE_API StorageError storage_begin_transaction(StorageHandle handle);

// 提交事务
STORAGE_API StorageError storage_commit_transaction(StorageHandle handle);

// 回滚事务
STORAGE_API StorageError storage_rollback_transaction(StorageHandle handle);

// 获取最后错误信息
STORAGE_API const char* storage_get_last_error(StorageHandle handle);

#ifdef __cplusplus
}
#endif

#endif // STORAGE_H
