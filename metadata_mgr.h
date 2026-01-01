#ifndef METADATA_MGR_H
#define METADATA_MGR_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 文件元数据项
typedef struct {
    uint64_t file_id;              // 文件ID
    uint64_t path_hash;            // 路径hash（压缩存储）
    char compressed_path[16];        // 压缩路径（hash或前缀）
    uint64_t size;                // 文件大小
    uint64_t offset;              // 存储偏移
    uint32_t block_id;            // 所属块ID
    uint64_t create_time;         // 创建时间
    uint64_t modify_time;         // 修改时间
    uint64_t access_time;         // 访问时间
    uint32_t attributes;          // 文件属性
    uint32_t checksum;            // CRC32校验
    uint64_t ref_count;           // 引用计数
    
    // 缓存统计
    uint64_t access_count;        // 访问次数
    uint64_t last_access_time;    // 最后访问时间
} MetadataItem;

// 元数据缓存节点（LRU）
typedef struct MetadataCacheNode {
    MetadataItem* item;
    struct MetadataCacheNode* prev;
    struct MetadataCacheNode* next;
} MetadataCacheNode;

// LRU缓存
typedef struct {
    MetadataCacheNode* head;       // 头节点（最近使用）
    MetadataCacheNode* tail;       // 尾节点（最少使用）
    size_t capacity;              // 容量
    size_t size;                 // 当前大小
    
    // Hash表加速查找
    MetadataCacheNode** hash_table;
    size_t hash_size;
    
    // 统计信息
    uint64_t hits;
    uint64_t misses;
    uint64_t evictions;
} LRUCache;

// 元数据管理器
typedef struct {
    MetadataItem** index;          // 主索引（hash表）
    size_t index_size;           // 索引大小
    size_t index_capacity;        // 索引容量
    
    LRUCache* cache;             // LRU缓存
    
    // 批量操作缓冲区
    MetadataItem* batch_buffer;    // 批量缓冲区
    size_t batch_count;           // 批次大小
    size_t batch_capacity;        // 批次容量
    
    // 统计信息
    uint64_t total_items;
    uint64_t total_reads;
    uint64_t total_writes;
    uint64_t batch_operations;
    
    void* user_context;           // 用户上下文
} MetadataManager;

// 初始化元数据管理器
MetadataManager* metadata_manager_init(size_t index_capacity, size_t cache_capacity);

// 销毁元数据管理器
void metadata_manager_destroy(MetadataManager* manager);

// 添加元数据
int metadata_add(MetadataManager* manager, const MetadataItem* item);

// 批量添加元数据
int metadata_add_batch(MetadataManager* manager, MetadataItem* items, size_t count);

// 查找元数据（按ID）
MetadataItem* metadata_find_by_id(MetadataManager* manager, uint64_t file_id);

// 查找元数据（按路径hash）
MetadataItem* metadata_find_by_path(MetadataManager* manager, uint64_t path_hash);

// 批量查找元数据
int metadata_find_batch(MetadataManager* manager, uint64_t* file_ids, 
                      MetadataItem** results, size_t count);

// 更新元数据
int metadata_update(MetadataManager* manager, const MetadataItem* item);

// 批量更新元数据
int metadata_update_batch(MetadataManager* manager, MetadataItem* items, size_t count);

// 删除元数据
int metadata_remove(MetadataManager* manager, uint64_t file_id);

// 刷新批量操作缓冲区
int metadata_flush_batch(MetadataManager* manager);

// 清空缓存
void metadata_clear_cache(MetadataManager* manager);

// 获取缓存统计信息
void metadata_get_cache_stats(MetadataManager* manager, 
                             uint64_t* hits, uint64_t* misses, uint64_t* evictions);

// 获取管理器统计信息
void metadata_get_stats(MetadataManager* manager, char* buffer, size_t buffer_size);

// 重置统计信息
void metadata_reset_stats(MetadataManager* manager);

// 增量同步准备
int metadata_prepare_incremental(MetadataManager* manager, uint64_t since_time);

// 获取增量变更
int metadata_get_incremental(MetadataManager* manager, MetadataItem** changes, 
                             size_t* count, uint64_t* since_time);

// 保存元数据到磁盘
int metadata_save(MetadataManager* manager, const char* filename);

// 从磁盘加载元数据
int metadata_load(MetadataManager* manager, const char* filename);

#ifdef __cplusplus
}
#endif

#endif // METADATA_MGR_H
