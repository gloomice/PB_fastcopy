#include "metadata_mgr.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define DEFAULT_INDEX_CAPACITY 1048576  // 1M容量
#define DEFAULT_CACHE_CAPACITY 1024       // 1K缓存
#define DEFAULT_BATCH_CAPACITY 256         // 256批量
#define HASH_TABLE_SIZE 65536          // 64K桶

// ============ LRU缓存实现 ============

static LRUCache* lru_cache_create(size_t capacity) {
    LRUCache* cache = (LRUCache*)calloc(1, sizeof(LRUCache));
    if (!cache) return NULL;
    
    cache->capacity = capacity;
    cache->size = 0;
    cache->head = NULL;
    cache->tail = NULL;
    
    // 创建Hash表
    cache->hash_size = HASH_TABLE_SIZE;
    cache->hash_table = (MetadataCacheNode**)calloc(
        cache->hash_size, sizeof(MetadataCacheNode*)
    );
    if (!cache->hash_table) {
        free(cache);
        return NULL;
    }
    
    cache->hits = 0;
    cache->misses = 0;
    cache->evictions = 0;
    
    return cache;
}

static void lru_cache_destroy(LRUCache* cache) {
    if (!cache) return;
    
    // 释放所有节点
    MetadataCacheNode* node = cache->head;
    while (node) {
        MetadataCacheNode* next = node->next;
        free(node);
        node = next;
    }
    
    if (cache->hash_table) {
        free(cache->hash_table);
    }
    
    free(cache);
}

// Hash函数
static size_t metadata_hash(uint64_t file_id) {
    return (size_t)(file_id % HASH_TABLE_SIZE);
}

// LRU缓存添加
static int lru_cache_add(LRUCache* cache, MetadataItem* item) {
    if (!cache || !item) return -1;
    
    // 检查是否已存在
    size_t hash_idx = metadata_hash(item->file_id);
    MetadataCacheNode* node = cache->hash_table[hash_idx];
    
    while (node) {
        if (node->item->file_id == item->file_id) {
            // 已存在，移动到头
            // 先从当前位置移除
            if (node->prev) {
                node->prev->next = node->next;
            } else {
                cache->head = node->next;
            }
            
            if (node->next) {
                node->next->prev = node->prev;
            } else {
                cache->tail = node->prev;
            }
            
            // 插入到头
            node->prev = NULL;
            node->next = cache->head;
            
            if (cache->head) {
                cache->head->prev = node;
            }
            cache->head = node;
            
            if (!cache->tail) {
                cache->tail = node;
            }
            
            return 0;
        }
        node = node->next;
    }
    
    // 不存在，创建新节点
    node = (MetadataCacheNode*)malloc(sizeof(MetadataCacheNode));
    if (!node) return -1;
    
    node->item = item;
    node->prev = NULL;
    node->next = cache->head;
    
    if (cache->head) {
        cache->head->prev = node;
    }
    cache->head = node;
    
    if (!cache->tail) {
        cache->tail = node;
    }
    
    cache->size++;
    
    // 添加到hash表
    node->next = cache->hash_table[hash_idx];
    cache->hash_table[hash_idx] = node;
    
    // 检查容量，必要时淘汰
    if (cache->size > cache->capacity) {
        if (cache->tail) {
            MetadataCacheNode* to_remove = cache->tail;
            
            // 从hash表移除
            size_t hash = metadata_hash(to_remove->item->file_id);
            MetadataCacheNode** ptr = &cache->hash_table[hash];
            while (*ptr && *ptr != to_remove) {
                ptr = &(*ptr)->next;
            }
            if (*ptr) {
                *ptr = to_remove->next;
            }
            
            // 从链表移除
            cache->tail = to_remove->prev;
            if (cache->tail) {
                cache->tail->next = NULL;
            }
            
            free(to_remove);
            cache->size--;
            cache->evictions++;
        }
    }
    
    return 0;
}

// LRU缓存查找
static MetadataItem* lru_cache_find(LRUCache* cache, uint64_t file_id) {
    if (!cache) return NULL;
    
    size_t hash_idx = metadata_hash(file_id);
    MetadataCacheNode* node = cache->hash_table[hash_idx];
    
    while (node) {
        if (node->item->file_id == file_id) {
            cache->hits++;
            
            // 移动到头
            if (node != cache->head) {
                // 先从当前位置移除
                if (node->prev) {
                    node->prev->next = node->next;
                } else {
                    cache->head = node->next;
                }
                
                if (node->next) {
                    node->next->prev = node->prev;
                } else {
                    cache->tail = node->prev;
                }
                
                // 插入到头
                node->prev = NULL;
                node->next = cache->head;
                
                if (cache->head) {
                    cache->head->prev = node;
                }
                cache->head = node;
                
                if (!cache->tail) {
                    cache->tail = node;
                }
            }
            
            return node->item;
        }
        node = node->next;
    }
    
    cache->misses++;
    return NULL;
}

// ============ 元数据管理器实现 ============

MetadataManager* metadata_manager_init(size_t index_capacity, size_t cache_capacity) {
    MetadataManager* manager = (MetadataManager*)calloc(1, sizeof(MetadataManager));
    if (!manager) return NULL;
    
    if (index_capacity == 0) {
        index_capacity = DEFAULT_INDEX_CAPACITY;
    }
    
    if (cache_capacity == 0) {
        cache_capacity = DEFAULT_CACHE_CAPACITY;
    }
    
    // 创建主索引
    manager->index = (MetadataItem**)calloc(index_capacity, sizeof(MetadataItem*));
    if (!manager->index) {
        free(manager);
        return NULL;
    }
    
    manager->index_size = 0;
    manager->index_capacity = index_capacity;
    
    // 创建LRU缓存
    manager->cache = lru_cache_create(cache_capacity);
    if (!manager->cache) {
        free(manager->index);
        free(manager);
        return NULL;
    }
    
    // 创建批量缓冲区
    manager->batch_buffer = (MetadataItem*)calloc(
        DEFAULT_BATCH_CAPACITY, sizeof(MetadataItem)
    );
    if (!manager->batch_buffer) {
        lru_cache_destroy(manager->cache);
        free(manager->index);
        free(manager);
        return NULL;
    }
    
    manager->batch_count = 0;
    manager->batch_capacity = DEFAULT_BATCH_CAPACITY;
    
    manager->total_items = 0;
    manager->total_reads = 0;
    manager->total_writes = 0;
    manager->batch_operations = 0;
    
    return manager;
}

void metadata_manager_destroy(MetadataManager* manager) {
    if (!manager) return;
    
    // 释放索引
    if (manager->index) {
        free(manager->index);
    }
    
    // 销毁缓存
    if (manager->cache) {
        lru_cache_destroy(manager->cache);
    }
    
    // 释放批量缓冲区
    if (manager->batch_buffer) {
        free(manager->batch_buffer);
    }
    
    free(manager);
}

int metadata_add(MetadataManager* manager, const MetadataItem* item) {
    if (!manager || !item) return -1;
    
    manager->total_reads++;
    
    // 检查索引容量
    if (manager->index_size >= manager->index_capacity) {
        return -2;  // 索引满
    }
    
    size_t hash_idx = metadata_hash(item->file_id);
    
    // 添加到索引
    MetadataItem* new_item = (MetadataItem*)malloc(sizeof(MetadataItem));
    if (!new_item) return -1;
    
    memcpy(new_item, item, sizeof(MetadataItem));
    new_item->ref_count = 1;
    new_item->access_count = 0;
    new_item->last_access_time = get_timestamp();
    
    // 插入到hash表
    new_item->offset = (uint64_t)manager->index[hash_idx];  // 简化：使用offset字段存储next指针
    manager->index[hash_idx] = new_item;
    
    manager->index_size++;
    manager->total_items++;
    manager->total_writes++;
    
    // 添加到缓存
    lru_cache_add(manager->cache, new_item);
    
    return 0;
}

int metadata_add_batch(MetadataManager* manager, MetadataItem* items, size_t count) {
    if (!manager || !items || count == 0) return -1;
    
    manager->batch_operations++;
    
    for (size_t i = 0; i < count; i++) {
        if (metadata_add(manager, &items[i]) != 0) {
            return -1;
        }
    }
    
    return 0;
}

MetadataItem* metadata_find_by_id(MetadataManager* manager, uint64_t file_id) {
    if (!manager) return NULL;
    
    manager->total_reads++;
    
    // 先从缓存查找
    MetadataItem* item = lru_cache_find(manager->cache, file_id);
    if (item) {
        item->access_count++;
        item->last_access_time = get_timestamp();
        return item;
    }
    
    // 从索引查找
    size_t hash_idx = metadata_hash(file_id);
    MetadataItem* curr = manager->index[hash_idx];
    
    while (curr) {
        if (curr->file_id == file_id) {
            // 添加到缓存
            lru_cache_add(manager->cache, curr);
            
            curr->access_count++;
            curr->last_access_time = get_timestamp();
            
            return curr;
        }
        curr = (MetadataItem*)curr->offset;  // 获取下一个
    }
    
    return NULL;
}

MetadataItem* metadata_find_by_path(MetadataManager* manager, uint64_t path_hash) {
    // 简化实现：遍历所有item查找path_hash
    if (!manager) return NULL;
    
    for (size_t i = 0; i < manager->index_capacity; i++) {
        MetadataItem* curr = manager->index[i];
        while (curr) {
            if (curr->path_hash == path_hash) {
                return curr;
            }
            curr = (MetadataItem*)curr->offset;
        }
    }
    
    return NULL;
}

int metadata_find_batch(MetadataManager* manager, uint64_t* file_ids,
                      MetadataItem** results, size_t count) {
    if (!manager || !file_ids || !results || count == 0) return -1;
    
    for (size_t i = 0; i < count; i++) {
        results[i] = metadata_find_by_id(manager, file_ids[i]);
    }
    
    return 0;
}

int metadata_update(MetadataManager* manager, const MetadataItem* item) {
    if (!manager || !item) return -1;
    
    MetadataItem* existing = metadata_find_by_id(manager, item->file_id);
    if (!existing) return -2;  // 未找到
    
    // 更新元数据
    memcpy(existing, item, sizeof(MetadataItem));
    existing->ref_count = 1;
    existing->access_count++;
    existing->last_access_time = get_timestamp();
    
    manager->total_writes++;
    
    return 0;
}

int metadata_update_batch(MetadataManager* manager, MetadataItem* items, size_t count) {
    if (!manager || !items || count == 0) return -1;
    
    manager->batch_operations++;
    
    for (size_t i = 0; i < count; i++) {
        if (metadata_update(manager, &items[i]) != 0) {
            return -1;
        }
    }
    
    return 0;
}

int metadata_remove(MetadataManager* manager, uint64_t file_id) {
    if (!manager) return -1;
    
    size_t hash_idx = metadata_hash(file_id);
    MetadataItem* prev = NULL;
    MetadataItem* curr = manager->index[hash_idx];
    
    while (curr) {
        if (curr->file_id == file_id) {
            if (prev) {
                prev->offset = curr->offset;
            } else {
                manager->index[hash_idx] = (MetadataItem*)curr->offset;
            }
            
            free(curr);
            manager->index_size--;
            manager->total_writes++;
            
            return 0;
        }
        prev = curr;
        curr = (MetadataItem*)curr->offset;
    }
    
    return -2;  // 未找到
}

int metadata_flush_batch(MetadataManager* manager) {
    if (!manager) return -1;
    
    // 简化实现：批量缓冲区已在metadata_add_batch中处理
    manager->batch_count = 0;
    
    return 0;
}

void metadata_clear_cache(MetadataManager* manager) {
    if (!manager || !manager->cache) return;
    
    // 重建缓存
    lru_cache_destroy(manager->cache);
    manager->cache = lru_cache_create(DEFAULT_CACHE_CAPACITY);
}

void metadata_get_cache_stats(MetadataManager* manager,
                             uint64_t* hits, uint64_t* misses, uint64_t* evictions) {
    if (!manager || !manager->cache) return;
    
    if (hits) *hits = manager->cache->hits;
    if (misses) *misses = manager->cache->misses;
    if (evictions) *evictions = manager->cache->evictions;
}

void metadata_get_stats(MetadataManager* manager, char* buffer, size_t buffer_size) {
    if (!manager || !buffer) return;
    
    uint64_t hits = 0, misses = 0, evictions = 0;
    metadata_get_cache_stats(manager, &hits, &misses, &evictions);
    
    double hit_rate = (hits + misses) > 0 ? 
        (100.0 * hits) / (hits + misses) : 0.0;
    
    snprintf(buffer, buffer_size,
        "Metadata Manager Statistics:\n"
        "  Total Items: %llu\n"
        "  Total Reads: %llu\n"
        "  Total Writes: %llu\n"
        "  Batch Operations: %llu\n"
        "  Cache Hits: %llu\n"
        "  Cache Misses: %llu\n"
        "  Cache Evictions: %llu\n"
        "  Cache Hit Rate: %.2f%%\n",
        (unsigned long long)manager->total_items,
        (unsigned long long)manager->total_reads,
        (unsigned long long)manager->total_writes,
        (unsigned long long)manager->batch_operations,
        (unsigned long long)hits,
        (unsigned long long)misses,
        (unsigned long long)evictions,
        hit_rate
    );
}

void metadata_reset_stats(MetadataManager* manager) {
    if (!manager) return;
    
    manager->total_reads = 0;
    manager->total_writes = 0;
    manager->batch_operations = 0;
    
    if (manager->cache) {
        manager->cache->hits = 0;
        manager->cache->misses = 0;
        manager->cache->evictions = 0;
    }
}

int metadata_prepare_incremental(MetadataManager* manager, uint64_t since_time) {
    // 简化实现
    return 0;
}

int metadata_get_incremental(MetadataManager* manager, MetadataItem** changes,
                             size_t* count, uint64_t* since_time) {
    // 简化实现
    return 0;
}

int metadata_save(MetadataManager* manager, const char* filename) {
    if (!manager || !filename) return -1;
    
    FILE* fp = fopen(filename, "wb");
    if (!fp) return -1;
    
    // 写入头信息
    fwrite("META", 4, 1, fp);
    
    // 写入统计信息
    fwrite(&manager->total_items, sizeof(uint64_t), 1, fp);
    
    // 写入所有元数据
    for (size_t i = 0; i < manager->index_capacity; i++) {
        MetadataItem* curr = manager->index[i];
        while (curr) {
            fwrite(curr, sizeof(MetadataItem), 1, fp);
            curr = (MetadataItem*)curr->offset;
        }
    }
    
    fclose(fp);
    return 0;
}

int metadata_load(MetadataManager* manager, const char* filename) {
    if (!manager || !filename) return -1;
    
    FILE* fp = fopen(filename, "rb");
    if (!fp) return -1;
    
    // 读取并验证头信息
    char header[4];
    fread(header, 4, 1, fp);
    if (memcmp(header, "META", 4) != 0) {
        fclose(fp);
        return -2;
    }
    
    // 读取统计信息
    uint64_t total_items = 0;
    fread(&total_items, sizeof(uint64_t), 1, fp);
    
    // 读取元数据
    for (uint64_t i = 0; i < total_items; i++) {
        MetadataItem item;
        fread(&item, sizeof(MetadataItem), 1, fp);
        metadata_add(manager, &item);
    }
    
    fclose(fp);
    return 0;
}
