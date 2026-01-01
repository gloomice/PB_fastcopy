#ifndef MEM_POOL_ADVANCED_H
#define MEM_POOL_ADVANCED_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

// 四级Slab分配器类型
typedef enum {
    SLAB_TINY = 0,    // 64B-1KB，用于元数据、哈希表节点
    SLAB_SMALL = 1,   // 1KB-16KB，用于小文件路径、索引项
    SLAB_MEDIUM = 2,   // 16KB-256KB，用于中等文件数据
    SLAB_LARGE = 3     // 256KB-4MB，用于大文件预读块
} SlabType;

// 线程本地缓存（减少锁竞争）
typedef struct {
    SlabBlock* tiny_cache[8];    // 小对象缓存
    SlabBlock* small_cache[8];   // 中等对象缓存
    SlabBlock* medium_cache[8];  // 大对象缓存
    SlabBlock* large_cache[8];   // 超大对象缓存
    
    uint64_t alloc_count;        // 本地分配次数
    uint64_t free_count;         // 本地释放次数
    uint64_t cross_allocs;       // 跨线程分配次数
    
    pthread_mutex_t cache_mutex;  // 缓存锁
} ThreadCache;

// Slab块状态
typedef enum {
    SLAB_FULL = 0,    // 已满
    SLAB_PARTIAL = 1, // 部分使用
    SLAB_EMPTY = 2    // 空闲
} SlabState;

// Slab块
typedef struct SlabBlock {
    void* memory;              // 内存块地址
    size_t block_size;         // 块大小
    size_t object_size;       // 对象大小
    size_t object_count;      // 对象总数
    size_t used_count;         // 已使用对象数
    uint64_t* bitmap;         // 位图，标记已分配对象
    size_t bitmap_size;       // 位图大小（字数）
    SlabState state;          // 块状态
    struct SlabBlock* next;   // 下一个块（用于链表）
    
    // 零拷贝支持
    uint32_t ref_count;       // 引用计数
    int zero_copy;            // 是否零拷贝
} SlabBlock;

// Slab分配器
typedef struct SlabAllocator {
    SlabBlock* full_list;     // 已满块列表
    SlabBlock* partial_list;  // 部分使用块列表
    SlabBlock* empty_list;    // 空闲块列表
    
    size_t object_size;       // 对象大小
    size_t block_size;        // 块大小
    size_t objects_per_block; // 每块对象数
    
    // 线程本地缓存数组
    ThreadCache** thread_caches;
    uint32_t thread_count;
    uint32_t next_thread_id;
    pthread_mutex_t thread_cache_mutex;
    
    // 统计信息
    uint64_t total_allocs;
    uint64_t total_frees;
    uint64_t current_objects;
    uint64_t peak_objects;
    uint64_t total_blocks;
    uint64_t cache_hits;
    uint64_t cache_misses;
    
    pthread_mutex_t mutex;    // 分配器锁
} SlabAllocator;

// 全局内存池管理器
typedef struct {
    SlabAllocator* slab_tiny;    // 超小对象分配器
    SlabAllocator* slab_small;   // 小对象分配器
    SlabAllocator* slab_medium;   // 中等对象分配器
    SlabAllocator* slab_large;   // 大对象分配器
    
    size_t total_memory;         // 总内存
    size_t used_memory;          // 已用内存
    size_t peak_memory;          // 峰值内存
    
    uint8_t* memory_base;        // 内存基址（大块预分配）
    size_t memory_size;          // 预分配内存总大小
    size_t memory_offset;        // 当前偏移
    
    pthread_mutex_t global_mutex; // 全局锁
    
    // 零拷贝支持
    int zero_copy_enabled;       // 启用零拷贝
} MemoryPoolManager;

// 初始化全局内存池（批量预分配）
MemoryPoolManager* memory_pool_init_advanced(size_t total_size, uint32_t thread_count);

// 销毁内存池
void memory_pool_destroy_advanced(MemoryPoolManager* manager);

// 从内存池分配内存（零碎片策略）
void* pool_alloc_advanced(MemoryPoolManager* manager, size_t size);

// 释放内存到池
void pool_free_advanced(MemoryPoolManager* manager, void* ptr);

// 获取统计信息
void pool_get_stats_advanced(MemoryPoolManager* manager, char* buffer, size_t buffer_size);

// 重置内存池（清空所有分配）
void pool_reset_advanced(MemoryPoolManager* manager);

// 对齐分配
void* pool_alloc_aligned_advanced(MemoryPoolManager* manager, size_t size, size_t alignment);

// 批量预分配特定类型内存
int pool_preallocate_advanced(MemoryPoolManager* manager, SlabType type, size_t count);

// 初始化线程本地缓存
ThreadCache* thread_cache_create(uint32_t thread_id);

// 销毁线程本地缓存
void thread_cache_destroy(ThreadCache* cache);

// 从线程本地缓存分配
void* thread_cache_alloc(ThreadCache* cache, size_t size);

// 释放到线程本地缓存
void thread_cache_free(ThreadCache* cache, void* ptr);

// 零拷贝分配（增加引用计数）
void* pool_alloc_zero_copy(MemoryPoolManager* manager, size_t size);

// 零拷贝释放（减少引用计数）
int pool_free_zero_copy(MemoryPoolManager* manager, void* ptr);

// 获取对象引用计数
uint32_t pool_get_ref_count(MemoryPoolManager* manager, void* ptr);

#ifdef __cplusplus
}
#endif

#endif // MEM_POOL_ADVANCED_H
