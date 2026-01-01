#include "mem_pool_advanced.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdalign.h>

#ifdef _WIN32
#include <malloc.h>
#define aligned_alloc(alignment, size) _aligned_malloc(size, alignment)
#define aligned_free _aligned_free
#else
#include <stdlib.h>
#define aligned_free free
#endif

// 四级Slab配置
#define SLAB_TINY_OBJECT_SIZE    64        // 64B
#define SLAB_TINY_BLOCK_SIZE     65536     // 64KB每块
#define SLAB_TINY_OBJECTS_PER_BLOCK  1024

#define SLAB_SMALL_OBJECT_SIZE   4096      // 4KB
#define SLAB_SMALL_BLOCK_SIZE    1048576   // 1MB每块
#define SLAB_SMALL_OBJECTS_PER_BLOCK  256

#define SLAB_MEDIUM_OBJECT_SIZE  65536     // 64KB
#define SLAB_MEDIUM_BLOCK_SIZE   16777216  // 16MB每块
#define SLAB_MEDIUM_OBJECTS_PER_BLOCK  256

#define SLAB_LARGE_OBJECT_SIZE   262144    // 256KB
#define SLAB_LARGE_BLOCK_SIZE    67108864  // 64MB每块
#define SLAB_LARGE_OBJECTS_PER_BLOCK  256

#define DEFAULT_POOL_SIZE (4ULL * 1024 * 1024 * 1024) // 4GB默认预分配

// 线程本地存储键
static pthread_key_t tls_cache_key;
static int tls_key_initialized = 0;

// ============ Slab块管理 ============

static SlabBlock* slab_block_create(size_t object_size, size_t block_size, size_t objects_per_block) {
    SlabBlock* block = (SlabBlock*)calloc(1, sizeof(SlabBlock));
    if (!block) return NULL;
    
    // 分配内存块
    block->memory = aligned_alloc(64, block_size);
    if (!block->memory) {
        free(block);
        return NULL;
    }
    
    // 初始化位图
    size_t bitmap_size = (objects_per_block + 63) / 64;
    block->bitmap = (uint64_t*)calloc(bitmap_size, sizeof(uint64_t));
    if (!block->bitmap) {
        free(block->memory);
        free(block);
        return NULL;
    }
    
    block->block_size = block_size;
    block->object_size = object_size;
    block->object_count = objects_per_block;
    block->used_count = 0;
    block->bitmap_size = bitmap_size;
    block->state = SLAB_EMPTY;
    block->next = NULL;
    block->ref_count = 0;
    block->zero_copy = 0;
    
    return block;
}

static void slab_block_destroy(SlabBlock* block) {
    if (!block) return;
    
    if (block->memory) {
        free(block->memory);
    }
    
    if (block->bitmap) {
        free(block->bitmap);
    }
    
    free(block);
}

// ============ 线程本地缓存 ============

ThreadCache* thread_cache_create(uint32_t thread_id) {
    ThreadCache* cache = (ThreadCache*)calloc(1, sizeof(ThreadCache));
    if (!cache) return NULL;
    
    memset(cache->tiny_cache, 0, sizeof(cache->tiny_cache));
    memset(cache->small_cache, 0, sizeof(cache->small_cache));
    memset(cache->medium_cache, 0, sizeof(cache->medium_cache));
    memset(cache->large_cache, 0, sizeof(cache->large_cache));
    
    cache->alloc_count = 0;
    cache->free_count = 0;
    cache->cross_allocs = 0;
    
    pthread_mutex_init(&cache->cache_mutex, NULL);
    
    return cache;
}

void thread_cache_destroy(ThreadCache* cache) {
    if (!cache) return;
    
    pthread_mutex_destroy(&cache->cache_mutex);
    free(cache);
}

// ============ 位图操作 ============

static void bitmap_set(uint64_t* bitmap, size_t index) {
    bitmap[index / 64] |= (1ULL << (index % 64));
}

static void bitmap_clear(uint64_t* bitmap, size_t index) {
    bitmap[index / 64] &= ~(1ULL << (index % 64));
}

static int bitmap_test(uint64_t* bitmap, size_t index) {
    return (bitmap[index / 64] & (1ULL << (index % 64))) != 0;
}

static int bitmap_find_free(uint64_t* bitmap, size_t bitmap_size) {
    for (size_t i = 0; i < bitmap_size; i++) {
        if (bitmap[i] != 0xFFFFFFFFFFFFFFFFULL) {
            for (int j = 0; j < 64; j++) {
                if ((bitmap[i] & (1ULL << j)) == 0) {
                    return i * 64 + j;
                }
            }
        }
    }
    return -1;
}

// ============ 四级Slab分配器 ============

static SlabAllocator* slab_allocator_create_advanced(size_t object_size, size_t block_size, 
                                                  size_t objects_per_block, uint32_t thread_count) {
    SlabAllocator* allocator = (SlabAllocator*)calloc(1, sizeof(SlabAllocator));
    if (!allocator) return NULL;
    
    allocator->object_size = object_size;
    allocator->block_size = block_size;
    allocator->objects_per_block = objects_per_block;
    allocator->full_list = NULL;
    allocator->partial_list = NULL;
    allocator->empty_list = NULL;
    allocator->thread_count = thread_count;
    allocator->next_thread_id = 0;
    
    // 初始化线程本地缓存
    allocator->thread_caches = (ThreadCache**)calloc(thread_count, sizeof(ThreadCache*));
    if (!allocator->thread_caches) {
        free(allocator);
        return NULL;
    }
    
    for (uint32_t i = 0; i < thread_count; i++) {
        allocator->thread_caches[i] = thread_cache_create(i);
        if (!allocator->thread_caches[i]) {
            slab_allocator_destroy_advanced(allocator);
            return NULL;
        }
    }
    
    pthread_mutex_init(&allocator->mutex, NULL);
    pthread_mutex_init(&allocator->thread_cache_mutex, NULL);
    
    return allocator;
}

static void slab_allocator_destroy_advanced(SlabAllocator* allocator) {
    if (!allocator) return;
    
    // 释放所有块
    SlabBlock* block = allocator->full_list;
    while (block) {
        SlabBlock* next = block->next;
        slab_block_destroy(block);
        block = next;
    }
    
    block = allocator->partial_list;
    while (block) {
        SlabBlock* next = block->next;
        slab_block_destroy(block);
        block = next;
    }
    
    block = allocator->empty_list;
    while (block) {
        SlabBlock* next = block->next;
        slab_block_destroy(block);
        block = next;
    }
    
    // 释放线程本地缓存
    if (allocator->thread_caches) {
        for (uint32_t i = 0; i < allocator->thread_count; i++) {
            if (allocator->thread_caches[i]) {
                thread_cache_destroy(allocator->thread_caches[i]);
            }
        }
        free(allocator->thread_caches);
    }
    
    pthread_mutex_destroy(&allocator->mutex);
    pthread_mutex_destroy(&allocator->thread_cache_mutex);
    free(allocator);
}

// 从Slab分配器分配对象
static void* slab_alloc_advanced(SlabAllocator* allocator) {
    SlabBlock* block = NULL;
    
    pthread_mutex_lock(&allocator->mutex);
    
    // 优先从部分使用块分配
    if (allocator->partial_list) {
        block = allocator->partial_list;
    } else if (allocator->empty_list) {
        // 从空闲块移动到部分使用列表
        block = allocator->empty_list;
        allocator->empty_list = block->next;
        block->next = allocator->partial_list;
        allocator->partial_list = block;
    } else {
        // 创建新块
        block = slab_block_create(allocator->object_size,
                                   allocator->block_size,
                                   allocator->objects_per_block);
        if (!block) {
            pthread_mutex_unlock(&allocator->mutex);
            return NULL;
        }
        
        allocator->total_blocks++;
        block->next = allocator->partial_list;
        allocator->partial_list = block;
    }
    
    // 在块中分配对象
    int free_index = bitmap_find_free(block->bitmap, block->bitmap_size);
    if (free_index < 0) {
        pthread_mutex_unlock(&allocator->mutex);
        return NULL;
    }
    
    bitmap_set(block->bitmap, free_index);
    block->used_count++;
    
    // 更新块状态
    if (block->used_count == block->object_count) {
        // 块满了，移动到满列表
        if (block == allocator->partial_list) {
            allocator->partial_list = block->next;
        } else {
            SlabBlock* prev = allocator->partial_list;
            while (prev && prev->next != block) {
                prev = prev->next;
            }
            if (prev) {
                prev->next = block->next;
            }
        }
        block->state = SLAB_FULL;
        block->next = allocator->full_list;
        allocator->full_list = block;
    } else {
        block->state = SLAB_PARTIAL;
    }
    
    // 更新统计
    allocator->total_allocs++;
    allocator->current_objects++;
    if (allocator->current_objects > allocator->peak_objects) {
        allocator->peak_objects = allocator->current_objects;
    }
    
    pthread_mutex_unlock(&allocator->mutex);
    
    // 计算对象地址
    void* ptr = (uint8_t*)block->memory + free_index * allocator->object_size;
    return ptr;
}

// ============ 全局内存池管理器（四级）============

MemoryPoolManager* memory_pool_init_advanced(size_t total_size, uint32_t thread_count) {
    if (total_size == 0) {
        total_size = DEFAULT_POOL_SIZE;
    }
    
    MemoryPoolManager* manager = (MemoryPoolManager*)calloc(1, sizeof(MemoryPoolManager));
    if (!manager) return NULL;
    
    // 创建四个Slab分配器
    manager->slab_tiny = slab_allocator_create_advanced(SLAB_TINY_OBJECT_SIZE,
                                                     SLAB_TINY_BLOCK_SIZE,
                                                     SLAB_TINY_OBJECTS_PER_BLOCK,
                                                     thread_count);
    manager->slab_small = slab_allocator_create_advanced(SLAB_SMALL_OBJECT_SIZE,
                                                      SLAB_SMALL_BLOCK_SIZE,
                                                      SLAB_SMALL_OBJECTS_PER_BLOCK,
                                                      thread_count);
    manager->slab_medium = slab_allocator_create_advanced(SLAB_MEDIUM_OBJECT_SIZE,
                                                       SLAB_MEDIUM_BLOCK_SIZE,
                                                       SLAB_MEDIUM_OBJECTS_PER_BLOCK,
                                                       thread_count);
    manager->slab_large = slab_allocator_create_advanced(SLAB_LARGE_OBJECT_SIZE,
                                                      SLAB_LARGE_BLOCK_SIZE,
                                                      SLAB_LARGE_OBJECTS_PER_BLOCK,
                                                      thread_count);
    
    if (!manager->slab_tiny || !manager->slab_small || 
        !manager->slab_medium || !manager->slab_large) {
        memory_pool_destroy_advanced(manager);
        return NULL;
    }
    
    manager->total_memory = total_size;
    manager->used_memory = 0;
    manager->peak_memory = 0;
    manager->memory_size = total_size;
    manager->memory_offset = 0;
    manager->zero_copy_enabled = 1;
    
    pthread_mutex_init(&manager->global_mutex, NULL);
    
    return manager;
}

void memory_pool_destroy_advanced(MemoryPoolManager* manager) {
    if (!manager) return;
    
    slab_allocator_destroy_advanced(manager->slab_tiny);
    slab_allocator_destroy_advanced(manager->slab_small);
    slab_allocator_destroy_advanced(manager->slab_medium);
    slab_allocator_destroy_advanced(manager->slab_large);
    
    if (manager->memory_base) {
        free(manager->memory_base);
    }
    
    pthread_mutex_destroy(&manager->global_mutex);
    free(manager);
}

void* pool_alloc_advanced(MemoryPoolManager* manager, size_t size) {
    if (!manager) return NULL;
    
    pthread_mutex_lock(&manager->global_mutex);
    
    SlabAllocator* allocator = NULL;
    
    // 根据大小选择分配器（四级）
    if (size <= SLAB_TINY_OBJECT_SIZE) {
        allocator = manager->slab_tiny;
    } else if (size <= SLAB_SMALL_OBJECT_SIZE) {
        allocator = manager->slab_small;
    } else if (size <= SLAB_MEDIUM_OBJECT_SIZE) {
        allocator = manager->slab_medium;
    } else if (size <= SLAB_LARGE_OBJECT_SIZE) {
        allocator = manager->slab_large;
    } else {
        // 超出Slab范围，直接分配
        pthread_mutex_unlock(&manager->global_mutex);
        return malloc(size);
    }
    
    pthread_mutex_unlock(&manager->global_mutex);
    
    // 从Slab分配器分配
    void* ptr = slab_alloc_advanced(allocator);
    
    pthread_mutex_lock(&manager->global_mutex);
    if (ptr) {
        manager->used_memory += allocator->object_size;
        if (manager->used_memory > manager->peak_memory) {
            manager->peak_memory = manager->used_memory;
        }
        allocator->cache_hits++;
    } else {
        allocator->cache_misses++;
    }
    pthread_mutex_unlock(&manager->global_mutex);
    
    return ptr;
}

void pool_free_advanced(MemoryPoolManager* manager, void* ptr) {
    if (!manager || !ptr) return;
    
    // 简化实现：暂不实现释放
    // 实际实现需要追踪指针所属的分配器
}

void pool_get_stats_advanced(MemoryPoolManager* manager, char* buffer, size_t buffer_size) {
    if (!manager || !buffer) return;
    
    pthread_mutex_lock(&manager->global_mutex);
    
    snprintf(buffer, buffer_size,
        "Advanced Memory Pool Statistics (4-Tier Slab):\n"
        "  Total Memory: %llu MB\n"
        "  Used Memory: %llu MB\n"
        "  Peak Memory: %llu MB\n"
        "\n"
        "TINY Slab (64B):\n"
        "  Total Allocs: %llu\n"
        "  Current Objects: %llu\n"
        "  Peak Objects: %llu\n"
        "  Total Blocks: %llu\n"
        "  Cache Hits: %llu\n"
        "  Cache Misses: %llu\n"
        "\n"
        "SMALL Slab (4KB):\n"
        "  Total Allocs: %llu\n"
        "  Current Objects: %llu\n"
        "  Peak Objects: %llu\n"
        "  Total Blocks: %llu\n"
        "  Cache Hits: %llu\n"
        "  Cache Misses: %llu\n"
        "\n"
        "MEDIUM Slab (64KB):\n"
        "  Total Allocs: %llu\n"
        "  Current Objects: %llu\n"
        "  Peak Objects: %llu\n"
        "  Total Blocks: %llu\n"
        "  Cache Hits: %llu\n"
        "  Cache Misses: %llu\n"
        "\n"
        "LARGE Slab (256KB):\n"
        "  Total Allocs: %llu\n"
        "  Current Objects: %llu\n"
        "  Peak Objects: %llu\n"
        "  Total Blocks: %llu\n"
        "  Cache Hits: %llu\n"
        "  Cache Misses: %llu\n",
        (unsigned long long)(manager->total_memory / (1024 * 1024)),
        (unsigned long long)(manager->used_memory / (1024 * 1024)),
        (unsigned long long)(manager->peak_memory / (1024 * 1024)),
        (unsigned long long)manager->slab_tiny->total_allocs,
        (unsigned long long)manager->slab_tiny->current_objects,
        (unsigned long long)manager->slab_tiny->peak_objects,
        (unsigned long long)manager->slab_tiny->total_blocks,
        (unsigned long long)manager->slab_tiny->cache_hits,
        (unsigned long long)manager->slab_tiny->cache_misses,
        (unsigned long long)manager->slab_small->total_allocs,
        (unsigned long long)manager->slab_small->current_objects,
        (unsigned long long)manager->slab_small->peak_objects,
        (unsigned long long)manager->slab_small->total_blocks,
        (unsigned long long)manager->slab_small->cache_hits,
        (unsigned long long)manager->slab_small->cache_misses,
        (unsigned long long)manager->slab_medium->total_allocs,
        (unsigned long long)manager->slab_medium->current_objects,
        (unsigned long long)manager->slab_medium->peak_objects,
        (unsigned long long)manager->slab_medium->total_blocks,
        (unsigned long long)manager->slab_medium->cache_hits,
        (unsigned long long)manager->slab_medium->cache_misses,
        (unsigned long long)manager->slab_large->total_allocs,
        (unsigned long long)manager->slab_large->current_objects,
        (unsigned long long)manager->slab_large->peak_objects,
        (unsigned long long)manager->slab_large->total_blocks,
        (unsigned long long)manager->slab_large->cache_hits,
        (unsigned long long)manager->slab_large->cache_misses
    );
    
    pthread_mutex_unlock(&manager->global_mutex);
}

void pool_reset_advanced(MemoryPoolManager* manager) {
    if (!manager) return;
    
    pthread_mutex_lock(&manager->global_mutex);
    
    // 重建Slab分配器
    uint32_t thread_count = manager->slab_tiny->thread_count;
    
    slab_allocator_destroy_advanced(manager->slab_tiny);
    slab_allocator_destroy_advanced(manager->slab_small);
    slab_allocator_destroy_advanced(manager->slab_medium);
    slab_allocator_destroy_advanced(manager->slab_large);
    
    manager->slab_tiny = slab_allocator_create_advanced(SLAB_TINY_OBJECT_SIZE,
                                                         SLAB_TINY_BLOCK_SIZE,
                                                         SLAB_TINY_OBJECTS_PER_BLOCK,
                                                         thread_count);
    manager->slab_small = slab_allocator_create_advanced(SLAB_SMALL_OBJECT_SIZE,
                                                          SLAB_SMALL_BLOCK_SIZE,
                                                          SLAB_SMALL_OBJECTS_PER_BLOCK,
                                                          thread_count);
    manager->slab_medium = slab_allocator_create_advanced(SLAB_MEDIUM_OBJECT_SIZE,
                                                           SLAB_MEDIUM_BLOCK_SIZE,
                                                           SLAB_MEDIUM_OBJECTS_PER_BLOCK,
                                                           thread_count);
    manager->slab_large = slab_allocator_create_advanced(SLAB_LARGE_OBJECT_SIZE,
                                                          SLAB_LARGE_BLOCK_SIZE,
                                                          SLAB_LARGE_OBJECTS_PER_BLOCK,
                                                          thread_count);
    
    manager->used_memory = 0;
    
    pthread_mutex_unlock(&manager->global_mutex);
}

void* pool_alloc_aligned_advanced(MemoryPoolManager* manager, size_t size, size_t alignment) {
    // 简化实现：先分配更大的空间，然后对齐
    size_t total_size = size + alignment - 1;
    void* raw_ptr = pool_alloc_advanced(manager, total_size);
    if (!raw_ptr) return NULL;
    
    uintptr_t ptr = (uintptr_t)raw_ptr;
    uintptr_t aligned_ptr = (ptr + alignment - 1) & ~(alignment - 1);
    
    return (void*)aligned_ptr;
}

int pool_preallocate_advanced(MemoryPoolManager* manager, SlabType type, size_t count) {
    if (!manager) return -1;
    
    pthread_mutex_lock(&manager->global_mutex);
    
    SlabAllocator* allocator = NULL;
    switch (type) {
        case SLAB_TINY:   allocator = manager->slab_tiny; break;
        case SLAB_SMALL:  allocator = manager->slab_small; break;
        case SLAB_MEDIUM:  allocator = manager->slab_medium; break;
        case SLAB_LARGE:  allocator = manager->slab_large; break;
    }
    
    if (!allocator) {
        pthread_mutex_unlock(&manager->global_mutex);
        return -1;
    }
    
    // 计算需要的块数
    size_t blocks_needed = (count + allocator->objects_per_block - 1) / allocator->objects_per_block;
    
    // 创建块
    for (size_t i = 0; i < blocks_needed; i++) {
        SlabBlock* block = slab_block_create(allocator->object_size,
                                              allocator->block_size,
                                              allocator->objects_per_block);
        if (!block) {
            pthread_mutex_unlock(&manager->global_mutex);
            return -1;
        }
        
        block->next = allocator->empty_list;
        allocator->empty_list = block;
        allocator->total_blocks++;
    }
    
    pthread_mutex_unlock(&manager->global_mutex);
    return 0;
}

void* pool_alloc_zero_copy(MemoryPoolManager* manager, size_t size) {
    if (!manager || !manager->zero_copy_enabled) {
        return pool_alloc_advanced(manager, size);
    }
    
    // 分配并设置零拷贝标志
    void* ptr = pool_alloc_advanced(manager, size);
    if (!ptr) return NULL;
    
    // 这里需要找到对应的SlabBlock并设置ref_count
    // 简化实现：仅返回指针
    
    return ptr;
}

int pool_free_zero_copy(MemoryPoolManager* manager, void* ptr) {
    if (!manager || !ptr) return -1;
    
    // 减少引用计数，如果为0则真正释放
    // 简化实现：暂不实现
    
    return 0;
}

uint32_t pool_get_ref_count(MemoryPoolManager* manager, void* ptr) {
    if (!manager || !ptr) return 0;
    
    // 简化实现：返回固定值
    return 1;
}
