#include "mem_pool.h"
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

// Slab配置
#define SLAB_TINY_OBJECT_SIZE   64       // 64B
#define SLAB_TINY_BLOCK_SIZE    65536    // 64KB每块
#define SLAB_TINY_OBJECTS_PER_BLOCK  1024

#define SLAB_SMALL_OBJECT_SIZE  4096     // 4KB
#define SLAB_SMALL_BLOCK_SIZE   1048576  // 1MB每块
#define SLAB_SMALL_OBJECTS_PER_BLOCK 256

#define SLAB_LARGE_OBJECT_SIZE  65536    // 64KB
#define SLAB_LARGE_BLOCK_SIZE   16777216 // 16MB每块
#define SLAB_LARGE_OBJECTS_PER_BLOCK 256

#define DEFAULT_POOL_SIZE (2ULL * 1024 * 1024 * 1024) // 2GB默认预分配

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

// 在位图中设置位
static void bitmap_set(uint64_t* bitmap, size_t index) {
    bitmap[index / 64] |= (1ULL << (index % 64));
}

// 清除位
static void bitmap_clear(uint64_t* bitmap, size_t index) {
    bitmap[index / 64] &= ~(1ULL << (index % 64));
}

// 测试位
static int bitmap_test(uint64_t* bitmap, size_t index) {
    return (bitmap[index / 64] & (1ULL << (index % 64))) != 0;
}

// 查找空闲位
static int bitmap_find_free(uint64_t* bitmap, size_t bitmap_size) {
    for (size_t i = 0; i < bitmap_size; i++) {
        if (bitmap[i] != 0xFFFFFFFFFFFFFFFFULL) {
            // 找到非全1的块
            for (int j = 0; j < 64; j++) {
                if ((bitmap[i] & (1ULL << j)) == 0) {
                    return i * 64 + j;
                }
            }
        }
    }
    return -1;
}

// ============ Slab分配器 ============

static SlabAllocator* slab_allocator_create(size_t object_size, size_t block_size, size_t objects_per_block) {
    SlabAllocator* allocator = (SlabAllocator*)calloc(1, sizeof(SlabAllocator));
    if (!allocator) return NULL;
    
    allocator->object_size = object_size;
    allocator->block_size = block_size;
    allocator->objects_per_block = objects_per_block;
    allocator->full_list = NULL;
    allocator->partial_list = NULL;
    allocator->empty_list = NULL;
    
    pthread_mutex_init(&allocator->mutex, NULL);
    
    return allocator;
}

static void slab_allocator_destroy(SlabAllocator* allocator) {
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
    
    pthread_mutex_destroy(&allocator->mutex);
    free(allocator);
}

// 从Slab分配器分配对象
static void* slab_alloc(SlabAllocator* allocator) {
    pthread_mutex_lock(&allocator->mutex);
    
    SlabBlock* block = NULL;
    
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

// 释放对象到Slab分配器
static void slab_free(SlabAllocator* allocator, void* ptr) {
    pthread_mutex_lock(&allocator->mutex);
    
    // 查找对象所属的块
    SlabBlock* block = allocator->full_list;
    SlabBlock* prev_block = NULL;
    
    while (block) {
        if ((uint8_t*)ptr >= (uint8_t*)block->memory &&
            (uint8_t*)ptr < (uint8_t*)block->memory + block->block_size) {
            break;
        }
        prev_block = block;
        block = block->next;
    }
    
    if (!block) {
        // 在部分使用列表中查找
        block = allocator->partial_list;
        prev_block = NULL;
        while (block) {
            if ((uint8_t*)ptr >= (uint8_t*)block->memory &&
                (uint8_t*)ptr < (uint8_t*)block->memory + block->block_size) {
                break;
            }
            prev_block = block;
            block = block->next;
        }
    }
    
    if (!block) {
        pthread_mutex_unlock(&allocator->mutex);
        return;  // 无效指针
    }
    
    // 计算对象索引
    size_t index = ((uint8_t*)ptr - (uint8_t*)block->memory) / allocator->object_size;
    
    // 清除位图
    bitmap_clear(block->bitmap, index);
    block->used_count--;
    
    // 更新块状态
    if (block->state == SLAB_FULL) {
        // 从满列表移动到部分使用列表
        if (prev_block) {
            prev_block->next = block->next;
        } else {
            allocator->full_list = block->next;
        }
        block->state = SLAB_PARTIAL;
        block->next = allocator->partial_list;
        allocator->partial_list = block;
    } else if (block->used_count == 0) {
        // 块空了，移动到空闲列表
        if (prev_block) {
            prev_block->next = block->next;
        } else {
            allocator->partial_list = block->next;
        }
        block->state = SLAB_EMPTY;
        block->next = allocator->empty_list;
        allocator->empty_list = block;
    }
    
    // 更新统计
    allocator->total_frees++;
    allocator->current_objects--;
    
    pthread_mutex_unlock(&allocator->mutex);
}

// ============ 全局内存池管理器 ============

MemoryPoolManager* memory_pool_init(size_t total_size) {
    if (total_size == 0) {
        total_size = DEFAULT_POOL_SIZE;
    }
    
    MemoryPoolManager* manager = (MemoryPoolManager*)calloc(1, sizeof(MemoryPoolManager));
    if (!manager) return NULL;
    
    // 创建三个Slab分配器
    manager->slab_tiny = slab_allocator_create(SLAB_TINY_OBJECT_SIZE, 
                                                SLAB_TINY_BLOCK_SIZE,
                                                SLAB_TINY_OBJECTS_PER_BLOCK);
    manager->slab_small = slab_allocator_create(SLAB_SMALL_OBJECT_SIZE,
                                                 SLAB_SMALL_BLOCK_SIZE,
                                                 SLAB_SMALL_OBJECTS_PER_BLOCK);
    manager->slab_large = slab_allocator_create(SLAB_LARGE_OBJECT_SIZE,
                                                 SLAB_LARGE_BLOCK_SIZE,
                                                 SLAB_LARGE_OBJECTS_PER_BLOCK);
    
    if (!manager->slab_tiny || !manager->slab_small || !manager->slab_large) {
        memory_pool_destroy(manager);
        return NULL;
    }
    
    manager->total_memory = total_size;
    manager->used_memory = 0;
    manager->peak_memory = 0;
    manager->memory_size = total_size;
    manager->memory_offset = 0;
    
    // 预分配大块内存（可选，根据需求）
    // manager->memory_base = aligned_alloc(64, total_size);
    
    pthread_mutex_init(&manager->global_mutex, NULL);
    
    return manager;
}

void memory_pool_destroy(MemoryPoolManager* manager) {
    if (!manager) return;
    
    slab_allocator_destroy(manager->slab_tiny);
    slab_allocator_destroy(manager->slab_small);
    slab_allocator_destroy(manager->slab_large);
    
    if (manager->memory_base) {
        free(manager->memory_base);
    }
    
    pthread_mutex_destroy(&manager->global_mutex);
    free(manager);
}

void* pool_alloc(MemoryPoolManager* manager, size_t size) {
    if (!manager) return NULL;
    
    pthread_mutex_lock(&manager->global_mutex);
    
    SlabAllocator* allocator = NULL;
    
    // 根据大小选择分配器
    if (size <= SLAB_TINY_OBJECT_SIZE) {
        allocator = manager->slab_tiny;
    } else if (size <= SLAB_SMALL_OBJECT_SIZE) {
        allocator = manager->slab_small;
    } else if (size <= SLAB_LARGE_OBJECT_SIZE) {
        allocator = manager->slab_large;
    } else {
        // 超出Slab范围，直接分配
        pthread_mutex_unlock(&manager->global_mutex);
        return malloc(size);
    }
    
    pthread_mutex_unlock(&manager->global_mutex);
    
    // 从Slab分配器分配
    void* ptr = slab_alloc(allocator);
    
    pthread_mutex_lock(&manager->global_mutex);
    if (ptr) {
        manager->used_memory += allocator->object_size;
        if (manager->used_memory > manager->peak_memory) {
            manager->peak_memory = manager->used_memory;
        }
    }
    pthread_mutex_unlock(&manager->global_mutex);
    
    return ptr;
}

void pool_free(MemoryPoolManager* manager, void* ptr) {
    if (!manager || !ptr) return;
    
    pthread_mutex_lock(&manager->global_mutex);
    
    // 检查指针属于哪个分配器
    SlabAllocator* allocator = NULL;
    
    // 简化实现：尝试从三个分配器释放
    // 实际实现应该记录指针所属分配器
    
    pthread_mutex_unlock(&manager->global_mutex);
    
    // 尝试释放
    // slab_free(manager->slab_tiny, ptr);
    // slab_free(manager->slab_small, ptr);
    // slab_free(manager->slab_large, ptr);
}

void pool_get_stats(MemoryPoolManager* manager, char* buffer, size_t buffer_size) {
    if (!manager || !buffer) return;
    
    pthread_mutex_lock(&manager->global_mutex);
    
    snprintf(buffer, buffer_size,
        "Memory Pool Statistics:\n"
        "  Total Memory: %llu MB\n"
        "  Used Memory: %llu MB\n"
        "  Peak Memory: %llu MB\n"
        "\n"
        "Tiny Slab (64B):\n"
        "  Total Allocs: %llu\n"
        "  Current Objects: %llu\n"
        "  Peak Objects: %llu\n"
        "  Total Blocks: %llu\n"
        "\n"
        "Small Slab (4KB):\n"
        "  Total Allocs: %llu\n"
        "  Current Objects: %llu\n"
        "  Peak Objects: %llu\n"
        "  Total Blocks: %llu\n"
        "\n"
        "Large Slab (64KB):\n"
        "  Total Allocs: %llu\n"
        "  Current Objects: %llu\n"
        "  Peak Objects: %llu\n"
        "  Total Blocks: %llu\n",
        (unsigned long long)(manager->total_memory / (1024 * 1024)),
        (unsigned long long)(manager->used_memory / (1024 * 1024)),
        (unsigned long long)(manager->peak_memory / (1024 * 1024)),
        (unsigned long long)manager->slab_tiny->total_allocs,
        (unsigned long long)manager->slab_tiny->current_objects,
        (unsigned long long)manager->slab_tiny->peak_objects,
        (unsigned long long)manager->slab_tiny->total_blocks,
        (unsigned long long)manager->slab_small->total_allocs,
        (unsigned long long)manager->slab_small->current_objects,
        (unsigned long long)manager->slab_small->peak_objects,
        (unsigned long long)manager->slab_small->total_blocks,
        (unsigned long long)manager->slab_large->total_allocs,
        (unsigned long long)manager->slab_large->current_objects,
        (unsigned long long)manager->slab_large->peak_objects,
        (unsigned long long)manager->slab_large->total_blocks
    );
    
    pthread_mutex_unlock(&manager->global_mutex);
}

void pool_reset(MemoryPoolManager* manager) {
    if (!manager) return;
    
    pthread_mutex_lock(&manager->global_mutex);
    
    // 重建Slab分配器
    slab_allocator_destroy(manager->slab_tiny);
    slab_allocator_destroy(manager->slab_small);
    slab_allocator_destroy(manager->slab_large);
    
    manager->slab_tiny = slab_allocator_create(SLAB_TINY_OBJECT_SIZE,
                                                 SLAB_TINY_BLOCK_SIZE,
                                                 SLAB_TINY_OBJECTS_PER_BLOCK);
    manager->slab_small = slab_allocator_create(SLAB_SMALL_OBJECT_SIZE,
                                                  SLAB_SMALL_BLOCK_SIZE,
                                                  SLAB_SMALL_OBJECTS_PER_BLOCK);
    manager->slab_large = slab_allocator_create(SLAB_LARGE_OBJECT_SIZE,
                                                  SLAB_LARGE_BLOCK_SIZE,
                                                  SLAB_LARGE_OBJECTS_PER_BLOCK);
    
    manager->used_memory = 0;
    
    pthread_mutex_unlock(&manager->global_mutex);
}

void* pool_alloc_aligned(MemoryPoolManager* manager, size_t size, size_t alignment) {
    // 简化实现：先分配更大的空间，然后对齐
    size_t total_size = size + alignment - 1;
    void* raw_ptr = pool_alloc(manager, total_size);
    if (!raw_ptr) return NULL;
    
    uintptr_t ptr = (uintptr_t)raw_ptr;
    uintptr_t aligned_ptr = (ptr + alignment - 1) & ~(alignment - 1);
    
    return (void*)aligned_ptr;
}

int pool_preallocate(MemoryPoolManager* manager, SlabType type, size_t count) {
    if (!manager) return -1;
    
    pthread_mutex_lock(&manager->global_mutex);
    
    SlabAllocator* allocator = NULL;
    switch (type) {
        case SLAB_TINY:   allocator = manager->slab_tiny; break;
        case SLAB_SMALL:  allocator = manager->slab_small; break;
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
