#include "storage.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef _WIN32
    #include <windows.h>
    #include <io.h>
    #include <direct.h>
    #include <time.h>
    #define mkdir(path, mode) _mkdir(path)
#else
    #include <unistd.h>
    #include <sys/mman.h>
    #include <time.h>
    #define _open open
    #define _read read
    #define _write write
    #define _close close
    #define _lseek lseek
#endif

#define MAX_CACHE_ENTRIES 10000
#define DEFAULT_BLOCK_SIZE (128 * 1024 * 1024)  // 128MB per block
#define MAX_FILE_COUNT (1ULL << 32)  // 4 billion files
#define HASH_TABLE_SIZE 65536

// 缓存条目
typedef struct CacheEntry {
    uint64_t file_id;
    void* data;
    size_t size;
    uint64_t access_time;
    struct CacheEntry* next;
    struct CacheEntry* prev;
} CacheEntry;

// 哈希表节点
typedef struct HashNode {
    uint64_t file_id;
    char path[512];
    FileMetadata metadata;
    struct HashNode* next;
} HashNode;

// 存储上下文
typedef struct {
    char base_path[512];
    char index_path[512];
    char data_path[512];
    FILE* index_file;
    
    // 索引管理
    HashNode* hash_table[HASH_TABLE_SIZE];
    pthread_mutex_t hash_lock;
    
    // 缓存管理
    CacheEntry* cache_head;
    CacheEntry* cache_tail;
    CacheEntry* cache_map[MAX_CACHE_ENTRIES];
    size_t cache_size;
    size_t cache_used;
    pthread_mutex_t cache_lock;
    
    // 存储块管理
    StorageBlock* blocks;
    uint32_t block_count;
    uint32_t current_block_id;
    pthread_mutex_t block_lock;
    
    // 事务支持
    int in_transaction;
    FILE* journal_file;
    pthread_mutex_t journal_lock;
    
    // 统计信息
    SystemStats stats;
    pthread_mutex_t stats_lock;
    
    // 错误信息
    char last_error[256];
    
    // 文件锁
    pthread_rwlock_t rwlock;
} StorageContext;

// CRC32计算
static uint32_t crc32_table[256];
static int crc32_initialized = 0;

static void init_crc32_table() {
    if (crc32_initialized) return;
    
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ ((crc & 1) ? 0xEDB88320 : 0);
        }
        crc32_table[i] = crc;
    }
    crc32_initialized = 1;
}

static uint32_t calculate_crc32(const void* data, size_t size) {
    init_crc32_table();
    uint32_t crc = 0xFFFFFFFF;
    const uint8_t* bytes = (const uint8_t*)data;
    
    for (size_t i = 0; i < size; i++) {
        crc = (crc >> 8) ^ crc32_table[(crc ^ bytes[i]) & 0xFF];
    }
    return ~crc;
}

// 哈希函数
static uint32_t hash_path(const char* path) {
    uint32_t hash = 5381;
    while (*path) {
        hash = ((hash << 5) + hash) + *path++;
    }
    return hash;
}

static uint32_t hash_id(uint64_t file_id) {
    return (uint32_t)(file_id % HASH_TABLE_SIZE);
}

// 获取当前时间戳
static uint64_t get_timestamp() {
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    return ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
#else
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
#endif
}

// 创建目录
static int create_directory(const char* path) {
#ifdef _WIN32
    return _mkdir(path);
#else
    return mkdir(path, 0755);
#endif
}

// 递归创建目录
static int create_directory_recursive(const char* path) {
    char tmp[512];
    char *p = NULL;
    size_t len;
    
    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if (tmp[len - 1] == '/') {
        tmp[len - 1] = 0;
    }
    
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (create_directory(tmp) != 0 && errno != EEXIST) {
                return -1;
            }
            *p = '/';
        }
    }
    if (create_directory(tmp) != 0 && errno != EEXIST) {
        return -1;
    }
    
    return 0;
}

// 缓存管理函数
static CacheEntry* cache_find(StorageContext* ctx, uint64_t file_id) {
    uint32_t index = file_id % MAX_CACHE_ENTRIES;
    return ctx->cache_map[index];
}

static void cache_add(StorageContext* ctx, uint64_t file_id, void* data, size_t size) {
    CacheEntry* entry = (CacheEntry*)malloc(sizeof(CacheEntry));
    entry->file_id = file_id;
    entry->data = data;
    entry->size = size;
    entry->access_time = get_timestamp();
    entry->next = NULL;
    entry->prev = NULL;
    
    uint32_t index = file_id % MAX_CACHE_ENTRIES;
    ctx->cache_map[index] = entry;
    
    // LRU链表管理
    if (ctx->cache_tail) {
        ctx->cache_tail->next = entry;
        entry->prev = ctx->cache_tail;
        ctx->cache_tail = entry;
    } else {
        ctx->cache_head = ctx->cache_tail = entry;
    }
    
    ctx->cache_used += size;
}

static void cache_remove(StorageContext* ctx, CacheEntry* entry) {
    if (entry->prev) {
        entry->prev->next = entry->next;
    } else {
        ctx->cache_head = entry->next;
    }
    
    if (entry->next) {
        entry->next->prev = entry->prev;
    } else {
        ctx->cache_tail = entry->prev;
    }
    
    uint32_t index = entry->file_id % MAX_CACHE_ENTRIES;
    if (ctx->cache_map[index] == entry) {
        ctx->cache_map[index] = NULL;
    }
    
    free(entry->data);
    free(entry);
}

static void cache_evict(StorageContext* ctx, size_t required_size) {
    while (ctx->cache_used + required_size > ctx->cache_size && ctx->cache_head) {
        CacheEntry* entry = ctx->cache_head;
        ctx->cache_used -= entry->size;
        cache_remove(ctx, entry);
    }
}

static void cache_hit(StorageContext* ctx, CacheEntry* entry) {
    entry->access_time = get_timestamp();
    
    // 移到链表尾部
    if (entry->prev) {
        entry->prev->next = entry->next;
    } else {
        ctx->cache_head = entry->next;
    }
    
    if (entry->next) {
        entry->next->prev = entry->prev;
    } else {
        ctx->cache_tail = entry->prev;
    }
    
    if (ctx->cache_tail) {
        ctx->cache_tail->next = entry;
        entry->prev = ctx->cache_tail;
    }
    ctx->cache_tail = entry;
    entry->next = NULL;
}

// 索引管理函数
static HashNode* index_find_by_path(StorageContext* ctx, const char* path) {
    uint32_t hash = hash_path(path);
    uint32_t index = hash % HASH_TABLE_SIZE;
    
    HashNode* node = ctx->hash_table[index];
    while (node) {
        if (strcmp(node->path, path) == 0) {
            return node;
        }
        node = node->next;
    }
    return NULL;
}

static HashNode* index_find_by_id(StorageContext* ctx, uint64_t file_id) {
    uint32_t index = hash_id(file_id);
    
    HashNode* node = ctx->hash_table[index];
    while (node) {
        if (node->metadata.file_id == file_id) {
            return node;
        }
        node = node->next;
    }
    return NULL;
}

static int index_add(StorageContext* ctx, const char* path, const FileMetadata* metadata) {
    uint32_t hash = hash_path(path);
    uint32_t index = hash % HASH_TABLE_SIZE;
    
    HashNode* node = (HashNode*)malloc(sizeof(HashNode));
    if (!node) return -1;
    
    strncpy(node->path, path, sizeof(node->path) - 1);
    node->path[sizeof(node->path) - 1] = '\0';
    memcpy(&node->metadata, metadata, sizeof(FileMetadata));
    node->next = ctx->hash_table[index];
    ctx->hash_table[index] = node;
    
    return 0;
}

static void index_remove(StorageContext* ctx, const char* path) {
    uint32_t hash = hash_path(path);
    uint32_t index = hash % HASH_TABLE_SIZE;
    
    HashNode* prev = NULL;
    HashNode* node = ctx->hash_table[index];
    
    while (node) {
        if (strcmp(node->path, path) == 0) {
            if (prev) {
                prev->next = node->next;
            } else {
                ctx->hash_table[index] = node->next;
            }
            free(node);
            return;
        }
        prev = node;
        node = node->next;
    }
}

// 保存索引到文件
static int save_index(StorageContext* ctx) {
    FILE* fp = fopen(ctx->index_path, "wb");
    if (!fp) return -1;
    
    // 写入文件头
    uint32_t magic = 0x53544F52;  // "STOR"
    fwrite(&magic, sizeof(uint32_t), 1, fp);
    
    uint32_t version = 1;
    fwrite(&version, sizeof(uint32_t), 1, fp);
    
    uint64_t timestamp = get_timestamp();
    fwrite(&timestamp, sizeof(uint64_t), 1, fp);
    
    // 写入所有哈希表项
    uint32_t total_count = 0;
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        HashNode* node = ctx->hash_table[i];
        while (node) {
            total_count++;
            node = node->next;
        }
    }
    fwrite(&total_count, sizeof(uint32_t), 1, fp);
    
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        HashNode* node = ctx->hash_table[i];
        while (node) {
            fwrite(node->path, sizeof(char), 512, fp);
            fwrite(&node->metadata, sizeof(FileMetadata), 1, fp);
            node = node->next;
        }
    }
    
    fclose(fp);
    return 0;
}

// 从文件加载索引
static int load_index(StorageContext* ctx) {
    FILE* fp = fopen(ctx->index_path, "rb");
    if (!fp) return -1;
    
    // 读取文件头
    uint32_t magic;
    fread(&magic, sizeof(uint32_t), 1, fp);
    if (magic != 0x53544F52) {
        fclose(fp);
        return -1;
    }
    
    uint32_t version;
    fread(&version, sizeof(uint32_t), 1, fp);
    
    uint64_t timestamp;
    fread(&timestamp, sizeof(uint64_t), 1, fp);
    
    // 读取文件数量
    uint32_t total_count;
    fread(&total_count, sizeof(uint32_t), 1, fp);
    
    // 读取文件元数据
    for (uint32_t i = 0; i < total_count; i++) {
        char path[512];
        FileMetadata metadata;
        
        fread(path, sizeof(char), 512, fp);
        fread(&metadata, sizeof(FileMetadata), 1, fp);
        
        index_add(ctx, path, &metadata);
    }
    
    fclose(fp);
    return 0;
}

// 获取当前块的文件路径
static void get_block_path(StorageContext* ctx, uint32_t block_id, char* path) {
    snprintf(path, 512, "%s/block_%08u.dat", ctx->data_path, block_id);
}

// 初始化存储系统
STORAGE_API StorageError storage_init(const char* base_path, StorageHandle* handle) {
    if (!base_path || !handle) {
        return STORAGE_ERROR_INVALID_PARAM;
    }
    
    StorageContext* ctx = (StorageContext*)calloc(1, sizeof(StorageContext));
    if (!ctx) {
        return STORAGE_ERROR;
    }
    
    // 初始化路径
    strncpy(ctx->base_path, base_path, sizeof(ctx->base_path) - 1);
    snprintf(ctx->index_path, sizeof(ctx->index_path), "%s/index.dat", base_path);
    snprintf(ctx->data_path, sizeof(ctx->data_path), "%s/blocks", base_path);
    
    // 创建目录
    create_directory_recursive(base_path);
    create_directory_recursive(ctx->data_path);
    
    // 初始化锁
    pthread_mutex_init(&ctx->hash_lock, NULL);
    pthread_mutex_init(&ctx->cache_lock, NULL);
    pthread_mutex_init(&ctx->block_lock, NULL);
    pthread_mutex_init(&ctx->journal_lock, NULL);
    pthread_mutex_init(&ctx->stats_lock, NULL);
    pthread_rwlock_init(&ctx->rwlock, NULL);
    
    // 初始化缓存
    ctx->cache_size = 1024 * 1024 * 1024;  // 1GB默认缓存
    ctx->cache_used = 0;
    ctx->cache_head = ctx->cache_tail = NULL;
    memset(ctx->cache_map, 0, sizeof(ctx->cache_map));
    
    // 初始化块管理
    ctx->blocks = NULL;
    ctx->block_count = 0;
    ctx->current_block_id = 0;
    
    // 初始化事务
    ctx->in_transaction = 0;
    ctx->journal_file = NULL;
    
    // 初始化统计
    memset(&ctx->stats, 0, sizeof(SystemStats));
    
    // 加载索引
    load_index(ctx);
    
    *handle = ctx;
    return STORAGE_SUCCESS;
}

// 关闭存储系统
STORAGE_API StorageError storage_close(StorageHandle handle) {
    if (!handle) return STORAGE_ERROR_INVALID_PARAM;
    
    StorageContext* ctx = (StorageContext*)handle;
    
    // 保存索引
    save_index(ctx);
    
    // 清理缓存
    pthread_mutex_lock(&ctx->cache_lock);
    while (ctx->cache_head) {
        CacheEntry* entry = ctx->cache_head;
        cache_remove(ctx, entry);
    }
    pthread_mutex_unlock(&ctx->cache_lock);
    
    // 清理哈希表
    pthread_mutex_lock(&ctx->hash_lock);
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        HashNode* node = ctx->hash_table[i];
        while (node) {
            HashNode* next = node->next;
            free(node);
            node = next;
        }
    }
    pthread_mutex_unlock(&ctx->hash_lock);
    
    // 清理块信息
    if (ctx->blocks) {
        free(ctx->blocks);
    }
    
    // 销毁锁
    pthread_mutex_destroy(&ctx->hash_lock);
    pthread_mutex_destroy(&ctx->cache_lock);
    pthread_mutex_destroy(&ctx->block_lock);
    pthread_mutex_destroy(&ctx->journal_lock);
    pthread_mutex_destroy(&ctx->stats_lock);
    pthread_rwlock_destroy(&ctx->rwlock);
    
    free(ctx);
    return STORAGE_SUCCESS;
}

// 写入文件
STORAGE_API StorageError storage_write_file(StorageHandle handle, const char* path,
                                             const void* data, size_t size, uint64_t* file_id) {
    if (!handle || !path || !data || !file_id) {
        return STORAGE_ERROR_INVALID_PARAM;
    }
    
    StorageContext* ctx = (StorageContext*)handle;
    pthread_rwlock_wrlock(&ctx->rwlock);
    
    // 检查文件是否已存在
    pthread_mutex_lock(&ctx->hash_lock);
    HashNode* existing_node = index_find_by_path(ctx, path);
    pthread_mutex_unlock(&ctx->hash_lock);
    
    if (existing_node) {
        pthread_rwlock_unlock(&ctx->rwlock);
        return STORAGE_ERROR_EXISTS;
    }
    
    // 生成文件ID
    uint64_t new_file_id = get_timestamp();
    *file_id = new_file_id;
    
    // 创建或获取存储块
    pthread_mutex_lock(&ctx->block_lock);
    if (ctx->current_block_id == 0 || ctx->blocks[ctx->current_block_id - 1].used_size + size > DEFAULT_BLOCK_SIZE) {
        // 需要创建新块
        ctx->current_block_id++;
        ctx->blocks = (StorageBlock*)realloc(ctx->blocks, ctx->current_block_id * sizeof(StorageBlock));
        
        StorageBlock* block = &ctx->blocks[ctx->current_block_id - 1];
        block->block_id = ctx->current_block_id;
        block->size = DEFAULT_BLOCK_SIZE;
        block->used_size = 0;
        block->file_count = 0;
        get_block_path(ctx, block->block_id, block->filename);
        block->create_time = get_timestamp();
        ctx->block_count = ctx->current_block_id;
    }
    
    StorageBlock* block = &ctx->blocks[ctx->current_block_id - 1];
    uint64_t offset = block->used_size;
    pthread_mutex_unlock(&ctx->block_lock);
    
    // 写入数据到块文件
    char block_path[512];
    get_block_path(ctx, block->block_id, block_path);
    
    FILE* fp = fopen(block_path, "ab+");
    if (!fp) {
        pthread_rwlock_unlock(&ctx->rwlock);
        return STORAGE_ERROR_IO;
    }
    
    fseek(fp, offset, SEEK_SET);
    size_t written = fwrite(data, 1, size, fp);
    fclose(fp);
    
    if (written != size) {
        pthread_rwlock_unlock(&ctx->rwlock);
        return STORAGE_ERROR_IO;
    }
    
    // 更新块信息
    pthread_mutex_lock(&ctx->block_lock);
    block->used_size += size;
    block->file_count++;
    pthread_mutex_unlock(&ctx->block_lock);
    
    // 计算校验和
    uint32_t checksum = calculate_crc32(data, size);
    
    // 创建文件元数据
    FileMetadata metadata;
    memset(&metadata, 0, sizeof(FileMetadata));
    metadata.file_id = new_file_id;
    strncpy(metadata.path, path, sizeof(metadata.path) - 1);
    metadata.size = size;
    metadata.offset = offset;
    metadata.block_id = block->block_id;
    metadata.create_time = get_timestamp();
    metadata.modify_time = metadata.create_time;
    metadata.checksum = checksum;
    metadata.ref_count = 1;
    
    // 添加到索引
    pthread_mutex_lock(&ctx->hash_lock);
    index_add(ctx, path, &metadata);
    pthread_mutex_unlock(&ctx->hash_lock);
    
    // 更新统计
    pthread_mutex_lock(&ctx->stats_lock);
    ctx->stats.total_files++;
    ctx->stats.used_storage += size;
    ctx->stats.write_count++;
    pthread_mutex_unlock(&ctx->stats_lock);
    
    // 写入日志（如果开启了事务）
    if (ctx->in_transaction) {
        pthread_mutex_lock(&ctx->journal_lock);
        if (ctx->journal_file) {
            fprintf(ctx->journal_file, "WRITE %llu %s\n", (unsigned long long)new_file_id, path);
            fflush(ctx->journal_file);
        }
        pthread_mutex_unlock(&ctx->journal_lock);
    }
    
    pthread_rwlock_unlock(&ctx->rwlock);
    return STORAGE_SUCCESS;
}

// 读取文件
STORAGE_API StorageError storage_read_file(StorageHandle handle, uint64_t file_id,
                                            void* buffer, size_t size, size_t* bytes_read) {
    if (!handle || !buffer || !bytes_read) {
        return STORAGE_ERROR_INVALID_PARAM;
    }
    
    StorageContext* ctx = (StorageContext*)handle;
    pthread_rwlock_rdlock(&ctx->rwlock);
    
    // 查找文件元数据
    pthread_mutex_lock(&ctx->hash_lock);
    HashNode* node = index_find_by_id(ctx, file_id);
    pthread_mutex_unlock(&ctx->hash_lock);
    
    if (!node) {
        pthread_mutex_lock(&ctx->stats_lock);
        ctx->stats.cache_misses++;
        pthread_mutex_unlock(&ctx->stats_lock);
        pthread_rwlock_unlock(&ctx->rwlock);
        return STORAGE_ERROR_NOT_FOUND;
    }
    
    FileMetadata* metadata = &node->metadata;
    if (size < metadata->size) {
        pthread_rwlock_unlock(&ctx->rwlock);
        return STORAGE_ERROR_INVALID_PARAM;
    }
    
    // 检查缓存
    pthread_mutex_lock(&ctx->cache_lock);
    CacheEntry* entry = cache_find(ctx, file_id);
    if (entry && entry->data) {
        memcpy(buffer, entry->data, metadata->size);
        *bytes_read = metadata->size;
        cache_hit(ctx, entry);
        
        pthread_mutex_lock(&ctx->stats_lock);
        ctx->stats.cache_hits++;
        pthread_mutex_unlock(&ctx->stats_lock);
        
        pthread_mutex_unlock(&ctx->cache_lock);
        pthread_rwlock_unlock(&ctx->rwlock);
        return STORAGE_SUCCESS;
    }
    pthread_mutex_unlock(&ctx->cache_lock);
    
    pthread_mutex_lock(&ctx->stats_lock);
    ctx->stats.cache_misses++;
    pthread_mutex_unlock(&ctx->stats_lock);
    
    // 从磁盘读取
    char block_path[512];
    get_block_path(ctx, metadata->block_id, block_path);
    
    FILE* fp = fopen(block_path, "rb");
    if (!fp) {
        pthread_rwlock_unlock(&ctx->rwlock);
        return STORAGE_ERROR_IO;
    }
    
    fseek(fp, metadata->offset, SEEK_SET);
    size_t read_count = fread(buffer, 1, metadata->size, fp);
    fclose(fp);
    
    if (read_count != metadata->size) {
        pthread_rwlock_unlock(&ctx->rwlock);
        return STORAGE_ERROR_IO;
    }
    
    *bytes_read = metadata->size;
    
    // 验证校验和
    uint32_t calculated_checksum = calculate_crc32(buffer, metadata->size);
    if (calculated_checksum != metadata->checksum) {
        pthread_rwlock_unlock(&ctx->rwlock);
        return STORAGE_ERROR_CHECKSUM;
    }
    
    // 添加到缓存
    pthread_mutex_lock(&ctx->cache_lock);
    if (metadata->size <= ctx->cache_size) {
        cache_evict(ctx, metadata->size);
        void* data_copy = malloc(metadata->size);
        memcpy(data_copy, buffer, metadata->size);
        cache_add(ctx, file_id, data_copy, metadata->size);
    }
    pthread_mutex_unlock(&ctx->cache_lock);
    
    // 更新统计
    pthread_mutex_lock(&ctx->stats_lock);
    ctx->stats.read_count++;
    pthread_mutex_unlock(&ctx->stats_lock);
    
    pthread_rwlock_unlock(&ctx->rwlock);
    return STORAGE_SUCCESS;
}

// 读取文件（按路径）
STORAGE_API StorageError storage_read_file_by_path(StorageHandle handle, const char* path,
                                                     void* buffer, size_t size, size_t* bytes_read) {
    if (!handle || !path || !buffer || !bytes_read) {
        return STORAGE_ERROR_INVALID_PARAM;
    }
    
    StorageContext* ctx = (StorageContext*)handle;
    
    // 查找文件元数据
    pthread_mutex_lock(&ctx->hash_lock);
    HashNode* node = index_find_by_path(ctx, path);
    pthread_mutex_unlock(&ctx->hash_lock);
    
    if (!node) {
        return STORAGE_ERROR_NOT_FOUND;
    }
    
    return storage_read_file(handle, node->metadata.file_id, buffer, size, bytes_read);
}

// 删除文件
STORAGE_API StorageError storage_delete_file(StorageHandle handle, uint64_t file_id) {
    if (!handle) {
        return STORAGE_ERROR_INVALID_PARAM;
    }
    
    StorageContext* ctx = (StorageContext*)handle;
    pthread_rwlock_wrlock(&ctx->rwlock);
    
    // 查找文件元数据
    pthread_mutex_lock(&ctx->hash_lock);
    HashNode* node = index_find_by_id(ctx, file_id);
    if (!node) {
        pthread_mutex_unlock(&ctx->hash_lock);
        pthread_rwlock_unlock(&ctx->rwlock);
        return STORAGE_ERROR_NOT_FOUND;
    }
    
    char path[512];
    strncpy(path, node->path, sizeof(path) - 1);
    
    index_remove(ctx, path);
    pthread_mutex_unlock(&ctx->hash_lock);
    
    // 从缓存中删除
    pthread_mutex_lock(&ctx->cache_lock);
    CacheEntry* entry = cache_find(ctx, file_id);
    if (entry) {
        cache_remove(ctx, entry);
    }
    pthread_mutex_unlock(&ctx->cache_lock);
    
    // 更新统计
    pthread_mutex_lock(&ctx->stats_lock);
    ctx->stats.total_files--;
    ctx->stats.used_storage -= node->metadata.size;
    pthread_mutex_unlock(&ctx->stats_lock);
    
    // 写入日志
    if (ctx->in_transaction) {
        pthread_mutex_lock(&ctx->journal_lock);
        if (ctx->journal_file) {
            fprintf(ctx->journal_file, "DELETE %llu %s\n", (unsigned long long)file_id, path);
            fflush(ctx->journal_file);
        }
        pthread_mutex_unlock(&ctx->journal_lock);
    }
    
    pthread_rwlock_unlock(&ctx->rwlock);
    return STORAGE_SUCCESS;
}

// 删除文件（按路径）
STORAGE_API StorageError storage_delete_file_by_path(StorageHandle handle, const char* path) {
    if (!handle || !path) {
        return STORAGE_ERROR_INVALID_PARAM;
    }
    
    StorageContext* ctx = (StorageContext*)handle;
    
    pthread_mutex_lock(&ctx->hash_lock);
    HashNode* node = index_find_by_path(ctx, path);
    uint64_t file_id = node ? node->metadata.file_id : 0;
    pthread_mutex_unlock(&ctx->hash_lock);
    
    if (!node) {
        return STORAGE_ERROR_NOT_FOUND;
    }
    
    return storage_delete_file(handle, file_id);
}

// 查询文件元数据
STORAGE_API StorageError storage_get_metadata(StorageHandle handle, uint64_t file_id,
                                               FileMetadata* metadata) {
    if (!handle || !metadata) {
        return STORAGE_ERROR_INVALID_PARAM;
    }
    
    StorageContext* ctx = (StorageContext*)handle;
    pthread_rwlock_rdlock(&ctx->rwlock);
    
    pthread_mutex_lock(&ctx->hash_lock);
    HashNode* node = index_find_by_id(ctx, file_id);
    pthread_mutex_unlock(&ctx->hash_lock);
    
    if (!node) {
        pthread_rwlock_unlock(&ctx->rwlock);
        return STORAGE_ERROR_NOT_FOUND;
    }
    
    memcpy(metadata, &node->metadata, sizeof(FileMetadata));
    pthread_rwlock_unlock(&ctx->rwlock);
    return STORAGE_SUCCESS;
}

// 查询文件元数据（按路径）
STORAGE_API StorageError storage_get_metadata_by_path(StorageHandle handle, const char* path,
                                                       FileMetadata* metadata) {
    if (!handle || !path || !metadata) {
        return STORAGE_ERROR_INVALID_PARAM;
    }
    
    StorageContext* ctx = (StorageContext*)handle;
    pthread_rwlock_rdlock(&ctx->rwlock);
    
    pthread_mutex_lock(&ctx->hash_lock);
    HashNode* node = index_find_by_path(ctx, path);
    pthread_mutex_unlock(&ctx->hash_lock);
    
    if (!node) {
        pthread_rwlock_unlock(&ctx->rwlock);
        return STORAGE_ERROR_NOT_FOUND;
    }
    
    memcpy(metadata, &node->metadata, sizeof(FileMetadata));
    pthread_rwlock_unlock(&ctx->rwlock);
    return STORAGE_SUCCESS;
}

// 文件是否存在
STORAGE_API StorageError storage_file_exists(StorageHandle handle, const char* path,
                                               int* exists) {
    if (!handle || !path || !exists) {
        return STORAGE_ERROR_INVALID_PARAM;
    }
    
    StorageContext* ctx = (StorageContext*)handle;
    pthread_rwlock_rdlock(&ctx->rwlock);
    
    pthread_mutex_lock(&ctx->hash_lock);
    HashNode* node = index_find_by_path(ctx, path);
    pthread_mutex_unlock(&ctx->hash_lock);
    
    *exists = (node != NULL);
    pthread_rwlock_unlock(&ctx->rwlock);
    return STORAGE_SUCCESS;
}

// 列出目录下的文件
STORAGE_API StorageError storage_list_directory(StorageHandle handle, const char* path,
                                                 FileMetadata** files, size_t* count) {
    if (!handle || !files || !count) {
        return STORAGE_ERROR_INVALID_PARAM;
    }
    
    StorageContext* ctx = (StorageContext*)handle;
    pthread_rwlock_rdlock(&ctx->rwlock);
    
    // 计算匹配文件数量
    size_t match_count = 0;
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        HashNode* node = ctx->hash_table[i];
        while (node) {
            if (path == NULL || strncmp(node->metadata.path, path, strlen(path)) == 0) {
                match_count++;
            }
            node = node->next;
        }
    }
    
    if (match_count == 0) {
        *files = NULL;
        *count = 0;
        pthread_rwlock_unlock(&ctx->rwlock);
        return STORAGE_SUCCESS;
    }
    
    // 分配内存
    FileMetadata* result = (FileMetadata*)malloc(match_count * sizeof(FileMetadata));
    if (!result) {
        pthread_rwlock_unlock(&ctx->rwlock);
        return STORAGE_ERROR;
    }
    
    // 收集文件
    size_t index = 0;
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        HashNode* node = ctx->hash_table[i];
        while (node) {
            if (path == NULL || strncmp(node->metadata.path, path, strlen(path)) == 0) {
                memcpy(&result[index], &node->metadata, sizeof(FileMetadata));
                index++;
            }
            node = node->next;
        }
    }
    
    *files = result;
    *count = match_count;
    pthread_rwlock_unlock(&ctx->rwlock);
    return STORAGE_SUCCESS;
}

// 释放文件列表内存
STORAGE_API void storage_free_list(FileMetadata* files) {
    if (files) {
        free(files);
    }
}

// 搜索文件
STORAGE_API StorageError storage_search_files(StorageHandle handle, const char* pattern,
                                               FileMetadata** files, size_t* count) {
    if (!handle || !pattern || !files || !count) {
        return STORAGE_ERROR_INVALID_PARAM;
    }
    
    StorageContext* ctx = (StorageContext*)handle;
    pthread_rwlock_rdlock(&ctx->rwlock);
    
    // 计算匹配文件数量
    size_t match_count = 0;
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        HashNode* node = ctx->hash_table[i];
        while (node) {
            if (strstr(node->metadata.path, pattern) != NULL) {
                match_count++;
            }
            node = node->next;
        }
    }
    
    if (match_count == 0) {
        *files = NULL;
        *count = 0;
        pthread_rwlock_unlock(&ctx->rwlock);
        return STORAGE_SUCCESS;
    }
    
    // 分配内存
    FileMetadata* result = (FileMetadata*)malloc(match_count * sizeof(FileMetadata));
    if (!result) {
        pthread_rwlock_unlock(&ctx->rwlock);
        return STORAGE_ERROR;
    }
    
    // 收集匹配文件
    size_t index = 0;
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        HashNode* node = ctx->hash_table[i];
        while (node) {
            if (strstr(node->metadata.path, pattern) != NULL) {
                memcpy(&result[index], &node->metadata, sizeof(FileMetadata));
                index++;
            }
            node = node->next;
        }
    }
    
    *files = result;
    *count = match_count;
    pthread_rwlock_unlock(&ctx->rwlock);
    return STORAGE_SUCCESS;
}

// 获取系统统计信息
STORAGE_API StorageError storage_get_stats(StorageHandle handle, SystemStats* stats) {
    if (!handle || !stats) {
        return STORAGE_ERROR_INVALID_PARAM;
    }
    
    StorageContext* ctx = (StorageContext*)handle;
    pthread_rwlock_rdlock(&ctx->rwlock);
    
    pthread_mutex_lock(&ctx->stats_lock);
    memcpy(stats, &ctx->stats, sizeof(SystemStats));
    pthread_mutex_unlock(&ctx->stats_lock);
    
    // 计算缓存命中率
    uint64_t total = stats->cache_hits + stats->cache_misses;
    if (total > 0) {
        // 缓存命中率已在stats中
    }
    
    pthread_rwlock_unlock(&ctx->rwlock);
    return STORAGE_SUCCESS;
}

// 设置缓存大小
STORAGE_API StorageError storage_set_cache_size(StorageHandle handle, size_t size) {
    if (!handle) {
        return STORAGE_ERROR_INVALID_PARAM;
    }
    
    StorageContext* ctx = (StorageContext*)handle;
    pthread_mutex_lock(&ctx->cache_lock);
    
    ctx->cache_size = size;
    cache_evict(ctx, 0);  // 如果新大小小于当前使用大小，自动淘汰
    
    pthread_mutex_unlock(&ctx->cache_lock);
    return STORAGE_SUCCESS;
}

// 清空缓存
STORAGE_API StorageError storage_clear_cache(StorageHandle handle) {
    if (!handle) {
        return STORAGE_ERROR_INVALID_PARAM;
    }
    
    StorageContext* ctx = (StorageContext*)handle;
    pthread_mutex_lock(&ctx->cache_lock);
    
    while (ctx->cache_head) {
        CacheEntry* entry = ctx->cache_head;
        cache_remove(ctx, entry);
    }
    ctx->cache_used = 0;
    
    pthread_mutex_unlock(&ctx->cache_lock);
    return STORAGE_SUCCESS;
}

// 开始事务
STORAGE_API StorageError storage_begin_transaction(StorageHandle handle) {
    if (!handle) {
        return STORAGE_ERROR_INVALID_PARAM;
    }
    
    StorageContext* ctx = (StorageContext*)handle;
    pthread_mutex_lock(&ctx->journal_lock);
    
    if (ctx->in_transaction) {
        pthread_mutex_unlock(&ctx->journal_lock);
        return STORAGE_ERROR;
    }
    
    char journal_path[512];
    snprintf(journal_path, sizeof(journal_path), "%s/journal.dat", ctx->base_path);
    
    ctx->journal_file = fopen(journal_path, "w");
    if (!ctx->journal_file) {
        pthread_mutex_unlock(&ctx->journal_lock);
        return STORAGE_ERROR_IO;
    }
    
    ctx->in_transaction = 1;
    pthread_mutex_unlock(&ctx->journal_lock);
    return STORAGE_SUCCESS;
}

// 提交事务
STORAGE_API StorageError storage_commit_transaction(StorageHandle handle) {
    if (!handle) {
        return STORAGE_ERROR_INVALID_PARAM;
    }
    
    StorageContext* ctx = (StorageContext*)handle;
    pthread_mutex_lock(&ctx->journal_lock);
    
    if (!ctx->in_transaction) {
        pthread_mutex_unlock(&ctx->journal_lock);
        return STORAGE_ERROR;
    }
    
    if (ctx->journal_file) {
        fclose(ctx->journal_file);
        ctx->journal_file = NULL;
        
        // 删除日志文件
        char journal_path[512];
        snprintf(journal_path, sizeof(journal_path), "%s/journal.dat", ctx->base_path);
        remove(journal_path);
    }
    
    ctx->in_transaction = 0;
    pthread_mutex_unlock(&ctx->journal_lock);
    
    // 保存索引
    save_index(ctx);
    return STORAGE_SUCCESS;
}

// 回滚事务
STORAGE_API StorageError storage_rollback_transaction(StorageHandle handle) {
    if (!handle) {
        return STORAGE_ERROR_INVALID_PARAM;
    }
    
    StorageContext* ctx = (StorageContext*)handle;
    pthread_mutex_lock(&ctx->journal_lock);
    
    if (!ctx->in_transaction) {
        pthread_mutex_unlock(&ctx->journal_lock);
        return STORAGE_ERROR;
    }
    
    // 重新加载索引（恢复到事务前状态）
    pthread_mutex_unlock(&ctx->journal_lock);
    
    pthread_rwlock_wrlock(&ctx->rwlock);
    
    // 清空哈希表
    pthread_mutex_lock(&ctx->hash_lock);
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        HashNode* node = ctx->hash_table[i];
        while (node) {
            HashNode* next = node->next;
            free(node);
            node = next;
        }
        ctx->hash_table[i] = NULL;
    }
    pthread_mutex_unlock(&ctx->hash_lock);
    
    // 重新加载索引
    load_index(ctx);
    
    pthread_rwlock_unlock(&ctx->rwlock);
    pthread_mutex_lock(&ctx->journal_lock);
    
    if (ctx->journal_file) {
        fclose(ctx->journal_file);
        ctx->journal_file = NULL;
        
        // 删除日志文件
        char journal_path[512];
        snprintf(journal_path, sizeof(journal_path), "%s/journal.dat", ctx->base_path);
        remove(journal_path);
    }
    
    ctx->in_transaction = 0;
    pthread_mutex_unlock(&ctx->journal_lock);
    return STORAGE_SUCCESS;
}

// 获取最后错误信息
STORAGE_API const char* storage_get_last_error(StorageHandle handle) {
    if (!handle) {
        return "Invalid handle";
    }
    
    StorageContext* ctx = (StorageContext*)handle;
    return ctx->last_error;
}

// 创建备份
STORAGE_API StorageError storage_create_backup(StorageHandle handle, const char* backup_path) {
    if (!handle || !backup_path) {
        return STORAGE_ERROR_INVALID_PARAM;
    }
    
    StorageContext* ctx = (StorageContext*)handle;
    pthread_rwlock_rdlock(&ctx->rwlock);
    
    // 保存索引到备份路径
    char backup_index[512];
    snprintf(backup_index, sizeof(backup_index), "%s/index.dat", backup_path);
    create_directory_recursive(backup_path);
    
    FILE* src = fopen(ctx->index_path, "rb");
    if (!src) {
        pthread_rwlock_unlock(&ctx->rwlock);
        return STORAGE_ERROR_IO;
    }
    
    FILE* dst = fopen(backup_index, "wb");
    if (!dst) {
        fclose(src);
        pthread_rwlock_unlock(&ctx->rwlock);
        return STORAGE_ERROR_IO;
    }
    
    // 复制索引文件
    char buffer[8192];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
        fwrite(buffer, 1, bytes, dst);
    }
    
    fclose(src);
    fclose(dst);
    
    // 备份数据块
    char backup_blocks[512];
    snprintf(backup_blocks, sizeof(backup_blocks), "%s/blocks", backup_path);
    create_directory_recursive(backup_blocks);
    
    // 在实际应用中，这里应该复制所有块文件
    // 为简化示例，这里只创建目录结构
    
    pthread_rwlock_unlock(&ctx->rwlock);
    return STORAGE_SUCCESS;
}

// 恢复备份
STORAGE_API StorageError storage_restore_backup(StorageHandle handle, const char* backup_path) {
    if (!handle || !backup_path) {
        return STORAGE_ERROR_INVALID_PARAM;
    }
    
    StorageContext* ctx = (StorageContext*)handle;
    pthread_rwlock_wrlock(&ctx->rwlock);
    
    // 清空当前索引
    pthread_mutex_lock(&ctx->hash_lock);
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        HashNode* node = ctx->hash_table[i];
        while (node) {
            HashNode* next = node->next;
            free(node);
            node = next;
        }
        ctx->hash_table[i] = NULL;
    }
    pthread_mutex_unlock(&ctx->hash_lock);
    
    // 从备份恢复索引
    char backup_index[512];
    snprintf(backup_index, sizeof(backup_index), "%s/index.dat", backup_path);
    
    FILE* src = fopen(backup_index, "rb");
    if (!src) {
        pthread_rwlock_unlock(&ctx->rwlock);
        return STORAGE_ERROR_IO;
    }
    
    FILE* dst = fopen(ctx->index_path, "wb");
    if (!dst) {
        fclose(src);
        pthread_rwlock_unlock(&ctx->rwlock);
        return STORAGE_ERROR_IO;
    }
    
    // 复制索引文件
    char buffer[8192];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
        fwrite(buffer, 1, bytes, dst);
    }
    
    fclose(src);
    fclose(dst);
    
    // 重新加载索引
    load_index(ctx);
    
    pthread_rwlock_unlock(&ctx->rwlock);
    return STORAGE_SUCCESS;
}

// 压缩存储
STORAGE_API StorageError storage_compact_storage(StorageHandle handle) {
    if (!handle) {
        return STORAGE_ERROR_INVALID_PARAM;
    }
    
    StorageContext* ctx = (StorageContext*)handle;
    pthread_rwlock_wrlock(&ctx->rwlock);
    
    // 这里实现存储压缩逻辑
    // 在实际应用中，应该重新组织存储块，消除碎片
    
    // 保存索引
    save_index(ctx);
    
    pthread_rwlock_unlock(&ctx->rwlock);
    return STORAGE_SUCCESS;
}
