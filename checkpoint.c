#include "checkpoint.h"
#include "storage.h"
#include "async_io.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <time.h>

#ifdef _WIN32
    #include <direct.h>
    #include <windows.h>
    // 简单的SHA-256实现用于Windows
    #define SHA256_DIGEST_LENGTH 32
    typedef struct {
        uint32_t h[8];
        unsigned char data[64];
        uint32_t datalen;
        uint64_t bitlen;
    } SHA256_CTX;
    
    void SHA256_Init(SHA256_CTX* ctx);
    void SHA256_Update(SHA256_CTX* ctx, const void* data, size_t len);
    void SHA256_Final(unsigned char digest[SHA256_DIGEST_LENGTH], SHA256_CTX* ctx);
#else
    #include <unistd.h>
    #include <openssl/sha.h>
#endif

#define DEFAULT_SAVE_INTERVAL 1000
#define MAX_RETRY_ATTEMPTS 3
#define DEFAULT_INITIAL_DELAY 1000
#define DEFAULT_MAX_DELAY 60000
#define DEFAULT_BACKOFF_FACTOR 2.0

// ============ 检查点管理实现 ============

CheckpointManager* checkpoint_manager_init(const char* checkpoint_dir, uint32_t save_interval) {
    CheckpointManager* manager = (CheckpointManager*)calloc(1, sizeof(CheckpointManager));
    if (!manager) return NULL;
    
    if (checkpoint_dir) {
        strncpy(manager->checkpoint_dir, checkpoint_dir, sizeof(manager->checkpoint_dir) - 1);
    } else {
        strncpy(manager->checkpoint_dir, "./checkpoints", sizeof(manager->checkpoint_dir) - 1);
    }
    
    manager->save_interval = save_interval ? save_interval : DEFAULT_SAVE_INTERVAL;
    manager->auto_save = 1;
    manager->last_save_count = 0;
    
    pthread_mutex_init(&manager->mutex, NULL);
    
    // 创建检查点目录
#ifdef _WIN32
    _mkdir(manager->checkpoint_dir);
#else
    mkdir(manager->checkpoint_dir, 0755);
#endif
    
    return manager;
}

void checkpoint_manager_destroy(CheckpointManager* manager) {
    if (!manager) return;
    
    if (manager->current_checkpoint) {
        checkpoint_save(manager, manager->current_checkpoint);
        free(manager->current_checkpoint);
    }
    
    pthread_mutex_destroy(&manager->mutex);
    free(manager);
}

// 获取检查点文件路径
static void get_checkpoint_path(CheckpointManager* manager, uint64_t checkpoint_id, char* path) {
    snprintf(path, 512, "%s/checkpoint_%016llu.dat", 
             manager->checkpoint_dir, (unsigned long long)checkpoint_id);
}

Checkpoint* checkpoint_create(CheckpointManager* manager, const char* source_path,
                             const char* dest_path, uint64_t total_files, uint64_t total_bytes) {
    if (!manager) return NULL;
    
    pthread_mutex_lock(&manager->mutex);
    
    // 释放旧检查点
    if (manager->current_checkpoint) {
        free(manager->current_checkpoint->positions);
        free(manager->current_checkpoint);
    }
    
    Checkpoint* checkpoint = (Checkpoint*)calloc(1, sizeof(Checkpoint));
    if (!checkpoint) {
        pthread_mutex_unlock(&manager->mutex);
        return NULL;
    }
    
    checkpoint->checkpoint_id = get_timestamp();
    checkpoint->last_file_id = 0;
    checkpoint->processed_count = 0;
    checkpoint->processed_bytes = 0;
    checkpoint->total_files = total_files;
    checkpoint->total_bytes = total_bytes;
    checkpoint->create_time = checkpoint->checkpoint_id;
    checkpoint->update_time = checkpoint->checkpoint_id;
    checkpoint->position_count = 0;
    checkpoint->position_capacity = 16;  // 初始容量
    
    checkpoint->positions = (FilePosition*)calloc(checkpoint->position_capacity, sizeof(FilePosition));
    if (!checkpoint->positions) {
        free(checkpoint);
        pthread_mutex_unlock(&manager->mutex);
        return NULL;
    }
    
    if (source_path) {
        strncpy(checkpoint->source_path, source_path, sizeof(checkpoint->source_path) - 1);
    }
    
    if (dest_path) {
        strncpy(checkpoint->dest_path, dest_path, sizeof(checkpoint->dest_path) - 1);
    }
    
    // 计算初始校验和
    checkpoint_calculate_checksum(checkpoint);
    
    manager->current_checkpoint = checkpoint;
    
    pthread_mutex_unlock(&manager->mutex);
    
    return checkpoint;
}

Checkpoint* checkpoint_load(CheckpointManager* manager, uint64_t checkpoint_id) {
    if (!manager) return NULL;
    
    char path[512];
    get_checkpoint_path(manager, checkpoint_id, path);
    
    FILE* fp = fopen(path, "rb");
    if (!fp) {
        return NULL;
    }
    
    Checkpoint* checkpoint = (Checkpoint*)calloc(1, sizeof(Checkpoint));
    if (!checkpoint) {
        fclose(fp);
        return NULL;
    }
    
    // 读取检查点数据
    size_t read_size = fread(checkpoint, 1, sizeof(Checkpoint), fp);
    fclose(fp);
    
    if (read_size < sizeof(Checkpoint) - sizeof(FilePosition*)) {
        free(checkpoint);
        return NULL;
    }
    
    // 重新分配位置数组
    checkpoint->positions = (FilePosition*)calloc(
        checkpoint->position_capacity, sizeof(FilePosition)
    );
    if (!checkpoint->positions) {
        free(checkpoint);
        return NULL;
    }
    
    // 读取位置数据
    fp = fopen(path, "rb");
    fseek(fp, sizeof(Checkpoint) - sizeof(FilePosition*), SEEK_SET);
    fread(checkpoint->positions, sizeof(FilePosition), checkpoint->position_count, fp);
    fclose(fp);
    
    // 验证检查点
    if (!checkpoint_verify(checkpoint)) {
        free(checkpoint->positions);
        free(checkpoint);
        return NULL;
    }
    
    pthread_mutex_lock(&manager->mutex);
    if (manager->current_checkpoint) {
        free(manager->current_checkpoint->positions);
        free(manager->current_checkpoint);
    }
    manager->current_checkpoint = checkpoint;
    pthread_mutex_unlock(&manager->mutex);
    
    return checkpoint;
}

int checkpoint_save(CheckpointManager* manager, Checkpoint* checkpoint) {
    if (!manager || !checkpoint) return -1;
    
    char path[512];
    get_checkpoint_path(manager, checkpoint->checkpoint_id, path);
    
    // 临时文件
    char temp_path[512];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);
    
    FILE* fp = fopen(temp_path, "wb");
    if (!fp) {
        return -1;
    }
    
    // 保存检查点数据（不包含positions指针）
    FilePosition* temp_positions = checkpoint->positions;
    checkpoint->positions = NULL;
    fwrite(checkpoint, 1, sizeof(Checkpoint), fp);
    checkpoint->positions = temp_positions;
    
    // 保存位置数据
    fwrite(checkpoint->positions, sizeof(FilePosition), checkpoint->position_count, fp);
    
    fclose(fp);
    
    // 原子重命名
    if (rename(temp_path, path) != 0) {
        remove(temp_path);
        return -1;
    }
    
    checkpoint->update_time = get_timestamp();
    
    return 0;
}

int checkpoint_update(CheckpointManager* manager, Checkpoint* checkpoint,
                     uint64_t file_id, uint64_t processed_bytes) {
    if (!manager || !checkpoint) return -1;
    
    pthread_mutex_lock(&manager->mutex);
    
    checkpoint->last_file_id = file_id;
    checkpoint->processed_count++;
    checkpoint->processed_bytes += processed_bytes;
    checkpoint->update_time = get_timestamp();
    
    // 更新校验和
    checkpoint_calculate_checksum(checkpoint);
    
    // 自动保存
    if (manager->auto_save && 
        (checkpoint->processed_count - manager->last_save_count) >= manager->save_interval) {
        checkpoint_save(manager, checkpoint);
        manager->last_save_count = checkpoint->processed_count;
    }
    
    pthread_mutex_unlock(&manager->mutex);
    
    return 0;
}

int checkpoint_add_position(Checkpoint* checkpoint, FilePosition* position) {
    if (!checkpoint || !position) return -1;
    
    // 检查是否需要扩容
    if (checkpoint->position_count >= checkpoint->position_capacity) {
        uint32_t new_capacity = checkpoint->position_capacity * 2;
        FilePosition* new_positions = (FilePosition*)realloc(
            checkpoint->positions, new_capacity * sizeof(FilePosition)
        );
        
        if (!new_positions) {
            return -1;
        }
        
        checkpoint->positions = new_positions;
        checkpoint->position_capacity = new_capacity;
    }
    
    // 添加位置
    memcpy(&checkpoint->positions[checkpoint->position_count], position, sizeof(FilePosition));
    checkpoint->position_count++;
    
    return 0;
}

FilePosition* checkpoint_get_position(Checkpoint* checkpoint, uint64_t file_id) {
    if (!checkpoint) return NULL;
    
    for (uint32_t i = 0; i < checkpoint->position_count; i++) {
        if (checkpoint->positions[i].file_id == file_id) {
            return &checkpoint->positions[i];
        }
    }
    
    return NULL;
}

int checkpoint_complete_file(Checkpoint* checkpoint, uint64_t file_id) {
    if (!checkpoint) return -1;
    
    FilePosition* position = checkpoint_get_position(checkpoint, file_id);
    if (position) {
        position->completed = 1;
        return 0;
    }
    
    return -1;
}

int checkpoint_delete(CheckpointManager* manager, uint64_t checkpoint_id) {
    if (!manager) return -1;
    
    char path[512];
    get_checkpoint_path(manager, checkpoint_id, path);
    
    if (remove(path) == 0) {
        return 0;
    }
    
    return -1;
}

Checkpoint** checkpoint_list(CheckpointManager* manager, uint32_t* count) {
    if (!manager || !count) return NULL;
    
    *count = 0;
    return NULL;
    
    // TODO: 实现列出检查点的逻辑
}

void checkpoint_free_list(Checkpoint** checkpoints, uint32_t count) {
    if (!checkpoints) return;
    
    for (uint32_t i = 0; i < count; i++) {
        if (checkpoints[i]) {
            if (checkpoints[i]->positions) {
                free(checkpoints[i]->positions);
            }
            free(checkpoints[i]);
        }
    }
    
    free(checkpoints);
}

void checkpoint_calculate_checksum(Checkpoint* checkpoint) {
    if (!checkpoint) return;
    
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    
    // 计算关键字段的SHA-256
    SHA256_Update(&sha256, &checkpoint->checkpoint_id, sizeof(uint64_t));
    SHA256_Update(&sha256, &checkpoint->last_file_id, sizeof(uint64_t));
    SHA256_Update(&sha256, &checkpoint->processed_count, sizeof(uint64_t));
    SHA256_Update(&sha256, &checkpoint->processed_bytes, sizeof(uint64_t));
    SHA256_Update(&sha256, checkpoint->source_path, sizeof(checkpoint->source_path));
    SHA256_Update(&sha256, checkpoint->dest_path, sizeof(checkpoint->dest_path));
    
    unsigned char hash[32];
    SHA256_Final(hash, &sha256);
    
    memcpy(checkpoint->checksum, hash, 32);
}

int checkpoint_verify(Checkpoint* checkpoint) {
    if (!checkpoint) return 0;
    
    // 计算当前校验和
    uint8_t calculated_checksum[32];
    memcpy(calculated_checksum, checkpoint->checksum, 32);
    checkpoint_calculate_checksum(checkpoint);
    
    // 比较
    int valid = (memcmp(calculated_checksum, checkpoint->checksum, 32) == 0);
    
    return valid;
}

// ============ 错误恢复实现 ============

int retry_operation(RetryConfig* config, RecoveryStats* stats,
                   int (*operation)(void*), void* arg) {
    if (!config || !stats || !operation) return -1;
    
    for (uint32_t attempt = 0; attempt <= config->max_attempts; attempt++) {
        int result = operation(arg);
        
        if (result == 0) {
            // 成功
            return 0;
        }
        
        // 失败
        stats->retry_count++;
        
        // 记录错误
        char error_msg[512];
        snprintf(error_msg, sizeof(error_msg), "Attempt %u failed", attempt + 1);
        log_error(stats, error_msg);
        
        // 如果是最后一次尝试，跳过或返回失败
        if (attempt == config->max_attempts) {
            if (config->skip_on_failure) {
                stats->skip_count++;
                return 0;  // �过，视为成功
            } else {
                return -1;  // 失败
            }
        }
        
        // 等待后重试
        retry_wait(config, attempt);
    }
    
    return -1;
}

void retry_wait(RetryConfig* config, uint32_t attempt) {
    uint32_t delay = get_retry_delay(config, attempt);
#ifdef _WIN32
    Sleep(delay);
#else
    usleep(delay * 1000);  // 转换为微秒
#endif
}

uint32_t get_retry_delay(RetryConfig* config, uint32_t attempt) {
    if (!config) return DEFAULT_INITIAL_DELAY;
    
    switch (config->strategy) {
        case RETRY_IMMEDIATE:
            return 0;
        
        case RETRY_DELAYED:
            return config->initial_delay_ms;
        
        case RETRY_EXPONENTIAL:
            // 指数退避
            uint32_t delay = config->initial_delay_ms;
            for (uint32_t i = 0; i < attempt; i++) {
                delay = (uint32_t)(delay * config->backoff_factor);
                if (delay > config->max_delay_ms) {
                    delay = config->max_delay_ms;
                    break;
                }
            }
            return delay;
        
        default:
            return DEFAULT_INITIAL_DELAY;
    }
}

void reset_recovery_stats(RecoveryStats* stats) {
    if (!stats) return;
    
    memset(stats, 0, sizeof(RecoveryStats));
}

void log_error(RecoveryStats* stats, const char* error_msg) {
    if (!stats || !error_msg) return;
    
    stats->error_count++;
    strncpy(stats->last_error, error_msg, sizeof(stats->last_error) - 1);
    stats->last_error[sizeof(stats->last_error) - 1] = '\0';
}

// ============ 断点续传实现 ============

int resume_from_checkpoint(CheckpointManager* manager, Checkpoint* checkpoint,
                          int (*process_file)(FilePosition*, void*), void* context) {
    if (!manager || !checkpoint || !process_file) return -1;
    
    // 处理每个文件的断点
    for (uint32_t i = 0; i < checkpoint->position_count; i++) {
        FilePosition* position = &checkpoint->positions[i];
        
        if (!position->completed) {
            // 从断点位置继续处理
            int result = process_file(position, context);
            
            if (result != 0) {
                return -1;
            }
            
            // 标记为完成
            position->completed = 1;
        }
    }
    
    return 0;
}

int verify_transferred_data(Checkpoint* checkpoint, const void* data, size_t size) {
    if (!checkpoint || !data) return -1;
    
    // 计算CRC32
    uint32_t checksum = calculate_crc32_parallel(data, size, 4);
    
    // 查找对应的文件位置并验证
    for (uint32_t i = 0; i < checkpoint->position_count; i++) {
        if (checkpoint->positions[i].checksum == checksum) {
            return 0;  // 验证通过
        }
    }
    
    return -1;  // 验证失败
}

int repair_checkpoint(Checkpoint* checkpoint) {
    if (!checkpoint) return -1;
    
    // 重新计算校验和
    checkpoint_calculate_checksum(checkpoint);
    
    return 0;
}

int cleanup_old_checkpoints(CheckpointManager* manager, uint64_t keep_count) {
    if (!manager) return -1;
    
    // TODO: 实现清理旧检查点的逻辑
    // 1. 列出所有检查点
    // 2. 按更新时间排序
    // 3. 删除超过keep_count的旧检查点
    
    return 0;
}

#ifdef _WIN32
// SHA-256实现（公共领域）
static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTRIGHT(word,bits) (((word) >> (bits)) | ((word) << (32-(bits))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static void sha256_transform(SHA256_CTX* ctx, const unsigned char data[]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];
    
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    for (; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    
    a = ctx->h[0];
    b = ctx->h[1];
    c = ctx->h[2];
    d = ctx->h[3];
    e = ctx->h[4];
    f = ctx->h[5];
    g = ctx->h[6];
    h = ctx->h[7];
    
    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    
    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;
    ctx->h[5] += f;
    ctx->h[6] += g;
    ctx->h[7] += h;
}

void SHA256_Init(SHA256_CTX* ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->h[0] = 0x6a09e667;
    ctx->h[1] = 0xbb67ae85;
    ctx->h[2] = 0x3c6ef372;
    ctx->h[3] = 0xa54ff53a;
    ctx->h[4] = 0x510e527f;
    ctx->h[5] = 0x9b05688c;
    ctx->h[6] = 0x1f83d9ab;
    ctx->h[7] = 0x5be0cd19;
}

void SHA256_Update(SHA256_CTX* ctx, const void* data, size_t len) {
    const unsigned char* d = (const unsigned char*)data;
    uint32_t i;
    
    for (i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = d[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

void SHA256_Final(unsigned char digest[SHA256_DIGEST_LENGTH], SHA256_CTX* ctx) {
    uint32_t i = ctx->datalen;
    
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56)
            ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64)
            ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }
    
    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    sha256_transform(ctx, ctx->data);
    
    for (i = 0; i < 4; ++i) {
        digest[i]      = (ctx->h[0] >> (24 - i * 8)) & 0x000000ff;
        digest[i + 4]  = (ctx->h[1] >> (24 - i * 8)) & 0x000000ff;
        digest[i + 8]  = (ctx->h[2] >> (24 - i * 8)) & 0x000000ff;
        digest[i + 12] = (ctx->h[3] >> (24 - i * 8)) & 0x000000ff;
        digest[i + 16] = (ctx->h[4] >> (24 - i * 8)) & 0x000000ff;
        digest[i + 20] = (ctx->h[5] >> (24 - i * 8)) & 0x000000ff;
        digest[i + 24] = (ctx->h[6] >> (24 - i * 8)) & 0x000000ff;
        digest[i + 28] = (ctx->h[7] >> (24 - i * 8)) & 0x000000ff;
    }
}
#endif
