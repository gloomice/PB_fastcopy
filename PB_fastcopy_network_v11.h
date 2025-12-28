/*
 * PB_fastcopy_network_v11.h
 * 
 * 极致性能的PB级小文件网络传输引擎
 * 支持：全异步管道、超级批处理、NUMA感知、FTP传输、零拷贝
 * 
 * 版本: v11.0
 */

#ifndef PB_FASTCOPY_NETWORK_V11_H
#define PB_FASTCOPY_NETWORK_V11_H

#include <windows.h>
#include <winsock2.h>
#include <mswsock.h>    // TransmitFile, AcceptEx, ConnectEx
#include <ntstatus.h>
#include <winternl.h>
#include <winhttp.h>
#include <ws2tcpip.h>
#include <intrin.h>
#include <xmmintrin.h>
#include <immintrin.h>  // AVX-512
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <sal.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mswsock.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "winhttp.lib")

// ====================== 架构宏定义 ======================
#define MAX_PATH_EXT           32768
#define MAX_FILE_PATH          1024
#define MAX_SUPER_BATCH_FILES  4096
#define SUPER_BATCH_SIZE       (16 * 1024 * 1024)
#define MAX_CONCURRENT_TASKS   131072
#define MAX_IO_THREADS         128
#define MAX_NUMA_NODES         8
#define MAX_RSS_QUEUES         64
#define MAX_FTP_SESSIONS_PER_NODE 32
#define PAGE_SIZE_2MB          (2 * 1024 * 1024)
#define PAGE_SIZE_64KB         (64 * 1024)
#define CACHE_LINE_SIZE        64
#define ALIGN_CACHE            __declspec(align(64))

// FTP相关常量
#define FTP_DEFAULT_PORT       21
#define FTP_DATA_PORT_RANGE_START 50000
#define FTP_DATA_PORT_RANGE_END   51000
#define FTP_CONTROL_TIMEOUT_MS   30000
#define FTP_DATA_TIMEOUT_MS      120000
#define FTP_MAX_RETRIES          3

// 内存池配置
#define SLAB_SIZE_4K           4096
#define SLAB_SIZE_64K          65536
#define SLAB_SIZE_1M           1048576
#define MAX_SLAB_CLASSES       32

// ====================== 枚举定义 ======================

// 异步操作类型
typedef enum {
    OP_NONE = 0,
    OP_FTP_CONNECT,
    OP_FTP_LOGIN,
    OP_FTP_PASV,
    OP_FTP_PORT,
    OP_FTP_STOR,
    OP_FTP_RETR,
    OP_FTP_SIZE,
    OP_FTP_MDTM,
    OP_FTP_REST,
    OP_FTP_CWD,
    OP_FTP_MKD,
    OP_FTP_RMD,
    OP_FTP_LIST,
    OP_TRANSMITFILE,
    OP_WSASEND,
    OP_WSARECV,
    OP_CONNECTEX,
    OP_ACCEPTEX,
    OP_READFILE,
    OP_WRITEFILE,
    OP_FILE_ENUM,
    OP_BATCH_TRANSMIT,
    OP_FTP_BATCH
} ASYNC_OPERATION;

// FTP传输模式
typedef enum {
    FTP_MODE_ASCII = 0,
    FTP_MODE_BINARY = 1,
    FTP_MODE_PASSIVE = 2
} FTP_TRANSFER_MODE;

// FTP状态码
typedef enum {
    FTP_CODE_READY = 220,
    FTP_CODE_LOGIN_SUCCESS = 230,
    FTP_CODE_LOGIN_NEED_PASSWORD = 331,
    FTP_CODE_PASSIVE_MODE = 227,
    FTP_CODE_EXT_PASSIVE_MODE = 229,
    FTP_CODE_FILE_OK = 150,
    FTP_CODE_TRANSFER_COMPLETE = 226,
    FTP_CODE_COMMAND_OK = 200,
    FTP_CODE_PATHNAME_CREATED = 257,
    FTP_CODE_FILE_STATUS = 213,
    FTP_CODE_RESTART_MARKER = 350,
    FTP_CODE_NOT_LOGGED_IN = 530,
    FTP_CODE_FILE_UNAVAILABLE = 550
} FTP_RESPONSE_CODE;

// 任务状态
typedef enum {
    TASK_STATE_PENDING = 0,
    TASK_STATE_CONNECTING,
    TASK_STATE_TRANSFERRING,
    TASK_STATE_COMPLETED,
    TASK_STATE_FAILED,
    TASK_STATE_CANCELLED,
    TASK_STATE_RESUMING
} TASK_STATE;

// ====================== 核心数据结构 ======================

// NTFS文件指纹
typedef struct {
    ULONGLONG   nFileIndexHigh;
    ULONGLONG   nFileIndexLow;
    LONGLONG    FileSize;
    LARGE_INTEGER LastWriteTime;
    ULONG       Crc32;
    ULONG       FastCrc32;      // 快速校验（前4KB）
} ALIGN_CACHE FILE_FINGERPRINT;

// FTP会话（每个NUMA节点一个连接池）
typedef struct _FTP_SESSION {
    SOCKET              ControlSocket;
    SOCKET              DataSocket;
    SOCKET              ListenSocket;   // 主动模式监听
    char                Server[256];
    DWORD               Port;
    char                Username[64];
    char                Password[64];
    FTP_TRANSFER_MODE   TransferMode;
    BOOL                PassiveMode;
    BOOL                ExtendedPassive;
    BOOL                Connected;
    BOOL                LoggedIn;
    DWORD               LastResponseCode;
    char                LastResponse[1024];
    CRITICAL_SECTION    Lock;
    DWORD               Timeout;
    ULONGLONG           TotalBytesSent;
    ULONGLONG           TotalFilesSent;
    DWORD               ReconnectCount;
    DWORD               NumaNode;
    HANDLE              IoCompletionPort;
    struct _FTP_SESSION* Next;          // 连接池链表
    LARGE_INTEGER       LastUsedTime;   // 最后使用时间（用于连接池清理）
    BOOL                InUse;          // 是否正在使用
} ALIGN_CACHE FTP_SESSION;

// FTP连接池
typedef struct {
    FTP_SESSION*        Sessions[MAX_FTP_SESSIONS_PER_NODE];
    DWORD               Count;
    DWORD               MaxSessions;
    DWORD               NumaNode;
    CRITICAL_SECTION    Lock;
    ULONGLONG           TotalAcquires;
    ULONGLONG           TotalReleases;
    ULONGLONG           CacheHits;
    ULONGLONG           CacheMisses;
} ALIGN_CACHE FTP_CONNECTION_POOL;

// 超级批处理包结构
#pragma pack(push, 1)
typedef struct {
    DWORD               Magic;          // 0x50534654 ('PSFT')
    DWORD               Version;        // 协议版本
    ULONGLONG           BatchId;        // 批处理ID
    ULONGLONG           TotalSize;      // 总数据大小
    DWORD               FileCount;      // 文件数量
    DWORD               Checksum;       // 头校验和
    ULONGLONG           Timestamp;      // 创建时间戳
    DWORD               Flags;          // 标志位
    DWORD               Reserved[12];   // 保留字段
} SUPER_BATCH_HEADER;

typedef struct {
    ULONGLONG           FileIdHigh;
    ULONGLONG           FileIdLow;
    ULONGLONG           FileSize;
    ULONGLONG           DataOffset;     // 在批处理中的数据偏移
    ULONGLONG           DataSize;
    DWORD               Attributes;
    DWORD               Crc32;
    WCHAR               FileName[256];  // Unicode文件名
} SUPER_BATCH_FILE_ENTRY;
#pragma pack(pop)

typedef struct {
    SUPER_BATCH_HEADER      Header;
    SUPER_BATCH_FILE_ENTRY  Entries[MAX_SUPER_BATCH_FILES];
    BYTE                    Data[SUPER_BATCH_SIZE];
} ALIGN_CACHE SUPER_BATCH_PACKET;

// 全异步任务上下文
typedef struct _FULL_ASYNC_CONTEXT {
    OVERLAPPED          Overlapped;
    ASYNC_OPERATION     Operation;
    DWORD               NumaNode;
    DWORD               RetryCount;
    union {
        struct {
            FTP_SESSION*    pSession;
            char            RemotePath[1024];
            HANDLE          hFile;
            ULONGLONG       FileOffset;
            ULONGLONG       BytesToTransfer;
            ULONGLONG       BytesTransferred;
            DWORD           Flags;
            BOOL            Resume;
        } FtpTransmit;
        
        struct {
            FTP_SESSION*    pSession;
            char            Command[64];
            char            Argument[512];
            DWORD           ExpectedResponse;
            char            ResponseBuffer[1024];
        } FtpCommand;
        
        struct {
            SUPER_BATCH_PACKET* pBatch;
            FTP_SESSION*        pSession;
            char                RemotePath[1024];
            DWORD               BytesSent;
            DWORD               CurrentBuffer;
        } FtpBatch;
        
        struct {
            WSABUF          Buffers[16];    // Scatter/Gather I/O
            DWORD           BufferCount;
            SOCKET          Socket;
            DWORD           Flags;
        } WsaSend;
        
        struct {
            WCHAR           Path[MAX_PATH_EXT];
            BOOL            Recursive;
            DWORD           MaxDepth;
            HANDLE          DirectoryHandle;
        } Enum;
    };
    
    PVOID               UserContext;
    struct _FULL_ASYNC_CONTEXT* Next;
} FULL_ASYNC_CONTEXT;

// 传输任务
typedef struct {
    WCHAR               LocalPath[MAX_PATH_EXT];
    WCHAR               RemotePath[MAX_FILE_PATH];
    FILE_FINGERPRINT    Fingerprint;
    LARGE_INTEGER       FileSize;
    LARGE_INTEGER       TransferOffset;
    TASK_STATE          State;
    DWORD               Flags;
    DWORD               NumaNode;
    HANDLE              hFile;
    SOCKET              DataSocket;
    FTP_SESSION*        pFtpSession;
    FULL_ASYNC_CONTEXT* pAsyncContext;
    LARGE_INTEGER       StartTime;
    LARGE_INTEGER       EndTime;
    DWORD               ErrorCode;
    char                ErrorMessage[256];
} ALIGN_CACHE TRANSFER_TASK_V11;

// NUMA节点信息
typedef struct {
    DWORD               NodeId;
    DWORD               CpuCount;
    KAFFINITY           CpuMask;
    ULONGLONG           TotalMemory;
    ULONGLONG           AvailableMemory;
    DWORD               RssQueues[MAX_RSS_QUEUES];
    DWORD               RssQueueCount;
    HANDLE              IoCompletionPort;
    HANDLE              WorkThreads[MAX_IO_THREADS / MAX_NUMA_NODES];
    DWORD               WorkThreadCount;
    FTP_CONNECTION_POOL* FtpPool;
    DWORD               ActiveTasks;
    ULONGLONG           BytesTransferred;
} ALIGN_CACHE NUMA_NODE_INFO;

// Slab内存分配器
typedef struct _SLAB_CLASS {
    DWORD               BlockSize;
    DWORD               BlocksPerSlab;
    DWORD               FreeCount;
    struct _SLAB*       SlabList;
    CRITICAL_SECTION    Lock;
    DWORD               NumaNode;
} SLAB_CLASS;

typedef struct _SLAB {
    struct _SLAB*       Next;
    BYTE*               Memory;
    DWORD               FreeCount;
    DWORD               FreeList[MAX_SUPER_BATCH_FILES];
    DWORD               NumaNode;
} SLAB;

typedef struct {
    SLAB_CLASS*         Classes[MAX_SLAB_CLASSES];
    DWORD               ClassCount;
    DWORD               NumaNode;
} SLAB_ALLOCATOR;

// 持久化任务数据库
typedef struct {
    HANDLE              hFile;
    HANDLE              hMapping;
    PVOID               pBaseAddress;
    ULONGLONG           MaxRecords;
    ULONGLONG           CurrentRecords;
    CRITICAL_SECTION    Lock;
    DWORD               NumaNode;
} TASK_DATABASE;

// 流控管理器
typedef struct {
    DWORD               DiskQueueDepth;
    DWORD               NetworkQueueDepth;
    DWORD               CurrentConcurrency;
    DWORD               MaxConcurrency;
    DWORD               TargetLatencyMs;
    DWORD               CurrentLatencyMs;
    ULONGLONG           BytesPerSecond;
    ULONGLONG           PeakBytesPerSecond;
    LARGE_INTEGER       LastAdjustmentTime;
    DWORD               AdjustmentInterval;
    DWORD               BackoffFactor;
    DWORD               SuccessiveFailures;
} FLOW_CONTROLLER;

// 无锁队列（Michael-Scott算法）
typedef struct _LOCKFREE_NODE {
    TRANSFER_TASK_V11*      pTask;
    struct _LOCKFREE_NODE*  Next;
} LOCKFREE_NODE;

typedef struct {
    volatile LOCKFREE_NODE* Head;
    volatile LOCKFREE_NODE* Tail;
    DWORD                   Count;
    SLAB_ALLOCATOR*         pAllocator;
} LOCKFREE_QUEUE;

// ====================== 配置结构 ======================

typedef struct {
    // 网络配置
    WCHAR               Server[256];
    WCHAR               Username[64];
    WCHAR               Password[64];
    DWORD               Port;
    DWORD               MaxConnections;
    
    // FTP配置
    BOOL                EnableFtp;
    BOOL                FtpPassiveMode;
    BOOL                FtpExtendedPassive;
    BOOL                FtpBinaryMode;
    BOOL                FtpUseTLS;
    BOOL                FtpUseRestart;
    BOOL                FtpVerifyUpload;
    DWORD               FtpTimeout;
    DWORD               FtpMaxRetries;
    DWORD               FtpMaxSessionsPerNode;
    BOOL                FtpConnectionPooling;
    DWORD               FtpConnectionIdleTimeout;
    DWORD               FtpDataPortRangeStart;
    DWORD               FtpDataPortRangeEnd;
    
    // 性能配置
    DWORD               IoThreadPerNuma;
    DWORD               MaxBatchSize;
    DWORD               MaxFileSize;
    BOOL                EnableZeroCopy;
    BOOL                EnableAggregation;
    BOOL                EnableResume;
    BOOL                EnableRssAffinity;
    BOOL                EnableNumaAwareness;
    BOOL                EnablePersistentDb;
    BOOL                EnableFlowControl;
    
    // 批处理配置
    DWORD               MinBatchSize;
    DWORD               BatchTimeoutMs;
    
    // 流控配置
    DWORD               MaxConcurrentFiles;
    DWORD               DiskQueueHighWatermark;
    DWORD               DiskQueueLowWatermark;
    ULONGLONG           BandwidthLimit;    // bytes/sec, 0 = unlimited
    
    // 路径配置
    WCHAR               LocalRoot[MAX_PATH_EXT];
    WCHAR               RemoteRoot[MAX_PATH_EXT];
} TRANSFER_CONFIG_V11;

// 主引擎结构
typedef struct {
    // 配置
    TRANSFER_CONFIG_V11 Config;
    
    // 核心组件
    HANDLE                  hIOCP;
    HANDLE                  hEnumThread;
    volatile BOOL           bRunning;
    volatile BOOL           bPaused;
    CRITICAL_SECTION        EngineLock;
    
    // NUMA感知
    NUMA_NODE_INFO          NumaNodes[MAX_NUMA_NODES];
    DWORD                   NumaNodeCount;
    
    // 内存管理
    SLAB_ALLOCATOR*         SlabAllocators[MAX_NUMA_NODES];
    TASK_DATABASE*          TaskDb;
    
    // 任务队列
    LOCKFREE_QUEUE*         TaskQueues[MAX_NUMA_NODES];
    
    // 批处理
    FULL_ASYNC_CONTEXT*     BatchContexts[MAX_NUMA_NODES];
    CRITICAL_SECTION        BatchLock[MAX_NUMA_NODES];
    
    // 流控
    FLOW_CONTROLLER         FlowControl;
    
    // 统计
    struct {
        LARGE_INTEGER       StartTime;
        LARGE_INTEGER       EndTime;
        ULONGLONG           TotalFiles;
        ULONGLONG           TransferredFiles;
        ULONGLONG           SkippedFiles;
        ULONGLONG           FailedFiles;
        ULONGLONG           TotalBytes;
        ULONGLONG           TransferredBytes;
        DWORD               ZeroCopyOps;
        DWORD               SuperBatches;
        DWORD               AsyncCompletions;
        DWORD               NumaLocalAccess;
        DWORD               NumaRemoteAccess;
        DWORD               FtpConnections;
        DWORD               FtpReconnects;
        DWORD               CurrentConcurrency;
        DWORD               PeakConcurrency;
        DWORD               MemoryAllocations;
        DWORD               MemoryFrees;
    } Stats;
} PB_ENGINE_V11;

// ====================== 函数声明 ======================

// 引擎生命周期
BOOL PB11_Initialize(_In_ TRANSFER_CONFIG_V11* pConfig);
BOOL PB11_StartTransfer(_In_ LPCWSTR lpSource, _In_ LPCWSTR lpTarget);
BOOL PB11_PauseTransfer();
BOOL PB11_ResumeTransfer();
BOOL PB11_StopTransfer();
VOID PB11_Shutdown();

// FTP会话管理
FTP_SESSION* FTP_CreateSession(_In_ LPCSTR Server, _In_ DWORD Port,
                              _In_ LPCSTR Username, _In_ LPCSTR Password,
                              _In_ DWORD NumaNode);
BOOL FTP_Connect(_In_ FTP_SESSION* pSession);
BOOL FTP_Login(_In_ FTP_SESSION* pSession);
BOOL FTP_SetTransferMode(_In_ FTP_SESSION* pSession, _In_ FTP_TRANSFER_MODE Mode);
BOOL FTP_EnterPassiveMode(_In_ FTP_SESSION* pSession, _Out_ SOCKET* pDataSocket);
BOOL FTP_SetupDataConnection(_In_ FTP_SESSION* pSession, _Out_ SOCKET* pDataSocket);
BOOL FTP_SendCommand(_In_ FTP_SESSION* pSession, _In_ LPCSTR Command,
                    _In_opt_ LPCSTR Argument, _Out_ DWORD* pResponseCode,
                    _Out_ char* Response, _In_ DWORD ResponseSize);
BOOL FTP_ReadResponse(_In_ FTP_SESSION* pSession, _Out_ DWORD* pResponseCode,
                     _Out_ char* Buffer, _In_ DWORD BufferSize);
BOOL FTP_Disconnect(_In_ FTP_SESSION* pSession);
VOID FTP_DestroySession(_In_ FTP_SESSION* pSession);

// FTP传输操作
BOOL FTP_BeginTransfer(_In_ FTP_SESSION* pSession, _In_ LPCSTR RemotePath,
                      _In_ ULONGLONG FileSize, _In_ ULONGLONG ResumeOffset);
BOOL FTP_TransmitFileAsync(_In_ FTP_SESSION* pSession, _In_ HANDLE hFile,
                          _In_ ULONGLONG Offset, _In_ ULONGLONG Length,
                          _In_ FULL_ASYNC_CONTEXT* pContext);
BOOL FTP_CompleteTransfer(_In_ FTP_SESSION* pSession, _Out_ BOOL* pSuccess);

// FTP连接池
FTP_CONNECTION_POOL* FTP_CreateConnectionPool(_In_ DWORD MaxSessions,
                                             _In_ DWORD NumaNode);
FTP_SESSION* FTP_AcquireSession(_In_ FTP_CONNECTION_POOL* pPool,
                               _In_ LPCSTR Server, _In_ DWORD Port,
                               _In_ LPCSTR Username, _In_ LPCSTR Password);
VOID FTP_ReleaseSession(_In_ FTP_CONNECTION_POOL* pPool,
                       _In_ FTP_SESSION* pSession);
VOID FTP_DestroyConnectionPool(_In_ FTP_CONNECTION_POOL* pPool);

// 内存管理
PVOID PB11_Allocate(_In_ SIZE_T Size, _In_ DWORD NumaNode);
PVOID PB11_AllocateAligned(_In_ SIZE_T Size, _In_ SIZE_T Alignment,
                          _In_ DWORD NumaNode);
VOID PB11_Free(_In_ PVOID pMemory);
VOID PB11_FreeAligned(_In_ PVOID pMemory);
SLAB_ALLOCATOR* CreateSlabAllocator(_In_ DWORD NumaNode);
VOID DestroySlabAllocator(_In_ SLAB_ALLOCATOR* pAllocator);

// NUMA感知
DWORD PB11_GetCurrentNumaNode();
BOOL PB11_BindToNumaNode(_In_ DWORD NumaNode);
BOOL PB11_QueryNumaTopology();
PVOID PB11_AllocateNumaLocal(_In_ SIZE_T Size, _In_ DWORD NumaNode);

// 无锁队列
LOCKFREE_QUEUE* CreateLockfreeQueue(_In_ DWORD NumaNode);
BOOL EnqueueTask(_In_ LOCKFREE_QUEUE* pQueue, _In_ TRANSFER_TASK_V11* pTask);
TRANSFER_TASK_V11* DequeueTask(_In_ LOCKFREE_QUEUE* pQueue);
VOID DestroyLockfreeQueue(_In_ LOCKFREE_QUEUE* pQueue);

// 超级批处理
BOOL PB11_CreateSuperBatch(_In_ DWORD NumaNode);
BOOL PB11_AddFileToBatch(_In_ DWORD NumaNode, _In_ LPCWSTR lpFilePath,
                        _In_ LPCWSTR lpRemotePath, _In_ ULONGLONG FileSize);
BOOL PB11_SubmitSuperBatch(_In_ DWORD NumaNode);
BOOL PB11_TransmitSuperBatchAsync(_In_ FULL_ASYNC_CONTEXT* pContext);

// 全异步传输
BOOL PB11_TransmitFileZeroCopy(_In_ HANDLE hFile, _In_ SOCKET Socket,
                              _In_ ULONGLONG Offset, _In_ ULONGLONG Length,
                              _In_ FULL_ASYNC_CONTEXT* pContext);
BOOL PB11_ScatterSendAsync(_In_ SOCKET Socket, _In_ WSABUF* pBuffers,
                          _In_ DWORD BufferCount, _In_ FULL_ASYNC_CONTEXT* pContext);

// 文件枚举
BOOL NTAPI_EnumerateFiles(_In_ LPCWSTR lpRootPath, _In_ BOOL bRecursive,
                         _In_ DWORD dwMaxDepth);
BOOL ProcessDiscoveredFile(_In_ LPCWSTR lpFilePath, _In_ LPCWSTR lpRelativePath,
                          _In_ const WIN32_FILE_ATTRIBUTE_DATA* pFileAttr);

// 持久化数据库
BOOL PB11_InitTaskDatabase(_In_ LPCWSTR lpDbPath);
BOOL PB11_SaveTaskRecord(_In_ const FILE_FINGERPRINT* pFingerprint,
                        _In_ LPCWSTR lpLocalPath, _In_ LPCWSTR lpRemotePath,
                        _In_ ULONGLONG TransferOffset);
BOOL PB11_LoadTaskRecord(_In_ LPCWSTR lpFilePath, _Out_ FILE_FINGERPRINT* pFingerprint,
                        _Out_ ULONGLONG* pTransferOffset);

// 流控
BOOL PB11_InitFlowControl(_In_ DWORD MaxConcurrency, _In_ DWORD TargetLatencyMs);
BOOL PB11_AdjustFlowControl();
BOOL PB11_CanSubmitTask(_In_ DWORD NumaNode);

// 统计监控
BOOL PB11_GetStatistics(_Out_ PB_ENGINE_V11* pEngineCopy);
BOOL PB11_GetPerformanceCounters(_Out_ PVOID pCounters, _In_ DWORD Size);
VOID PB11_DumpStats();
VOID PB11_ResetStats();

// 回调函数类型
typedef VOID (*PFN_TASK_COMPLETE_CALLBACK)(
    _In_ TRANSFER_TASK_V11* pTask,
    _In_ DWORD ErrorCode,
    _In_opt_ PVOID UserContext
);

typedef VOID (*PFN_PROGRESS_CALLBACK)(
    _In_ ULONGLONG TransferredFiles,
    _In_ ULONGLONG TotalFiles,
    _In_ ULONGLONG TransferredBytes,
    _In_ ULONGLONG TotalBytes,
    _In_opt_ PVOID UserContext
);

typedef BOOL (*PFN_FILE_FILTER_CALLBACK)(
    _In_ LPCWSTR FilePath,
    _In_ const WIN32_FILE_ATTRIBUTE_DATA* pFileAttr,
    _In_opt_ PVOID UserContext
);

// 设置回调
BOOL PB11_SetTaskCompleteCallback(_In_ PFN_TASK_COMPLETE_CALLBACK pfnCallback,
                                 _In_opt_ PVOID UserContext);
BOOL PB11_SetProgressCallback(_In_ PFN_PROGRESS_CALLBACK pfnCallback,
                             _In_opt_ PVOID UserContext);
BOOL PB11_SetFileFilterCallback(_In_ PFN_FILE_FILTER_CALLBACK pfnCallback,
                               _In_opt_ PVOID UserContext);

// 高级功能
BOOL PB11_EnableCompression(_In_ BOOL Enable);
BOOL PB11_EnableEncryption(_In_ BOOL Enable);
BOOL PB11_SetBandwidthLimit(_In_ ULONGLONG BytesPerSecond);

// 调试支持
VOID PB11_EnableDebugLogging(_In_ BOOL Enable);
VOID PB11_DumpMemoryStats();

// ====================== 导出函数 ======================

#ifdef __cplusplus
extern "C" {
#endif

__declspec(dllexport) BOOL PB11_InitializeEngine(_In_ TRANSFER_CONFIG_V11* pConfig);
__declspec(dllexport) BOOL PB11_StartFileTransfer(_In_ LPCWSTR lpSource,
                                                 _In_ LPCWSTR lpTarget,
                                                 _In_ BOOL bResume);
__declspec(dllexport) BOOL PB11_GetTransferStatus(_Out_ PB_ENGINE_V11* pStats);
__declspec(dllexport) VOID PB11_StopEngine();
__declspec(dllexport) BOOL PB11_TestFtpConnection(_In_ LPCSTR Server,
                                                 _In_ DWORD Port,
                                                 _In_ LPCSTR Username,
                                                 _In_ LPCSTR Password);

#ifdef __cplusplus
}
#endif

// ====================== 内联辅助函数 ======================

FORCEINLINE DWORD GetSlabClass(_In_ SIZE_T Size) {
    if (Size <= 128) return 0;
    if (Size <= 256) return 1;
    if (Size <= 512) return 2;
    if (Size <= 1024) return 3;
    if (Size <= 2048) return 4;
    if (Size <= 4096) return 5;
    if (Size <= 8192) return 6;
    if (Size <= 16384) return 7;
    if (Size <= 32768) return 8;
    if (Size <= 65536) return 9;
    return 10; // 使用直接分配
}

FORCEINLINE BOOL ShouldUseSuperBatch(_In_ ULONGLONG FileSize) {
    return FileSize <= (64 * 1024); // 小于64KB的文件使用超级批处理
}

FORCEINLINE DWORD CalculateChecksum(_In_ const VOID* pData, _In_ SIZE_T Size) {
    DWORD checksum = 0;
    const BYTE* pBytes = (const BYTE*)pData;
    
    for (SIZE_T i = 0; i < Size; i++) {
        checksum ^= pBytes[i];
        checksum = _rotl(checksum, 1);
    }
    
    return checksum;
}

FORCEINLINE VOID PrefetchNuma(_In_ const VOID* pData, _In_ DWORD NumaNode) {
    _mm_prefetch((const char*)pData, _MM_HINT_T0);
}

FORCEINLINE ULONGLONG GetNanoTime() {
    LARGE_INTEGER counter, frequency;
    QueryPerformanceCounter(&counter);
    QueryPerformanceFrequency(&frequency);
    return (counter.QuadPart * 1000000000ULL) / frequency.QuadPart;
}

FORCEINLINE ULONGLONG GetMicroTime() {
    LARGE_INTEGER counter, frequency;
    QueryPerformanceCounter(&counter);
    QueryPerformanceFrequency(&frequency);
    return (counter.QuadPart * 1000000ULL) / frequency.QuadPart;
}

FORCEINLINE ULONGLONG GetMilliTime() {
    LARGE_INTEGER counter, frequency;
    QueryPerformanceCounter(&counter);
    QueryPerformanceFrequency(&frequency);
    return (counter.QuadPart * 1000ULL) / frequency.QuadPart;
}

FORCEINLINE VOID MemoryBarrier() {
    _mm_mfence();
}

FORCEINLINE LONG AtomicIncrement(volatile LONG* pValue) {
    return _InterlockedIncrement(pValue);
}

FORCEINLINE LONG AtomicDecrement(volatile LONG* pValue) {
    return _InterlockedDecrement(pValue);
}

FORCEINLINE LONG AtomicCompareExchange(volatile LONG* pDestination,
                                      LONG Exchange, LONG Comparand) {
    return _InterlockedCompareExchange(pDestination, Exchange, Comparand);
}

FORCEINLINE LONGLONG AtomicIncrement64(volatile LONGLONG* pValue) {
    return _InterlockedIncrement64(pValue);
}

FORCEINLINE LONGLONG AtomicDecrement64(volatile LONGLONG* pValue) {
    return _InterlockedDecrement64(pValue);
}

// 字符串转换辅助
FORCEINLINE BOOL WideToMultiByte(_In_ LPCWSTR lpWide, _Out_ LPSTR lpMulti,
                                _In_ DWORD dwMultiSize) {
    return WideCharToMultiByte(CP_UTF8, 0, lpWide, -1,
                              lpMulti, dwMultiSize, NULL, NULL) > 0;
}

FORCEINLINE BOOL MultiByteToWide(_In_ LPCSTR lpMulti, _Out_ LPWSTR lpWide,
                                _In_ DWORD dwWideSize) {
    return MultiByteToWideChar(CP_UTF8, 0, lpMulti, -1,
                              lpWide, dwWideSize) > 0;
}

#endif // PB_FASTCOPY_NETWORK_V11_H