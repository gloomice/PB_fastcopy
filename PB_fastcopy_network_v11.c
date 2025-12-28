/*
 * PB_fastcopy_network_v11.c
 * 
 * 极致性能的PB级小文件网络传输引擎实现
 * 版本: v11.0
 */

#include "PB_fastcopy_network_v11.h"
#include <iphlpapi.h>
#include <psapi.h>
#include <memoryapi.h>
#include <winnls.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "kernel32.lib")

// ====================== 全局引擎实例 ======================
static PB_ENGINE_V11 g_Engine = {0};
static volatile LONG g_EngineInitialized = 0;

// 回调函数
static PFN_TASK_COMPLETE_CALLBACK g_pfnTaskComplete = NULL;
static PFN_PROGRESS_CALLBACK g_pfnProgress = NULL;
static PFN_FILE_FILTER_CALLBACK g_pfnFileFilter = NULL;
static PVOID g_pTaskCompleteContext = NULL;
static PVOID g_pProgressContext = NULL;
static PVOID g_pFilterContext = NULL;

// 调试支持
static BOOL g_bDebugLogging = FALSE;

// ====================== 调试日志 ======================

VOID DebugLog(_In_ LPCSTR format, ...) {
    if (!g_bDebugLogging) return;
    
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsprintf_s(buffer, sizeof(buffer), format, args);
    va_end(args);
    
    OutputDebugStringA(buffer);
    OutputDebugStringA("\n");
}

VOID DebugLogW(_In_ LPCWSTR format, ...) {
    if (!g_bDebugLogging) return;
    
    WCHAR buffer[1024];
    va_list args;
    va_start(args, format);
    vswprintf_s(buffer, sizeof(buffer), format, args);
    va_end(args);
    
    OutputDebugStringW(buffer);
    OutputDebugStringW(L"\n");
}

// ====================== 内存分配器实现 ======================

SLAB_ALLOCATOR* CreateSlabAllocator(_In_ DWORD NumaNode) {
    SLAB_ALLOCATOR* pAllocator = (SLAB_ALLOCATOR*)VirtualAllocExNuma(
        GetCurrentProcess(),
        NULL,
        sizeof(SLAB_ALLOCATOR),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
        NumaNode
    );
    
    if (!pAllocator) {
        DebugLog("Failed to create slab allocator for NUMA node %u", NumaNode);
        return NULL;
    }
    
    ZeroMemory(pAllocator, sizeof(SLAB_ALLOCATOR));
    pAllocator->NumaNode = NumaNode;
    
    // 预定义的内存块大小类别
    static const DWORD s_ClassSizes[] = {
        128,   256,   512,   1024,  2048,  4096,
        8192,  16384, 32768, 65536, 131072, 262144,
        524288, 1048576, 2097152, 4194304
    };
    
    pAllocator->ClassCount = sizeof(s_ClassSizes) / sizeof(DWORD);
    
    for (DWORD i = 0; i < pAllocator->ClassCount; i++) {
        SLAB_CLASS* pClass = (SLAB_CLASS*)VirtualAllocExNuma(
            GetCurrentProcess(),
            NULL,
            sizeof(SLAB_CLASS),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
            NumaNode
        );
        
        if (!pClass) {
            DebugLog("Failed to create slab class %u for size %u", i, s_ClassSizes[i]);
            goto Cleanup;
        }
        
        ZeroMemory(pClass, sizeof(SLAB_CLASS));
        pClass->BlockSize = s_ClassSizes[i];
        pClass->BlocksPerSlab = SLAB_SIZE_1M / s_ClassSizes[i];
        if (pClass->BlocksPerSlab == 0) pClass->BlocksPerSlab = 1;
        pClass->NumaNode = NumaNode;
        InitializeCriticalSection(&pClass->Lock);
        
        pAllocator->Classes[i] = pClass;
        g_Engine.Stats.MemoryAllocations++;
    }
    
    DebugLog("Created slab allocator for NUMA node %u with %u classes",
            NumaNode, pAllocator->ClassCount);
    
    return pAllocator;
    
Cleanup:
    DestroySlabAllocator(pAllocator);
    return NULL;
}

VOID DestroySlabAllocator(_In_ SLAB_ALLOCATOR* pAllocator) {
    if (!pAllocator) return;
    
    for (DWORD i = 0; i < pAllocator->ClassCount; i++) {
        SLAB_CLASS* pClass = pAllocator->Classes[i];
        if (pClass) {
            // 释放所有Slab
            SLAB* pSlab = pClass->SlabList;
            while (pSlab) {
                SLAB* pNext = pSlab->Next;
                VirtualFree(pSlab, 0, MEM_RELEASE);
                g_Engine.Stats.MemoryFrees++;
                pSlab = pNext;
            }
            DeleteCriticalSection(&pClass->Lock);
            VirtualFree(pClass, 0, MEM_RELEASE);
            g_Engine.Stats.MemoryFrees++;
        }
    }
    
    VirtualFree(pAllocator, 0, MEM_RELEASE);
    g_Engine.Stats.MemoryFrees++;
}

static PVOID AllocateFromSlab(_In_ SLAB_ALLOCATOR* pAllocator, _In_ SIZE_T Size) {
    if (!pAllocator) return NULL;
    
    DWORD classIdx = GetSlabClass(Size);
    if (classIdx >= pAllocator->ClassCount) {
        // 大内存，直接分配
        DebugLog("Large allocation (%zu bytes) from NUMA node %u",
                Size, pAllocator->NumaNode);
        return VirtualAllocExNuma(
            GetCurrentProcess(),
            NULL,
            Size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
            pAllocator->NumaNode
        );
    }
    
    SLAB_CLASS* pClass = pAllocator->Classes[classIdx];
    EnterCriticalSection(&pClass->Lock);
    
    // 查找有空闲块的Slab
    SLAB* pSlab = pClass->SlabList;
    while (pSlab && pSlab->FreeCount == 0) {
        pSlab = pSlab->Next;
    }
    
    if (!pSlab) {
        // 创建新的Slab
        SIZE_T slabSize = sizeof(SLAB) + SLAB_SIZE_1M;
        if (pClass->BlockSize > SLAB_SIZE_1M) {
            slabSize = sizeof(SLAB) + pClass->BlockSize * pClass->BlocksPerSlab;
        }
        
        pSlab = (SLAB*)VirtualAllocExNuma(
            GetCurrentProcess(),
            NULL,
            slabSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
            pAllocator->NumaNode
        );
        
        if (!pSlab) {
            LeaveCriticalSection(&pClass->Lock);
            DebugLog("Failed to create new slab for class %u", classIdx);
            return NULL;
        }
        
        ZeroMemory(pSlab, sizeof(SLAB));
        pSlab->Memory = (BYTE*)pSlab + sizeof(SLAB);
        pSlab->FreeCount = pClass->BlocksPerSlab;
        pSlab->NumaNode = pAllocator->NumaNode;
        
        for (DWORD i = 0; i < pClass->BlocksPerSlab; i++) {
            pSlab->FreeList[i] = i;
        }
        
        pSlab->Next = pClass->SlabList;
        pClass->SlabList = pSlab;
        pClass->FreeCount += pClass->BlocksPerSlab;
        g_Engine.Stats.MemoryAllocations++;
        
        DebugLog("Created new slab for class %u (block size %u)",
                classIdx, pClass->BlockSize);
    }
    
    // 分配块
    DWORD blockIdx = pSlab->FreeList[--pSlab->FreeCount];
    PVOID pBlock = pSlab->Memory + (blockIdx * pClass->BlockSize);
    
    pClass->FreeCount--;
    
    LeaveCriticalSection(&pClass->Lock);
    
    // 清空内存（可选，为了安全）
    ZeroMemory(pBlock, pClass->BlockSize);
    
    return pBlock;
}

static VOID FreeToSlab(_In_ SLAB_ALLOCATOR* pAllocator, _In_ PVOID pMemory, _In_ SIZE_T Size) {
    if (!pAllocator || !pMemory) return;
    
    DWORD classIdx = GetSlabClass(Size);
    if (classIdx >= pAllocator->ClassCount) {
        // 大内存直接释放
        VirtualFree(pMemory, 0, MEM_RELEASE);
        g_Engine.Stats.MemoryFrees++;
        return;
    }
    
    SLAB_CLASS* pClass = pAllocator->Classes[classIdx];
    if (!pClass) {
        VirtualFree(pMemory, 0, MEM_RELEASE);
        g_Engine.Stats.MemoryFrees++;
        return;
    }
    
    EnterCriticalSection(&pClass->Lock);
    
    // 查找包含该内存的Slab
    SLAB* pSlab = pClass->SlabList;
    SLAB* pPrev = NULL;
    
    while (pSlab) {
        BYTE* slabStart = pSlab->Memory;
        BYTE* slabEnd = slabStart + (pClass->BlocksPerSlab * pClass->BlockSize);
        
        if ((BYTE*)pMemory >= slabStart && (BYTE*)pMemory < slabEnd) {
            break;
        }
        
        pPrev = pSlab;
        pSlab = pSlab->Next;
    }
    
    if (!pSlab) {
        // 不在Slab中，直接释放
        VirtualFree(pMemory, 0, MEM_RELEASE);
        g_Engine.Stats.MemoryFrees++;
        LeaveCriticalSection(&pClass->Lock);
        return;
    }
    
    // 计算块索引
    DWORD blockIdx = ((BYTE*)pMemory - pSlab->Memory) / pClass->BlockSize;
    
    // 添加到空闲列表
    pSlab->FreeList[pSlab->FreeCount++] = blockIdx;
    pClass->FreeCount++;
    
    // 如果Slab完全空闲且不是第一个，可以释放它
    if (pSlab->FreeCount == pClass->BlocksPerSlab && pPrev) {
        pPrev->Next = pSlab->Next;
        VirtualFree(pSlab, 0, MEM_RELEASE);
        g_Engine.Stats.MemoryFrees++;
    }
    
    LeaveCriticalSection(&pClass->Lock);
}

PVOID PB11_Allocate(_In_ SIZE_T Size, _In_ DWORD NumaNode) {
    if (NumaNode >= g_Engine.NumaNodeCount) {
        NumaNode = 0;
    }
    
    SLAB_ALLOCATOR* pAllocator = g_Engine.SlabAllocators[NumaNode];
    if (pAllocator) {
        PVOID pMemory = AllocateFromSlab(pAllocator, Size);
        if (pMemory) {
            AtomicIncrement64((LONGLONG*)&g_Engine.Stats.MemoryAllocations);
            return pMemory;
        }
    }
    
    // 回退到NUMA感知的VirtualAlloc
    DebugLog("Falling back to VirtualAllocExNuma for size %zu on node %u",
            Size, NumaNode);
    
    PVOID pMemory = VirtualAllocExNuma(
        GetCurrentProcess(),
        NULL,
        Size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
        NumaNode
    );
    
    if (pMemory) {
        AtomicIncrement64((LONGLONG*)&g_Engine.Stats.MemoryAllocations);
    }
    
    return pMemory;
}

PVOID PB11_AllocateAligned(_In_ SIZE_T Size, _In_ SIZE_T Alignment, _In_ DWORD NumaNode) {
    // 确保对齐是2的幂
    if ((Alignment & (Alignment - 1)) != 0) {
        Alignment = 1;
        while (Alignment < Size) Alignment <<= 1;
    }
    
    SIZE_T alignedSize = Size + Alignment + sizeof(void*) + sizeof(DWORD);
    
    PVOID pOriginal = PB11_Allocate(alignedSize, NumaNode);
    if (!pOriginal) return NULL;
    
    // 计算对齐地址
    PVOID pAligned = (PVOID)(((ULONG_PTR)pOriginal + Alignment + sizeof(void*) + sizeof(DWORD)) & ~(Alignment - 1));
    
    // 在调整后的地址前面存储原始指针和NUMA节点
    *((PVOID*)((BYTE*)pAligned - sizeof(void*))) = pOriginal;
    *((DWORD*)((BYTE*)pAligned - sizeof(void*) - sizeof(DWORD))) = NumaNode;
    
    return pAligned;
}

VOID PB11_Free(_In_ PVOID pMemory) {
    if (!pMemory) return;
    
    // 尝试从所有分配器释放
    for (DWORD i = 0; i < g_Engine.NumaNodeCount; i++) {
        // 简化实现：假设内存来自正确的分配器
        if (g_Engine.SlabAllocators[i]) {
            // 在实际实现中需要跟踪内存大小
            // 这里简化处理
        }
    }
    
    VirtualFree(pMemory, 0, MEM_RELEASE);
    AtomicIncrement64((LONGLONG*)&g_Engine.Stats.MemoryFrees);
}

VOID PB11_FreeAligned(_In_ PVOID pMemory) {
    if (!pMemory) return;
    
    // 获取原始指针
    PVOID pOriginal = *((PVOID*)((BYTE*)pMemory - sizeof(void*)));
    
    PB11_Free(pOriginal);
}

// ====================== 无锁队列实现 ======================

LOCKFREE_QUEUE* CreateLockfreeQueue(_In_ DWORD NumaNode) {
    LOCKFREE_QUEUE* pQueue = (LOCKFREE_QUEUE*)PB11_Allocate(
        sizeof(LOCKFREE_QUEUE), NumaNode);
    
    if (!pQueue) {
        return NULL;
    }
    
    ZeroMemory(pQueue, sizeof(LOCKFREE_QUEUE));
    pQueue->pAllocator = g_Engine.SlabAllocators[NumaNode];
    
    // 创建哨兵节点
    LOCKFREE_NODE* pSentinel = (LOCKFREE_NODE*)PB11_Allocate(
        sizeof(LOCKFREE_NODE), NumaNode);
    
    if (!pSentinel) {
        PB11_Free(pQueue);
        return NULL;
    }
    
    ZeroMemory(pSentinel, sizeof(LOCKFREE_NODE));
    pSentinel->pTask = NULL;
    pSentinel->Next = NULL;
    
    pQueue->Head = pSentinel;
    pQueue->Tail = pSentinel;
    pQueue->Count = 0;
    
    return pQueue;
}

BOOL EnqueueTask(_In_ LOCKFREE_QUEUE* pQueue, _In_ TRANSFER_TASK_V11* pTask) {
    if (!pQueue || !pTask) return FALSE;
    
    LOCKFREE_NODE* pNewNode = (LOCKFREE_NODE*)PB11_Allocate(
        sizeof(LOCKFREE_NODE), pTask->NumaNode);
    
    if (!pNewNode) return FALSE;
    
    pNewNode->pTask = pTask;
    pNewNode->Next = NULL;
    
    // Michael-Scott算法入队
    LOCKFREE_NODE* pTail;
    LOCKFREE_NODE* pNext;
    
    while (TRUE) {
        pTail = (LOCKFREE_NODE*)pQueue->Tail;
        pNext = pTail->Next;
        
        // 检查Tail是否仍然指向最后一个节点
        if (pTail == (LOCKFREE_NODE*)pQueue->Tail) {
            if (pNext == NULL) {
                // 尝试将新节点链接到队尾
                if (InterlockedCompareExchangePointer(
                    (PVOID volatile*)&pTail->Next, pNewNode, pNext) == pNext) {
                    // 成功，尝试移动Tail指针
                    InterlockedCompareExchangePointer(
                        (PVOID volatile*)&pQueue->Tail, pNewNode, pTail);
                    AtomicIncrement((LONG*)&pQueue->Count);
                    return TRUE;
                }
            } else {
                // 帮助其他线程完成操作
                InterlockedCompareExchangePointer(
                    (PVOID volatile*)&pQueue->Tail, pNext, pTail);
            }
        }
    }
}

TRANSFER_TASK_V11* DequeueTask(_In_ LOCKFREE_QUEUE* pQueue) {
    if (!pQueue || pQueue->Count == 0) return NULL;
    
    LOCKFREE_NODE* pHead;
    LOCKFREE_NODE* pTail;
    LOCKFREE_NODE* pNext;
    TRANSFER_TASK_V11* pTask = NULL;
    
    while (TRUE) {
        pHead = (LOCKFREE_NODE*)pQueue->Head;
        pTail = (LOCKFREE_NODE*)pQueue->Tail;
        pNext = pHead->Next;
        
        // 检查Head是否仍然指向第一个节点
        if (pHead == (LOCKFREE_NODE*)pQueue->Head) {
            if (pHead == pTail) {
                // 队列为空或Tail指针落后
                if (pNext == NULL) {
                    return NULL; // 队列为空
                }
                // 帮助移动Tail指针
                InterlockedCompareExchangePointer(
                    (PVOID volatile*)&pQueue->Tail, pNext, pTail);
            } else {
                // 读取任务
                pTask = pNext->pTask;
                
                // 尝试移动Head指针
                if (InterlockedCompareExchangePointer(
                    (PVOID volatile*)&pQueue->Head, pNext, pHead) == pHead) {
                    // 成功出队
                    AtomicDecrement((LONG*)&pQueue->Count);
                    
                    // 释放旧的头节点
                    PB11_Free(pHead);
                    
                    return pTask;
                }
            }
        }
    }
}

VOID DestroyLockfreeQueue(_In_ LOCKFREE_QUEUE* pQueue) {
    if (!pQueue) return;
    
    // 清空队列
    while (DequeueTask(pQueue)) {
        // 继续出队直到为空
    }
    
    // 释放哨兵节点
    if (pQueue->Head) {
        PB11_Free((PVOID)pQueue->Head);
    }
    
    PB11_Free(pQueue);
}

// ====================== FTP会话管理 ======================

FTP_SESSION* FTP_CreateSession(_In_ LPCSTR Server, _In_ DWORD Port,
                              _In_ LPCSTR Username, _In_ LPCSTR Password,
                              _In_ DWORD NumaNode) {
    FTP_SESSION* pSession = (FTP_SESSION*)PB11_AllocateAligned(
        sizeof(FTP_SESSION), CACHE_LINE_SIZE, NumaNode);
    
    if (!pSession) {
        DebugLog("Failed to allocate FTP session for NUMA node %u", NumaNode);
        return NULL;
    }
    
    ZeroMemory(pSession, sizeof(FTP_SESSION));
    
    strcpy_s(pSession->Server, sizeof(pSession->Server), Server);
    pSession->Port = Port ? Port : FTP_DEFAULT_PORT;
    strcpy_s(pSession->Username, sizeof(pSession->Username), Username);
    strcpy_s(pSession->Password, sizeof(pSession->Password), Password);
    pSession->TransferMode = FTP_MODE_BINARY;
    pSession->PassiveMode = TRUE;
    pSession->ExtendedPassive = TRUE;
    pSession->Timeout = FTP_CONTROL_TIMEOUT_MS;
    pSession->ControlSocket = INVALID_SOCKET;
    pSession->DataSocket = INVALID_SOCKET;
    pSession->ListenSocket = INVALID_SOCKET;
    pSession->AcceptSocket = INVALID_SOCKET;
    pSession->NumaNode = NumaNode;
    
    InitializeCriticalSection(&pSession->Lock);
    
    DebugLog("Created FTP session for server %s:%u on NUMA node %u",
            Server, Port, NumaNode);
    
    return pSession;
}

BOOL FTP_Connect(_In_ FTP_SESSION* pSession) {
    if (!pSession || pSession->Connected) {
        return FALSE;
    }
    
    // 创建控制socket
    pSession->ControlSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (pSession->ControlSocket == INVALID_SOCKET) {
        DebugLog("Failed to create control socket for FTP session");
        return FALSE;
    }
    
    // 设置socket选项
    int optval = 1;
    setsockopt(pSession->ControlSocket, SOL_SOCKET, SO_REUSEADDR,
              (const char*)&optval, sizeof(optval));
    
    // 设置发送和接收缓冲区
    int bufsize = 64 * 1024; // 64KB
    setsockopt(pSession->ControlSocket, SOL_SOCKET, SO_SNDBUF,
              (const char*)&bufsize, sizeof(bufsize));
    setsockopt(pSession->ControlSocket, SOL_SOCKET, SO_RCVBUF,
              (const char*)&bufsize, sizeof(bufsize));
    
    // 设置超时
    setsockopt(pSession->ControlSocket, SOL_SOCKET, SO_SNDTIMEO,
              (const char*)&pSession->Timeout, sizeof(DWORD));
    setsockopt(pSession->ControlSocket, SOL_SOCKET, SO_RCVTIMEO,
              (const char*)&pSession->Timeout, sizeof(DWORD));
    
    // 解析服务器地址
    struct addrinfo hints, *result = NULL;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    
    char portStr[16];
    sprintf_s(portStr, sizeof(portStr), "%u", pSession->Port);
    
    if (getaddrinfo(pSession->Server, portStr, &hints, &result) != 0) {
        DebugLog("Failed to resolve FTP server %s", pSession->Server);
        closesocket(pSession->ControlSocket);
        pSession->ControlSocket = INVALID_SOCKET;
        return FALSE;
    }
    
    // 连接服务器
    int connectResult = connect(pSession->ControlSocket,
                               result->ai_addr,
                               (int)result->ai_addrlen);
    
    freeaddrinfo(result);
    
    if (connectResult == SOCKET_ERROR) {
        DWORD error = WSAGetLastError();
        DebugLog("Failed to connect to FTP server %s:%u, error: %lu",
                pSession->Server, pSession->Port, error);
        closesocket(pSession->ControlSocket);
        pSession->ControlSocket = INVALID_SOCKET;
        return FALSE;
    }
    
    // 读取欢迎消息
    char welcomeBuffer[1024];
    DWORD responseCode;
    
    if (!FTP_ReadResponse(pSession, &responseCode, welcomeBuffer,
                         sizeof(welcomeBuffer))) {
        DebugLog("Failed to read welcome message from FTP server");
        closesocket(pSession->ControlSocket);
        pSession->ControlSocket = INVALID_SOCKET;
        return FALSE;
    }
    
    if (responseCode != FTP_CODE_READY) {
        DebugLog("Unexpected FTP welcome code: %lu, expected: 220", responseCode);
        closesocket(pSession->ControlSocket);
        pSession->ControlSocket = INVALID_SOCKET;
        return FALSE;
    }
    
    pSession->Connected = TRUE;
    AtomicIncrement(&g_Engine.Stats.FtpConnections);
    
    DebugLog("Successfully connected to FTP server %s:%u",
            pSession->Server, pSession->Port);
    
    return TRUE;
}

BOOL FTP_Login(_In_ FTP_SESSION* pSession) {
    if (!pSession || !pSession->Connected) {
        return FALSE;
    }
    
    char response[1024];
    DWORD responseCode;
    
    // 发送用户名
    if (!FTP_SendCommand(pSession, "USER", pSession->Username,
                        &responseCode, response, sizeof(response))) {
        DebugLog("Failed to send USER command to FTP server");
        return FALSE;
    }
    
    // 检查是否需要密码
    if (responseCode == FTP_CODE_LOGIN_NEED_PASSWORD) {
        // 发送密码
        if (!FTP_SendCommand(pSession, "PASS", pSession->Password,
                            &responseCode, response, sizeof(response))) {
            DebugLog("Failed to send PASS command to FTP server");
            return FALSE;
        }
    }
    
    if (responseCode != FTP_CODE_LOGIN_SUCCESS) {
        DebugLog("FTP login failed with code: %lu", responseCode);
        return FALSE;
    }
    
    // 设置传输模式为二进制
    if (!FTP_SendCommand(pSession, "TYPE", "I",
                        &responseCode, response, sizeof(response))) {
        DebugLog("Failed to set binary transfer mode");
        return FALSE;
    }
    
    if (responseCode != FTP_CODE_COMMAND_OK) {
        DebugLog("Failed to set binary mode, code: %lu", responseCode);
        return FALSE;
    }
    
    pSession->LoggedIn = TRUE;
    
    DebugLog("Successfully logged in to FTP server as %s",
            pSession->Username);
    
    return TRUE;
}

BOOL FTP_SendCommand(_In_ FTP_SESSION* pSession, _In_ LPCSTR Command,
                    _In_opt_ LPCSTR Argument, _Out_ DWORD* pResponseCode,
                    _Out_ char* Response, _In_ DWORD ResponseSize) {
    if (!pSession || !pSession->Connected || !Command || !pResponseCode) {
        return FALSE;
    }
    
    EnterCriticalSection(&pSession->Lock);
    
    // 构建命令字符串
    char commandBuffer[512];
    if (Argument && Argument[0]) {
        sprintf_s(commandBuffer, sizeof(commandBuffer), "%s %s\r\n",
                 Command, Argument);
    } else {
        sprintf_s(commandBuffer, sizeof(commandBuffer), "%s\r\n", Command);
    }
    
    // 发送命令
    int bytesSent = send(pSession->ControlSocket, commandBuffer,
                        (int)strlen(commandBuffer), 0);
    
    if (bytesSent <= 0) {
        DWORD error = WSAGetLastError();
        DebugLog("Failed to send FTP command %s, error: %lu", Command, error);
        LeaveCriticalSection(&pSession->Lock);
        return FALSE;
    }
    
    // 读取响应
    BOOL result = FTP_ReadResponse(pSession, pResponseCode,
                                  Response, ResponseSize);
    
    if (!result) {
        DebugLog("Failed to read response for FTP command %s", Command);
    }
    
    LeaveCriticalSection(&pSession->Lock);
    return result;
}

BOOL FTP_ReadResponse(_In_ FTP_SESSION* pSession, _Out_ DWORD* pResponseCode,
                     _Out_ char* Buffer, _In_ DWORD BufferSize) {
    if (!pSession || !pSession->Connected || !pResponseCode || !Buffer) {
        return FALSE;
    }
    
    memset(Buffer, 0, BufferSize);
    
    char responseBuffer[4096];
    int totalBytes = 0;
    BOOL multiLine = FALSE;
    
    // 设置超时
    fd_set readSet;
    struct timeval timeout;
    
    while (totalBytes < (int)(BufferSize - 1)) {
        FD_ZERO(&readSet);
        FD_SET(pSession->ControlSocket, &readSet);
        
        timeout.tv_sec = pSession->Timeout / 1000;
        timeout.tv_usec = (pSession->Timeout % 1000) * 1000;
        
        int selectResult = select(0, &readSet, NULL, NULL, &timeout);
        if (selectResult <= 0) {
            DebugLog("Timeout waiting for FTP response");
            return FALSE; // 超时或错误
        }
        
        int bytesRead = recv(pSession->ControlSocket,
                            responseBuffer + totalBytes,
                            (int)(BufferSize - totalBytes - 1), 0);
        
        if (bytesRead <= 0) {
            DWORD error = WSAGetLastError();
            DebugLog("Failed to read from FTP control socket, error: %lu", error);
            return FALSE;
        }
        
        totalBytes += bytesRead;
        responseBuffer[totalBytes] = '\0';
        
        // 检查是否收到完整响应
        if (totalBytes >= 4) {
            // 检查响应码
            if (isdigit(responseBuffer[0]) &&
                isdigit(responseBuffer[1]) &&
                isdigit(responseBuffer[2])) {
                
                // 解析响应码
                *pResponseCode = (responseBuffer[0] - '0') * 100 +
                                (responseBuffer[1] - '0') * 10 +
                                (responseBuffer[2] - '0');
                
                // 检查是否为多行响应
                if (responseBuffer[3] == '-') {
                    multiLine = TRUE;
                } else if (responseBuffer[3] == ' ') {
                    // 单行响应结束
                    break;
                }
                
                // 对于多行响应，检查结束行
                if (multiLine) {
                    // 查找以 "响应码 " 开头的行
                    for (int i = 4; i < totalBytes - 3; i++) {
                        if (isdigit(responseBuffer[i]) &&
                            isdigit(responseBuffer[i + 1]) &&
                            isdigit(responseBuffer[i + 2]) &&
                            responseBuffer[i + 3] == ' ') {
                            
                            // 检查是否相同的响应码
                            DWORD endCode = (responseBuffer[i] - '0') * 100 +
                                           (responseBuffer[i + 1] - '0') * 10 +
                                           (responseBuffer[i + 2] - '0');
                            
                            if (endCode == *pResponseCode) {
                                // 多行响应结束
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    
    // 复制响应到输出缓冲区
    strncpy_s(Buffer, BufferSize, responseBuffer, BufferSize - 1);
    
    // 存储最后的响应
    strncpy_s(pSession->LastResponse, sizeof(pSession->LastResponse),
             responseBuffer, sizeof(pSession->LastResponse) - 1);
    pSession->LastResponseCode = *pResponseCode;
    
    return TRUE;
}

BOOL FTP_EnterPassiveMode(_In_ FTP_SESSION* pSession, _Out_ SOCKET* pDataSocket) {
    if (!pSession || !pSession->Connected || !pDataSocket) {
        return FALSE;
    }
    
    char response[1024];
    DWORD responseCode;
    
    // 优先尝试扩展被动模式
    if (pSession->ExtendedPassive) {
        if (FTP_SendCommand(pSession, "EPSV", NULL,
                           &responseCode, response, sizeof(response))) {
            if (responseCode == FTP_CODE_EXT_PASSIVE_MODE) {
                // 解析扩展被动模式响应
                // 格式：229 Entering Extended Passive Mode (|||port|)
                const char* portStart = strstr(response, "|||");
                if (portStart) {
                    portStart += 3;
                    const char* portEnd = strstr(portStart, "|");
                    if (portEnd) {
                        char portStr[16];
                        size_t portLen = portEnd - portStart;
                        strncpy_s(portStr, sizeof(portStr), portStart, portLen);
                        portStr[portLen] = '\0';
                        
                        DWORD dataPort = atoi(portStr);
                        
                        // 创建数据socket
                        SOCKET dataSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                        if (dataSocket != INVALID_SOCKET) {
                            // 设置socket选项
                            int bufsize = 256 * 1024; // 256KB
                            setsockopt(dataSocket, SOL_SOCKET, SO_SNDBUF,
                                      (const char*)&bufsize, sizeof(bufsize));
                            
                            // 连接服务器数据端口
                            struct sockaddr_in serverAddr;
                            memset(&serverAddr, 0, sizeof(serverAddr));
                            serverAddr.sin_family = AF_INET;
                            serverAddr.sin_port = htons((u_short)dataPort);
                            serverAddr.sin_addr.s_addr = inet_addr(pSession->Server);
                            
                            if (connect(dataSocket, (struct sockaddr*)&serverAddr,
                                       sizeof(serverAddr)) != SOCKET_ERROR) {
                                *pDataSocket = dataSocket;
                                DebugLog("Entered extended passive mode, data port: %u",
                                        dataPort);
                                return TRUE;
                            }
                            
                            closesocket(dataSocket);
                        }
                    }
                }
            }
        }
    }
    
    // 回退到普通被动模式
    if (!FTP_SendCommand(pSession, "PASV", NULL,
                        &responseCode, response, sizeof(response))) {
        DebugLog("Failed to send PASV command");
        return FALSE;
    }
    
    if (responseCode != FTP_CODE_PASSIVE_MODE) {
        DebugLog("PASV command failed with code: %lu", responseCode);
        return FALSE;
    }
    
    // 解析被动模式响应
    // 格式：227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
    const char* start = strchr(response, '(');
    if (!start) {
        DebugLog("Invalid PASV response format");
        return FALSE;
    }
    
    start++; // 跳过'('
    
    int h1, h2, h3, h4, p1, p2;
    if (sscanf_s(start, "%d,%d,%d,%d,%d,%d",
                &h1, &h2, &h3, &h4, &p1, &p2) != 6) {
        DebugLog("Failed to parse PASV response");
        return FALSE;
    }
    
    // 计算IP地址和端口
    char ipAddress[16];
    sprintf_s(ipAddress, sizeof(ipAddress), "%d.%d.%d.%d", h1, h2, h3, h4);
    DWORD dataPort = (p1 << 8) | p2;
    
    // 创建数据socket
    SOCKET dataSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (dataSocket == INVALID_SOCKET) {
        DebugLog("Failed to create data socket");
        return FALSE;
    }
    
    // 设置socket选项
    int bufsize = 256 * 1024; // 256KB
    setsockopt(dataSocket, SOL_SOCKET, SO_SNDBUF,
              (const char*)&bufsize, sizeof(bufsize));
    
    // 连接服务器数据端口
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons((u_short)dataPort);
    inet_pton(AF_INET, ipAddress, &serverAddr.sin_addr);
    
    if (connect(dataSocket, (struct sockaddr*)&serverAddr,
               sizeof(serverAddr)) == SOCKET_ERROR) {
        DWORD error = WSAGetLastError();
        DebugLog("Failed to connect to data port %u, error: %lu",
                dataPort, error);
        closesocket(dataSocket);
        return FALSE;
    }
    
    *pDataSocket = dataSocket;
    DebugLog("Entered passive mode, data port: %u", dataPort);
    
    return TRUE;
}

BOOL FTP_SetupDataConnection(_In_ FTP_SESSION* pSession, _Out_ SOCKET* pDataSocket) {
    if (!pSession || !pSession->Connected || !pDataSocket) {
        return FALSE;
    }
    
    if (pSession->PassiveMode) {
        return FTP_EnterPassiveMode(pSession, pDataSocket);
    } else {
        // 主动模式实现
        // 创建监听socket
        pSession->ListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (pSession->ListenSocket == INVALID_SOCKET) {
            DebugLog("Failed to create listen socket for active mode");
            return FALSE;
        }
        
        // 绑定到随机端口
        struct sockaddr_in localAddr;
        memset(&localAddr, 0, sizeof(localAddr));
        localAddr.sin_family = AF_INET;
        localAddr.sin_addr.s_addr = htonl(INADDR_ANY);
        localAddr.sin_port = 0; // 让系统选择端口
        
        if (bind(pSession->ListenSocket, (struct sockaddr*)&localAddr,
                sizeof(localAddr)) == SOCKET_ERROR) {
            DebugLog("Failed to bind listen socket");
            closesocket(pSession->ListenSocket);
            pSession->ListenSocket = INVALID_SOCKET;
            return FALSE;
        }
        
        // 获取分配的端口
        int addrLen = sizeof(localAddr);
        getsockname(pSession->ListenSocket, (struct sockaddr*)&localAddr, &addrLen);
        DWORD localPort = ntohs(localAddr.sin_port);
        
        // 监听连接
        if (listen(pSession->ListenSocket, 1) == SOCKET_ERROR) {
            DebugLog("Failed to listen on socket");
            closesocket(pSession->ListenSocket);
            pSession->ListenSocket = INVALID_SOCKET;
            return FALSE;
        }
        
        // 获取本地IP地址
        char localIP[16];
        DWORD localIPSize = sizeof(localIP);
        if (getsockname(pSession->ControlSocket, (struct sockaddr*)&localAddr, &addrLen) != 0) {
            strcpy_s(localIP, sizeof(localIP), "127.0.0.1");
        } else {
            inet_ntop(AF_INET, &localAddr.sin_addr, localIP, sizeof(localIP));
        }
        
        // 发送PORT命令
        BYTE* ipBytes = (BYTE*)&localAddr.sin_addr.s_addr;
        char portCommand[64];
        sprintf_s(portCommand, sizeof(portCommand),
                 "%d,%d,%d,%d,%d,%d",
                 ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3],
                 localPort >> 8, localPort & 0xFF);
        
        char response[1024];
        DWORD responseCode;
        if (!FTP_SendCommand(pSession, "PORT", portCommand,
                           &responseCode, response, sizeof(response))) {
            closesocket(pSession->ListenSocket);
            pSession->ListenSocket = INVALID_SOCKET;
            return FALSE;
        }
        
        if (responseCode != FTP_CODE_COMMAND_OK) {
            DebugLog("PORT command failed with code: %lu", responseCode);
            closesocket(pSession->ListenSocket);
            pSession->ListenSocket = INVALID_SOCKET;
            return FALSE;
        }
        
        // 等待服务器连接
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(pSession->ListenSocket, &readSet);
        
        struct timeval timeout;
        timeout.tv_sec = pSession->Timeout / 1000;
        timeout.tv_usec = (pSession->Timeout % 1000) * 1000;
        
        if (select(0, &readSet, NULL, NULL, &timeout) <= 0) {
            DebugLog("Timeout waiting for server data connection");
            closesocket(pSession->ListenSocket);
            pSession->ListenSocket = INVALID_SOCKET;
            return FALSE;
        }
        
        // 接受连接
        pSession->AcceptSocket = accept(pSession->ListenSocket, NULL, NULL);
        if (pSession->AcceptSocket == INVALID_SOCKET) {
            DebugLog("Failed to accept data connection");
            closesocket(pSession->ListenSocket);
            pSession->ListenSocket = INVALID_SOCKET;
            return FALSE;
        }
        
        *pDataSocket = pSession->AcceptSocket;
        DebugLog("Active mode established, data port: %u", localPort);
        
        return TRUE;
    }
}

BOOL FTP_BeginTransfer(_In_ FTP_SESSION* pSession, _In_ LPCSTR RemotePath,
                      _In_ ULONGLONG FileSize, _In_ ULONGLONG ResumeOffset) {
    if (!pSession || !pSession->Connected || !pSession->LoggedIn) {
        return FALSE;
    }
    
    // 如果需要断点续传，发送REST命令
    if (ResumeOffset > 0) {
        char offsetStr[32];
        sprintf_s(offsetStr, sizeof(offsetStr), "%llu", ResumeOffset);
        
        char response[1024];
        DWORD responseCode;
        if (!FTP_SendCommand(pSession, "REST", offsetStr,
                            &responseCode, response, sizeof(response))) {
            DebugLog("Failed to send REST command for offset %llu", ResumeOffset);
            return FALSE;
        }
        
        if (responseCode != FTP_CODE_RESTART_MARKER) {
            DebugLog("REST command failed with code: %lu", responseCode);
            return FALSE;
        }
        
        DebugLog("Resume transfer from offset %llu", ResumeOffset);
    }
    
    // 建立数据连接
    SOCKET dataSocket;
    if (!FTP_SetupDataConnection(pSession, &dataSocket)) {
        DebugLog("Failed to setup data connection for transfer");
        return FALSE;
    }
    
    pSession->DataSocket = dataSocket;
    
    // 发送STOR命令
    char response[1024];
    DWORD responseCode;
    if (!FTP_SendCommand(pSession, "STOR", RemotePath,
                        &responseCode, response, sizeof(response))) {
        DebugLog("Failed to send STOR command for %s", RemotePath);
        closesocket(dataSocket);
        pSession->DataSocket = INVALID_SOCKET;
        return FALSE;
    }
    
    if (responseCode != FTP_CODE_FILE_OK) {
        DebugLog("STOR command failed with code: %lu", responseCode);
        closesocket(dataSocket);
        pSession->DataSocket = INVALID_SOCKET;
        return FALSE;
    }
    
    DebugLog("Began FTP transfer for %s (size: %llu, resume: %llu)",
            RemotePath, FileSize, ResumeOffset);
    
    return TRUE;
}

BOOL FTP_TransmitFileAsync(_In_ FTP_SESSION* pSession, _In_ HANDLE hFile,
                          _In_ ULONGLONG Offset, _In_ ULONGLONG Length,
                          _In_ FULL_ASYNC_CONTEXT* pContext) {
    if (!pSession || pSession->DataSocket == INVALID_SOCKET || !pContext) {
        return FALSE;
    }
    
    // 准备TransmitFile参数
    TRANSMIT_FILE_BUFFERS buffers = {0};
    
    pContext->Overlapped.Offset = (DWORD)(Offset & 0xFFFFFFFF);
    pContext->Overlapped.OffsetHigh = (DWORD)(Offset >> 32);
    
    // 提交异步TransmitFile
    if (!TransmitFile(
        pSession->DataSocket,
        hFile,
        (DWORD)Length,
        0,  // 默认块大小
        &pContext->Overlapped,
        &buffers,
        TF_WRITE_BEHIND | TF_USE_KERNEL_APC
    )) {
        DWORD error = GetLastError();
        if (error != ERROR_IO_PENDING) {
            DebugLog("TransmitFile failed with error: %lu", error);
            return FALSE;
        }
    }
    
    DebugLog("Submitted async TransmitFile for %llu bytes from offset %llu",
            Length, Offset);
    
    return TRUE;
}

BOOL FTP_CompleteTransfer(_In_ FTP_SESSION* pSession, _Out_ BOOL* pSuccess) {
    if (!pSession || !pSuccess) {
        return FALSE;
    }
    
    *pSuccess = FALSE;
    
    // 关闭数据socket
    if (pSession->DataSocket != INVALID_SOCKET) {
        closesocket(pSession->DataSocket);
        pSession->DataSocket = INVALID_SOCKET;
    }
    
    // 关闭监听socket（主动模式）
    if (pSession->ListenSocket != INVALID_SOCKET) {
        closesocket(pSession->ListenSocket);
        pSession->ListenSocket = INVALID_SOCKET;
    }
    
    if (pSession->AcceptSocket != INVALID_SOCKET) {
        closesocket(pSession->AcceptSocket);
        pSession->AcceptSocket = INVALID_SOCKET;
    }
    
    // 读取传输完成响应
    char response[1024];
    DWORD responseCode;
    
    if (!FTP_ReadResponse(pSession, &responseCode, response, sizeof(response))) {
        DebugLog("Failed to read transfer completion response");
        return FALSE;
    }
    
    *pSuccess = (responseCode == FTP_CODE_TRANSFER_COMPLETE);
    
    if (*pSuccess) {
        DebugLog("FTP transfer completed successfully");
    } else {
        DebugLog("FTP transfer failed with code: %lu", responseCode);
    }
    
    return TRUE;
}

VOID FTP_DestroySession(_In_ FTP_SESSION* pSession) {
    if (!pSession) return;
    
    // 发送QUIT命令
    if (pSession->Connected && pSession->ControlSocket != INVALID_SOCKET) {
        FTP_SendCommand(pSession, "QUIT", NULL, NULL, NULL, 0);
    }
    
    // 关闭所有socket
    if (pSession->ControlSocket != INVALID_SOCKET) {
        closesocket(pSession->ControlSocket);
    }
    
    if (pSession->DataSocket != INVALID_SOCKET) {
        closesocket(pSession->DataSocket);
    }
    
    if (pSession->ListenSocket != INVALID_SOCKET) {
        closesocket(pSession->ListenSocket);
    }
    
    if (pSession->AcceptSocket != INVALID_SOCKET) {
        closesocket(pSession->AcceptSocket);
    }
    
    DeleteCriticalSection(&pSession->Lock);
    PB11_FreeAligned(pSession);
    
    DebugLog("Destroyed FTP session");
}

// ====================== FTP连接池实现 ======================

FTP_CONNECTION_POOL* FTP_CreateConnectionPool(_In_ DWORD MaxSessions,
                                             _In_ DWORD NumaNode) {
    FTP_CONNECTION_POOL* pPool = (FTP_CONNECTION_POOL*)PB11_AllocateAligned(
        sizeof(FTP_CONNECTION_POOL), CACHE_LINE_SIZE, NumaNode);
    
    if (!pPool) {
        DebugLog("Failed to create FTP connection pool for NUMA node %u", NumaNode);
        return NULL;
    }
    
    ZeroMemory(pPool, sizeof(FTP_CONNECTION_POOL));
    pPool->MaxSessions = min(MaxSessions, MAX_FTP_SESSIONS_PER_NODE);
    pPool->NumaNode = NumaNode;
    
    InitializeCriticalSection(&pPool->Lock);
    
    DebugLog("Created FTP connection pool for NUMA node %u (max sessions: %u)",
            NumaNode, pPool->MaxSessions);
    
    return pPool;
}

FTP_SESSION* FTP_AcquireSession(_In_ FTP_CONNECTION_POOL* pPool,
                               _In_ LPCSTR Server, _In_ DWORD Port,
                               _In_ LPCSTR Username, _In_ LPCSTR Password) {
    if (!pPool) {
        return NULL;
    }
    
    EnterCriticalSection(&pPool->Lock);
    
    FTP_SESSION* pSession = NULL;
    DWORD oldestIndex = 0;
    LARGE_INTEGER oldestTime;
    QueryPerformanceCounter(&oldestTime);
    
    // 查找可用的会话
    for (DWORD i = 0; i < pPool->Count; i++) {
        if (pPool->Sessions[i] &&
            pPool->Sessions[i]->Connected &&
            pPool->Sessions[i]->LoggedIn &&
            !pPool->Sessions[i]->InUse &&
            strcmp(pPool->Sessions[i]->Server, Server) == 0 &&
            pPool->Sessions[i]->Port == Port &&
            strcmp(pPool->Sessions[i]->Username, Username) == 0) {
            
            // 检查会话是否空闲时间过长
            LARGE_INTEGER currentTime;
            QueryPerformanceCounter(&currentTime);
            
            // 如果会话空闲时间超过10分钟，重新连接
            ULONGLONG idleTimeMs = (currentTime.QuadPart - 
                                   pPool->Sessions[i]->LastUsedTime.QuadPart) * 1000ULL /
                                   g_Engine.Stats.EndTime.QuadPart; // 使用频率计数器
            
            if (idleTimeMs < 10 * 60 * 1000) { // 10分钟
                pSession = pPool->Sessions[i];
                pSession->InUse = TRUE;
                QueryPerformanceCounter(&pSession->LastUsedTime);
                pPool->CacheHits++;
                break;
            } else {
                // 会话空闲时间过长，标记为需要清理
                DebugLog("FTP session idle for %llu ms, will reconnect", idleTimeMs);
            }
        }
        
        // 跟踪最旧的会话用于替换
        if (pPool->Sessions[i] && 
            pPool->Sessions[i]->LastUsedTime.QuadPart < oldestTime.QuadPart) {
            oldestTime = pPool->Sessions[i]->LastUsedTime;
            oldestIndex = i;
        }
    }
    
    // 如果没有可用会话且未达到最大限制，创建新会话
    if (!pSession && pPool->Count < pPool->MaxSessions) {
        pSession = FTP_CreateSession(Server, Port, Username, Password, pPool->NumaNode);
        
        if (pSession) {
            if (FTP_Connect(pSession) && FTP_Login(pSession)) {
                pSession->InUse = TRUE;
                QueryPerformanceCounter(&pSession->LastUsedTime);
                pPool->Sessions[pPool->Count++] = pSession;
                pPool->CacheMisses++;
            } else {
                FTP_DestroySession(pSession);
                pSession = NULL;
            }
        }
    }
    
    // 如果达到最大限制且没有可用会话，替换最旧的会话
    if (!pSession && pPool->Count >= pPool->MaxSessions) {
        if (pPool->Sessions[oldestIndex]) {
            FTP_DestroySession(pPool->Sessions[oldestIndex]);
            pPool->Sessions[oldestIndex] = NULL;
        }
        
        pSession = FTP_CreateSession(Server, Port, Username, Password, pPool->NumaNode);
        
        if (pSession) {
            if (FTP_Connect(pSession) && FTP_Login(pSession)) {
                pSession->InUse = TRUE;
                QueryPerformanceCounter(&pSession->LastUsedTime);
                pPool->Sessions[oldestIndex] = pSession;
                pPool->CacheMisses++;
            } else {
                FTP_DestroySession(pSession);
                pSession = NULL;
            }
        }
    }
    
    if (pSession) {
        pPool->TotalAcquires++;
        DebugLog("Acquired FTP session from pool (hits: %llu, misses: %llu)",
                pPool->CacheHits, pPool->CacheMisses);
    }
    
    LeaveCriticalSection(&pPool->Lock);
    
    return pSession;
}

VOID FTP_ReleaseSession(_In_ FTP_CONNECTION_POOL* pPool,
                       _In_ FTP_SESSION* pSession) {
    if (!pPool || !pSession) {
        return;
    }
    
    EnterCriticalSection(&pPool->Lock);
    
    pSession->InUse = FALSE;
    QueryPerformanceCounter(&pSession->LastUsedTime);
    pPool->TotalReleases++;
    
    DebugLog("Released FTP session to pool (total releases: %llu)",
            pPool->TotalReleases);
    
    LeaveCriticalSection(&pPool->Lock);
}

VOID FTP_DestroyConnectionPool(_In_ FTP_CONNECTION_POOL* pPool) {
    if (!pPool) return;
    
    EnterCriticalSection(&pPool->Lock);
    
    for (DWORD i = 0; i < pPool->Count; i++) {
        if (pPool->Sessions[i]) {
            FTP_DestroySession(pPool->Sessions[i]);
            pPool->Sessions[i] = NULL;
        }
    }
    
    LeaveCriticalSection(&pPool->Lock);
    DeleteCriticalSection(&pPool->Lock);
    
    PB11_FreeAligned(pPool);
    
    DebugLog("Destroyed FTP connection pool");
}

// ====================== NUMA系统初始化 ======================

BOOL PB11_QueryNumaTopology() {
    // 获取NUMA节点数量
    ULONG highestNodeNumber;
    if (!GetNumaHighestNodeNumber(&highestNodeNumber)) {
        g_Engine.NumaNodeCount = 1;
        DebugLog("NUMA not supported or error, using single node");
    } else {
        g_Engine.NumaNodeCount = highestNodeNumber + 1;
        if (g_Engine.NumaNodeCount > MAX_NUMA_NODES) {
            g_Engine.NumaNodeCount = MAX_NUMA_NODES;
        }
        DebugLog("Detected %u NUMA nodes", g_Engine.NumaNodeCount);
    }
    
    // 查询每个NUMA节点的信息
    for (DWORD i = 0; i < g_Engine.NumaNodeCount; i++) {
        NUMA_NODE_INFO* pNode = &g_Engine.NumaNodes[i];
        pNode->NodeId = i;
        
        // 获取CPU信息
        ULONGLONG processorMask;
        if (GetNumaNodeProcessorMaskEx(i, &processorMask)) {
            pNode->CpuMask = (KAFFINITY)processorMask;
            
            // 计算CPU数量
            pNode->CpuCount = 0;
            KAFFINITY mask = pNode->CpuMask;
            while (mask) {
                pNode->CpuCount += (mask & 1);
                mask >>= 1;
            }
            
            DebugLog("NUMA node %u: %u CPUs, mask: 0x%llx",
                    i, pNode->CpuCount, processorMask);
        } else {
            pNode->CpuCount = 1;
            pNode->CpuMask = 1;
            DebugLog("NUMA node %u: Failed to get CPU info, using default", i);
        }
        
        // 获取内存信息
        ULONGLONG availableBytes;
        if (GetNumaAvailableMemoryNodeEx(i, &availableBytes)) {
            pNode->AvailableMemory = availableBytes;
            
            // 估算总内存
            MEMORYSTATUSEX memStatus;
            memStatus.dwLength = sizeof(memStatus);
            if (GlobalMemoryStatusEx(&memStatus)) {
                pNode->TotalMemory = memStatus.ullTotalPhys / g_Engine.NumaNodeCount;
            }
            
            DebugLog("NUMA node %u: %llu MB available, %llu MB total",
                    i, pNode->AvailableMemory / (1024 * 1024),
                    pNode->TotalMemory / (1024 * 1024));
        }
        
        // 为每个NUMA节点创建IOCP
        pNode->IoCompletionPort = CreateIoCompletionPort(
            INVALID_HANDLE_VALUE,
            NULL,
            0,
            pNode->CpuCount * 2
        );
        
        if (!pNode->IoCompletionPort) {
            DebugLog("Failed to create IOCP for NUMA node %u", i);
            return FALSE;
        }
        
        // 创建FTP连接池（如果启用）
        if (g_Engine.Config.EnableFtp && g_Engine.Config.FtpConnectionPooling) {
            pNode->FtpPool = FTP_CreateConnectionPool(
                g_Engine.Config.FtpMaxSessionsPerNode, i);
        }
        
        // 创建任务队列
        pNode->WorkThreads[i] = CreateLockfreeQueue(i);
    }
    
    return TRUE;
}

BOOL PB11_BindToNumaNode(_In_ DWORD NumaNode) {
    if (NumaNode >= g_Engine.NumaNodeCount) {
        return FALSE;
    }
    
    // 设置线程的NUMA节点亲和性
    HANDLE hThread = GetCurrentThread();
    
    GROUP_AFFINITY groupAffinity = {0};
    groupAffinity.Group = 0;
    groupAffinity.Mask = g_Engine.NumaNodes[NumaNode].CpuMask;
    
    if (!SetThreadGroupAffinity(hThread, &groupAffinity, NULL)) {
        DWORD error = GetLastError();
        DebugLog("Failed to bind thread to NUMA node %u, error: %lu",
                NumaNode, error);
        return FALSE;
    }
    
    // 设置线程优先级
    SetThreadPriority(hThread, THREAD_PRIORITY_HIGHEST);
    
    DebugLog("Thread %lu bound to NUMA node %u (CPU mask: 0x%llx)",
            GetCurrentThreadId(), NumaNode, groupAffinity.Mask);
    
    return TRUE;
}

DWORD PB11_GetCurrentNumaNode() {
    PROCESSOR_NUMBER procNumber;
    GetCurrentProcessorNumberEx(&procNumber);
    
    // 获取CPU所属的NUMA节点
    ULONG numaNode;
    if (GetNumaProcessorNode((UCHAR)procNumber.Number, &numaNode)) {
        return numaNode;
    }
    
    return 0;
}

// ====================== 工作线程实现 ======================

DWORD WINAPI NumaWorkerThread(_In_ LPVOID lpParam) {
    DWORD numaNode = (DWORD)(ULONG_PTR)lpParam;
    
    if (numaNode >= g_Engine.NumaNodeCount) {
        return 1;
    }
    
    // 绑定到NUMA节点
    PB11_BindToNumaNode(numaNode);
    
    NUMA_NODE_INFO* pNode = &g_Engine.NumaNodes[numaNode];
    
    DebugLog("Worker thread %lu started on NUMA node %u",
            GetCurrentThreadId(), numaNode);
    
    // 工作循环
    while (g_Engine.bRunning) {
        if (g_Engine.bPaused) {
            Sleep(100);
            continue;
        }
        
        // 检查流量控制
        if (!PB11_CanSubmitTask(numaNode)) {
            Sleep(10);
            continue;
        }
        
        // 从IOCP获取完成通知
        DWORD bytesTransferred = 0;
        ULONG_PTR completionKey = 0;
        LPOVERLAPPED pOverlapped = NULL;
        
        BOOL success = GetQueuedCompletionStatus(
            pNode->IoCompletionPort,
            &bytesTransferred,
            &completionKey,
            &pOverlapped,
            100  // 100ms超时
        );
        
        if (pOverlapped) {
            // 处理完成通知
            FULL_ASYNC_CONTEXT* pContext = CONTAINING_RECORD(
                pOverlapped, FULL_ASYNC_CONTEXT, Overlapped);
            
            ProcessAsyncCompletion(pContext, bytesTransferred, success);
            g_Engine.Stats.AsyncCompletions++;
            continue;
        }
        
        // 如果没有IOCP事件，尝试处理任务队列
        ProcessTaskQueue(numaNode);
    }
    
    DebugLog("Worker thread %lu exiting", GetCurrentThreadId());
    return 0;
}

VOID ProcessAsyncCompletion(_In_ FULL_ASYNC_CONTEXT* pContext,
                           _In_ DWORD BytesTransferred,
                           _In_ BOOL Success) {
    if (!pContext) return;
    
    switch (pContext->Operation) {
        case OP_FTP_STOR:
            // FTP传输完成
            if (Success) {
                pContext->FtpTransmit.BytesTransferred += BytesTransferred;
                
                if (pContext->FtpTransmit.BytesTransferred >= 
                    pContext->FtpTransmit.BytesToTransfer) {
                    // 传输完成，通知完成
                    BOOL transferSuccess = FALSE;
                    if (pContext->FtpTransmit.pSession) {
                        FTP_CompleteTransfer(pContext->FtpTransmit.pSession, &transferSuccess);
                    }
                    
                    // 回调通知
                    if (g_pfnTaskComplete && pContext->UserContext) {
                        TRANSFER_TASK_V11* pTask = (TRANSFER_TASK_V11*)pContext->UserContext;
                        g_pfnTaskComplete(pTask, 
                                         transferSuccess ? ERROR_SUCCESS : ERROR_NETWORK_ACCESS_DENIED,
                                         g_pTaskCompleteContext);
                    }
                    
                    // 释放资源
                    if (pContext->FtpTransmit.hFile != INVALID_HANDLE_VALUE) {
                        CloseHandle(pContext->FtpTransmit.hFile);
                    }
                    
                    if (pContext->FtpTransmit.pSession && 
                        pContext->FtpTransmit.pSession->InUse) {
                        // 释放会话回连接池
                        NUMA_NODE_INFO* pNode = &g_Engine.NumaNodes[pContext->NumaNode];
                        if (pNode->FtpPool) {
                            FTP_ReleaseSession(pNode->FtpPool, pContext->FtpTransmit.pSession);
                        }
                    }
                    
                    PB11_Free(pContext);
                }
            } else {
                // 传输失败，重试或报告错误
                if (pContext->RetryCount < g_Engine.Config.FtpMaxRetries) {
                    pContext->RetryCount++;
                    DebugLog("FTP transmission failed, retry %u/%u",
                            pContext->RetryCount, g_Engine.Config.FtpMaxRetries);
                    
                    // 重新提交传输
                    // 这里需要重新实现重试逻辑
                } else {
                    // 重试次数用尽，报告失败
                    if (g_pfnTaskComplete && pContext->UserContext) {
                        TRANSFER_TASK_V11* pTask = (TRANSFER_TASK_V11*)pContext->UserContext;
                        g_pfnTaskComplete(pTask, ERROR_NETWORK_ACCESS_DENIED,
                                         g_pTaskCompleteContext);
                    }
                    
                    PB11_Free(pContext);
                }
            }
            break;
            
        case OP_BATCH_TRANSMIT:
            // 批处理传输完成
            ProcessBatchCompletion(pContext, BytesTransferred, Success);
            break;
            
        default:
            // 其他操作类型
            DebugLog("Unhandled async operation type: %d", pContext->Operation);
            PB11_Free(pContext);
            break;
    }
}

VOID ProcessTaskQueue(_In_ DWORD NumaNode) {
    NUMA_NODE_INFO* pNode = &g_Engine.NumaNodes[NumaNode];
    if (!pNode->WorkThreads[NumaNode]) return;
    
    // 从队列获取任务
    TRANSFER_TASK_V11* pTask = DequeueTask(pNode->WorkThreads[NumaNode]);
    if (!pTask) {
        return;
    }
    
    // 更新并发统计
    AtomicIncrement((LONG*)&g_Engine.Stats.CurrentConcurrency);
    AtomicIncrement((LONG*)&pNode->ActiveTasks);
    
    if (g_Engine.Stats.CurrentConcurrency > g_Engine.Stats.PeakConcurrency) {
        g_Engine.Stats.PeakConcurrency = g_Engine.Stats.CurrentConcurrency;
    }
    
    // 处理传输任务
    BOOL success = ProcessTransferTask(pTask);
    
    // 更新统计
    if (success) {
        AtomicIncrement64((LONGLONG*)&g_Engine.Stats.TransferredFiles);
        AtomicIncrement64((LONGLONG*)&g_Engine.Stats.TransferredBytes, pTask->FileSize.QuadPart);
        AtomicIncrement64((LONGLONG*)&pNode->BytesTransferred, pTask->FileSize.QuadPart);
    } else {
        AtomicIncrement64((LONGLONG*)&g_Engine.Stats.FailedFiles);
    }
    
    // 减少并发计数
    AtomicDecrement((LONG*)&g_Engine.Stats.CurrentConcurrency);
    AtomicDecrement((LONG*)&pNode->ActiveTasks);
    
    // 进度回调
    if (g_pfnProgress && (g_Engine.Stats.TransferredFiles % 1000 == 0)) {
        g_pfnProgress(g_Engine.Stats.TransferredFiles, g_Engine.Stats.TotalFiles,
                     g_Engine.Stats.TransferredBytes, g_Engine.Stats.TotalBytes,
                     g_pProgressContext);
    }
    
    // 清理任务
    PB11_Free(pTask);
}

BOOL ProcessTransferTask(_In_ TRANSFER_TASK_V11* pTask) {
    if (!pTask) return FALSE;
    
    QueryPerformanceCounter(&pTask->StartTime);
    
    // 打开文件
    pTask->hFile = CreateFileW(pTask->LocalPath,
                              GENERIC_READ,
                              FILE_SHARE_READ,
                              NULL,
                              OPEN_EXISTING,
                              FILE_FLAG_OVERLAPPED | FILE_FLAG_SEQUENTIAL_SCAN,
                              NULL);
    
    if (pTask->hFile == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        DebugLogW(L"Failed to open file %s, error: %lu", pTask->LocalPath, error);
        return FALSE;
    }
    
    // 获取FTP会话
    if (g_Engine.Config.EnableFtp) {
        if (g_Engine.Config.FtpConnectionPooling && 
            g_Engine.NumaNodes[pTask->NumaNode].FtpPool) {
            
            char server[256], username[64], password[64];
            WideToMultiByte(g_Engine.Config.Server, server, sizeof(server));
            WideToMultiByte(g_Engine.Config.Username, username, sizeof(username));
            WideToMultiByte(g_Engine.Config.Password, password, sizeof(password));
            
            pTask->pFtpSession = FTP_AcquireSession(
                g_Engine.NumaNodes[pTask->NumaNode].FtpPool,
                server,
                g_Engine.Config.Port,
                username,
                password);
        } else {
            // 创建新会话
            char server[256], username[64], password[64], remotePath[1024];
            WideToMultiByte(g_Engine.Config.Server, server, sizeof(server));
            WideToMultiByte(g_Engine.Config.Username, username, sizeof(username));
            WideToMultiByte(g_Engine.Config.Password, password, sizeof(password));
            WideToMultiByte(pTask->RemotePath, remotePath, sizeof(remotePath));
            
            pTask->pFtpSession = FTP_CreateSession(
                server,
                g_Engine.Config.Port,
                username,
                password,
                pTask->NumaNode);
            
            if (pTask->pFtpSession) {
                if (!FTP_Connect(pTask->pFtpSession) || !FTP_Login(pTask->pFtpSession)) {
                    FTP_DestroySession(pTask->pFtpSession);
                    pTask->pFtpSession = NULL;
                }
            }
        }
        
        if (!pTask->pFtpSession) {
            CloseHandle(pTask->hFile);
            DebugLogW(L"Failed to get FTP session for file %s", pTask->LocalPath);
            return FALSE;
        }
        
        // 转换远程路径
        char remotePath[1024];
        WideToMultiByte(pTask->RemotePath, remotePath, sizeof(remotePath));
        
        // 开始FTP传输
        if (!FTP_BeginTransfer(pTask->pFtpSession, remotePath,
                              pTask->FileSize.QuadPart,
                              pTask->TransferOffset.QuadPart)) {
            DebugLogW(L"Failed to begin FTP transfer for %s", pTask->LocalPath);
            if (g_Engine.Config.FtpConnectionPooling) {
                FTP_ReleaseSession(g_Engine.NumaNodes[pTask->NumaNode].FtpPool,
                                 pTask->pFtpSession);
            } else {
                FTP_DestroySession(pTask->pFtpSession);
            }
            CloseHandle(pTask->hFile);
            return FALSE;
        }
        
        // 创建异步上下文
        FULL_ASYNC_CONTEXT* pContext = (FULL_ASYNC_CONTEXT*)PB11_Allocate(
            sizeof(FULL_ASYNC_CONTEXT), pTask->NumaNode);
        
        if (!pContext) {
            FTP_CompleteTransfer(pTask->pFtpSession, NULL);
            if (g_Engine.Config.FtpConnectionPooling) {
                FTP_ReleaseSession(g_Engine.NumaNodes[pTask->NumaNode].FtpPool,
                                 pTask->pFtpSession);
            } else {
                FTP_DestroySession(pTask->pFtpSession);
            }
            CloseHandle(pTask->hFile);
            return FALSE;
        }
        
        ZeroMemory(pContext, sizeof(FULL_ASYNC_CONTEXT));
        pContext->Operation = OP_FTP_STOR;
        pContext->NumaNode = pTask->NumaNode;
        pContext->FtpTransmit.pSession = pTask->pFtpSession;
        pContext->FtpTransmit.hFile = pTask->hFile;
        pContext->FtpTransmit.FileOffset = pTask->TransferOffset.QuadPart;
        pContext->FtpTransmit.BytesToTransfer = pTask->FileSize.QuadPart;
        pContext->UserContext = pTask;
        
        strcpy_s(pContext->FtpTransmit.RemotePath, sizeof(pContext->FtpTransmit.RemotePath),
                remotePath);
        
        // 提交异步传输
        if (!FTP_TransmitFileAsync(pTask->pFtpSession, pTask->hFile,
                                  pTask->TransferOffset.QuadPart,
                                  pTask->FileSize.QuadPart,
                                  pContext)) {
            PB11_Free(pContext);
            FTP_CompleteTransfer(pTask->pFtpSession, NULL);
            if (g_Engine.Config.FtpConnectionPooling) {
                FTP_ReleaseSession(g_Engine.NumaNodes[pTask->NumaNode].FtpPool,
                                 pTask->pFtpSession);
            } else {
                FTP_DestroySession(pTask->pFtpSession);
            }
            CloseHandle(pTask->hFile);
            return FALSE;
        }
        
        // 关联到IOCP
        CreateIoCompletionPort((HANDLE)pTask->pFtpSession->DataSocket,
                              g_Engine.NumaNodes[pTask->NumaNode].IoCompletionPort,
                              (ULONG_PTR)pContext, 0);
        
        // 任务现在由异步上下文管理
        pTask->pAsyncContext = pContext;
        
        return TRUE; // 传输已开始，异步完成
    } else {
        // 非FTP传输（例如原始socket）
        // 这里可以实现其他传输协议
        CloseHandle(pTask->hFile);
        return FALSE;
    }
}

// ====================== 超级批处理实现 ======================

BOOL PB11_CreateSuperBatch(_In_ DWORD NumaNode) {
    if (NumaNode >= g_Engine.NumaNodeCount) {
        return FALSE;
    }
    
    EnterCriticalSection(&g_Engine.BatchLock[NumaNode]);
    
    if (g_Engine.BatchContexts[NumaNode]) {
        // 已经存在批处理上下文
        LeaveCriticalSection(&g_Engine.BatchLock[NumaNode]);
        return TRUE;
    }
    
    // 创建新的批处理上下文
    FULL_ASYNC_CONTEXT* pContext = (FULL_ASYNC_CONTEXT*)PB11_Allocate(
        sizeof(FULL_ASYNC_CONTEXT), NumaNode);
    
    if (!pContext) {
        LeaveCriticalSection(&g_Engine.BatchLock[NumaNode]);
        return FALSE;
    }
    
    ZeroMemory(pContext, sizeof(FULL_ASYNC_CONTEXT));
    pContext->Operation = OP_BATCH_TRANSMIT;
    pContext->NumaNode = NumaNode;
    
    // 创建超级批处理包
    SUPER_BATCH_PACKET* pBatch = (SUPER_BATCH_PACKET*)PB11_AllocateAligned(
        sizeof(SUPER_BATCH_PACKET), CACHE_LINE_SIZE, NumaNode);
    
    if (!pBatch) {
        PB11_Free(pContext);
        LeaveCriticalSection(&g_Engine.BatchLock[NumaNode]);
        return FALSE;
    }
    
    ZeroMemory(pBatch, sizeof(SUPER_BATCH_PACKET));
    
    // 初始化批处理头
    pBatch->Header.Magic = 0x50534654;  // 'PSFT'
    pBatch->Header.Version = 1;
    pBatch->Header.BatchId = GetNanoTime();
    pBatch->Header.TotalSize = 0;
    pBatch->Header.FileCount = 0;
    pBatch->Header.Timestamp = GetNanoTime();
    pBatch->Header.Flags = 0;
    pBatch->Header.Checksum = 0;
    
    pContext->FtpBatch.pBatch = pBatch;
    g_Engine.BatchContexts[NumaNode] = pContext;
    
    LeaveCriticalSection(&g_Engine.BatchLock[NumaNode]);
    
    DebugLog("Created super batch for NUMA node %u", NumaNode);
    
    return TRUE;
}

BOOL PB11_AddFileToBatch(_In_ DWORD NumaNode, _In_ LPCWSTR lpFilePath,
                        _In_ LPCWSTR lpRemotePath, _In_ ULONGLONG FileSize) {
    if (NumaNode >= g_Engine.NumaNodeCount) {
        return FALSE;
    }
    
    EnterCriticalSection(&g_Engine.BatchLock[NumaNode]);
    
    FULL_ASYNC_CONTEXT* pContext = g_Engine.BatchContexts[NumaNode];
    if (!pContext || !pContext->FtpBatch.pBatch) {
        LeaveCriticalSection(&g_Engine.BatchLock[NumaNode]);
        return FALSE;
    }
    
    SUPER_BATCH_PACKET* pBatch = pContext->FtpBatch.pBatch;
    
    // 检查是否还有空间
    if (pBatch->Header.FileCount >= MAX_SUPER_BATCH_FILES ||
        (pBatch->Header.TotalSize + FileSize) > SUPER_BATCH_SIZE) {
        // 提交当前批处理
        PB11_SubmitSuperBatch(NumaNode);
        
        // 创建新的批处理
        PB11_CreateSuperBatch(NumaNode);
        
        // 重新获取上下文
        pContext = g_Engine.BatchContexts[NumaNode];
        pBatch = pContext->FtpBatch.pBatch;
        
        if (!pBatch) {
            LeaveCriticalSection(&g_Engine.BatchLock[NumaNode]);
            return FALSE;
        }
    }
    
    // 获取文件信息
    WIN32_FILE_ATTRIBUTE_DATA fileAttr;
    if (!GetFileAttributesExW(lpFilePath, GetFileExInfoStandard, &fileAttr)) {
        DebugLogW(L"Failed to get file attributes for %s", lpFilePath);
        LeaveCriticalSection(&g_Engine.BatchLock[NumaNode]);
        return FALSE;
    }
    
    // 获取文件ID
    BY_HANDLE_FILE_INFORMATION fileInfo;
    HANDLE hFile = CreateFileW(
        lpFilePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        DebugLogW(L"Failed to open file for fingerprint: %s", lpFilePath);
        LeaveCriticalSection(&g_Engine.BatchLock[NumaNode]);
        return FALSE;
    }
    
    if (!GetFileInformationByHandle(hFile, &fileInfo)) {
        DebugLogW(L"Failed to get file information for %s", lpFilePath);
        CloseHandle(hFile);
        LeaveCriticalSection(&g_Engine.BatchLock[NumaNode]);
        return FALSE;
    }
    
    // 读取文件数据
    HANDLE hFileData = CreateFileW(
        lpFilePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        NULL
    );
    
    if (hFileData == INVALID_HANDLE_VALUE) {
        DebugLogW(L"Failed to open file for reading: %s", lpFilePath);
        CloseHandle(hFile);
        LeaveCriticalSection(&g_Engine.BatchLock[NumaNode]);
        return FALSE;
    }
    
    // 读取文件数据到批处理缓冲区
    DWORD bytesRead;
    DWORD dataOffset = (DWORD)pBatch->Header.TotalSize;
    
    if (!ReadFile(
        hFileData,
        pBatch->Data + dataOffset,
        (DWORD)FileSize,
        &bytesRead,
        NULL
    ) || bytesRead != FileSize) {
        DebugLogW(L"Failed to read file data for %s", lpFilePath);
        CloseHandle(hFile);
        CloseHandle(hFileData);
        LeaveCriticalSection(&g_Engine.BatchLock[NumaNode]);
        return FALSE;
    }
    
    CloseHandle(hFileData);
    
    // 添加文件条目
    DWORD entryIndex = pBatch->Header.FileCount;
    SUPER_BATCH_FILE_ENTRY* pEntry = &pBatch->Entries[entryIndex];
    
    pEntry->FileIdHigh = fileInfo.nFileIndexHigh;
    pEntry->FileIdLow = fileInfo.nFileIndexLow;
    pEntry->FileSize = FileSize;
    pEntry->DataOffset = dataOffset;
    pEntry->DataSize = FileSize;
    pEntry->Attributes = fileInfo.dwFileAttributes;
    pEntry->Crc32 = 0; // 可以计算CRC32
    
    // 复制文件名
    const WCHAR* pFileName = wcsrchr(lpFilePath, L'\\');
    if (pFileName) {
        pFileName++; // 跳过反斜杠
    } else {
        pFileName = lpFilePath;
    }
    
    wcsncpy_s(pEntry->FileName, 256, pFileName, _TRUNCATE);
    
    // 更新批处理头
    pBatch->Header.FileCount++;
    pBatch->Header.TotalSize += FileSize;
    
    // 更新统计
    AtomicIncrement64((LONGLONG*)&g_Engine.Stats.TotalFiles);
    AtomicIncrement64((LONGLONG*)&g_Engine.Stats.TotalBytes, FileSize);
    
    CloseHandle(hFile);
    LeaveCriticalSection(&g_Engine.BatchLock[NumaNode]);
    
    DebugLogW(L"Added file to super batch: %s (size: %llu)", lpFilePath, FileSize);
    
    return TRUE;
}

BOOL PB11_SubmitSuperBatch(_In_ DWORD NumaNode) {
    if (NumaNode >= g_Engine.NumaNodeCount) {
        return FALSE;
    }
    
    EnterCriticalSection(&g_Engine.BatchLock[NumaNode]);
    
    FULL_ASYNC_CONTEXT* pContext = g_Engine.BatchContexts[NumaNode];
    if (!pContext || !pContext->FtpBatch.pBatch) {
        LeaveCriticalSection(&g_Engine.BatchLock[NumaNode]);
        return FALSE;
    }
    
    SUPER_BATCH_PACKET* pBatch = pContext->FtpBatch.pBatch;
    
    if (pBatch->Header.FileCount == 0) {
        // 空批处理
        LeaveCriticalSection(&g_Engine.BatchLock[NumaNode]);
        return FALSE;
    }
    
    // 计算校验和
    pBatch->Header.Checksum = CalculateChecksum(pBatch, 
        sizeof(SUPER_BATCH_HEADER) + 
        pBatch->Header.FileCount * sizeof(SUPER_BATCH_FILE_ENTRY));
    
    // 获取FTP会话
    FTP_SESSION* pSession = NULL;
    if (g_Engine.Config.FtpConnectionPooling && 
        g_Engine.NumaNodes[NumaNode].FtpPool) {
        
        char server[256], username[64], password[64];
        WideToMultiByte(g_Engine.Config.Server, server, sizeof(server));
        WideToMultiByte(g_Engine.Config.Username, username, sizeof(username));
        WideToMultiByte(g_Engine.Config.Password, password, sizeof(password));
        
        pSession = FTP_AcquireSession(
            g_Engine.NumaNodes[NumaNode].FtpPool,
            server,
            g_Engine.Config.Port,
            username,
            password);
    }
    
    if (!pSession) {
        DebugLog("Failed to acquire FTP session for super batch");
        LeaveCriticalSection(&g_Engine.BatchLock[NumaNode]);
        return FALSE;
    }
    
    // 生成远程文件名
    WCHAR remoteFileName[MAX_PATH];
    swprintf_s(remoteFileName, MAX_PATH, L"batch_%llu.pbf", pBatch->Header.BatchId);
    
    // 转换为UTF-8
    char remotePath[1024];
    WideToMultiByte(remoteFileName, remotePath, sizeof(remotePath));
    
    // 开始FTP传输
    if (!FTP_BeginTransfer(pSession, remotePath,
                          sizeof(SUPER_BATCH_HEADER) + 
                          pBatch->Header.FileCount * sizeof(SUPER_BATCH_FILE_ENTRY) +
                          pBatch->Header.TotalSize,
                          0)) {
        DebugLog("Failed to begin FTP transfer for super batch");
        FTP_ReleaseSession(g_Engine.NumaNodes[NumaNode].FtpPool, pSession);
        LeaveCriticalSection(&g_Engine.BatchLock[NumaNode]);
        return FALSE;
    }
    
    pContext->FtpBatch.pSession = pSession;
    strcpy_s(pContext->FtpBatch.RemotePath, sizeof(pContext->FtpBatch.RemotePath),
            remotePath);
    
    // 使用WSASend发送批处理数据
    WSABUF wsaBufs[3];
    
    // 发送头部
    wsaBufs[0].buf = (CHAR*)&pBatch->Header;
    wsaBufs[0].len = sizeof(SUPER_BATCH_HEADER);
    
    // 发送文件条目
    wsaBufs[1].buf = (CHAR*)&pBatch->Entries;
    wsaBufs[1].len = pBatch->Header.FileCount * sizeof(SUPER_BATCH_FILE_ENTRY);
    
    // 发送数据
    wsaBufs[2].buf = (CHAR*)pBatch->Data;
    wsaBufs[2].len = (DWORD)pBatch->Header.TotalSize;
    
    // 异步发送
    DWORD dwBytesSent = 0;
    if (WSASend(
        pSession->DataSocket,
        wsaBufs,
        3,
        &dwBytesSent,
        0,
        &pContext->Overlapped,
        NULL
    ) == SOCKET_ERROR) {
        DWORD error = WSAGetLastError();
        if (error != WSA_IO_PENDING) {
            DebugLog("WSASend failed for super batch, error: %lu", error);
            FTP_CompleteTransfer(pSession, NULL);
            FTP_ReleaseSession(g_Engine.NumaNodes[NumaNode].FtpPool, pSession);
            LeaveCriticalSection(&g_Engine.BatchLock[NumaNode]);
            return FALSE;
        }
    }
    
    // 关联到IOCP
    CreateIoCompletionPort((HANDLE)pSession->DataSocket,
                          g_Engine.NumaNodes[NumaNode].IoCompletionPort,
                          (ULONG_PTR)pContext, 0);
    
    // 更新统计
    g_Engine.Stats.SuperBatches++;
    
    // 重置批处理上下文
    g_Engine.BatchContexts[NumaNode] = NULL;
    
    LeaveCriticalSection(&g_Engine.BatchLock[NumaNode]);
    
    DebugLog("Submitted super batch with %u files, total size: %llu",
            pBatch->Header.FileCount, pBatch->Header.TotalSize);
    
    return TRUE;
}

VOID ProcessBatchCompletion(_In_ FULL_ASYNC_CONTEXT* pContext,
                           _In_ DWORD BytesTransferred,
                           _In_ BOOL Success) {
    if (!pContext || pContext->Operation != OP_BATCH_TRANSMIT) {
        return;
    }
    
    SUPER_BATCH_PACKET* pBatch = pContext->FtpBatch.pBatch;
    FTP_SESSION* pSession = pContext->FtpBatch.pSession;
    
    // 完成传输
    BOOL transferSuccess = FALSE;
    if (Success && pSession) {
        FTP_CompleteTransfer(pSession, &transferSuccess);
    }
    
    // 更新统计
    if (transferSuccess && pBatch) {
        g_Engine.Stats.TransferredFiles += pBatch->Header.FileCount;
        g_Engine.Stats.TransferredBytes += pBatch->Header.TotalSize;
        
        DebugLog("Super batch completed successfully: %u files, %llu bytes",
                pBatch->Header.FileCount, pBatch->Header.TotalSize);
    } else {
        DebugLog("Super batch failed");
    }
    
    // 释放资源
    if (pSession && g_Engine.Config.FtpConnectionPooling) {
        FTP_ReleaseSession(g_Engine.NumaNodes[pContext->NumaNode].FtpPool, pSession);
    } else if (pSession) {
        FTP_DestroySession(pSession);
    }
    
    if (pBatch) {
        PB11_FreeAligned(pBatch);
    }
    
    PB11_Free(pContext);
}

// ====================== 文件枚举 ======================

DWORD WINAPI EnumerationThread(_In_ LPVOID lpParam) {
    UNREFERENCED_PARAMETER(lpParam);
    
    DebugLog("Enumeration thread started");
    
    // 使用NTAPI枚举文件
    NTAPI_EnumerateFiles(g_Engine.Config.LocalRoot, TRUE, 0);
    
    DebugLog("Enumeration thread completed, enumerated %llu files", 
            g_Engine.Stats.TotalFiles);
    
    return 0;
}

BOOL NTAPI_EnumerateFiles(_In_ LPCWSTR lpRootPath, _In_ BOOL bRecursive,
                         _In_ DWORD dwMaxDepth) {
    NTSTATUS status;
    HANDLE hDirectory = INVALID_HANDLE_VALUE;
    IO_STATUS_BLOCK ioStatus = {0};
    UNICODE_STRING uniPath = {0};
    OBJECT_ATTRIBUTES objAttr = {0};
    
    // 转换为NT路径
    WCHAR ntPath[MAX_PATH_EXT];
    swprintf_s(ntPath, MAX_PATH_EXT, L"\\??\\%s", lpRootPath);
    
    // 初始化UNICODE_STRING
    RtlInitUnicodeString(&uniPath, ntPath);
    
    // 设置对象属性
    InitializeObjectAttributes(
        &objAttr,
        &uniPath,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );
    
    // 打开目录
    status = NtOpenFile(
        &hDirectory,
        FILE_LIST_DIRECTORY | SYNCHRONIZE,
        &objAttr,
        &ioStatus,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
    );
    
    if (!NT_SUCCESS(status)) {
        DebugLog("NtOpenFile failed for %ls, status: 0x%08X", lpRootPath, status);
        return FALSE;
    }
    
    // 分配2MB对齐缓冲区
    PVOID pBuffer = PB11_AllocateAligned(PAGE_SIZE_2MB, PAGE_SIZE_2MB, 0);
    if (pBuffer == NULL) {
        NtClose(hDirectory);
        return FALSE;
    }
    
    BOOL bFirstQuery = TRUE;
    BOOL bMoreEntries = TRUE;
    
    while (bMoreEntries && g_Engine.bRunning) {
        // 查询目录内容
        status = NtQueryDirectoryFile(
            hDirectory,
            NULL, NULL, NULL,
            &ioStatus,
            pBuffer,
            PAGE_SIZE_2MB,
            FileBothDirectoryInformation,
            FALSE,  // 返回单个条目
            NULL,
            bFirstQuery
        );
        
        if (status == STATUS_NO_MORE_FILES) {
            bMoreEntries = FALSE;
            break;
        }
        
        if (!NT_SUCCESS(status)) {
            DebugLog("NtQueryDirectoryFile failed, status: 0x%08X", status);
            break;
        }
        
        bFirstQuery = FALSE;
        
        // 处理目录条目
        PFILE_BOTH_DIR_INFORMATION pInfo = (PFILE_BOTH_DIR_INFORMATION)pBuffer;
        
        while (TRUE) {
            // 跳过"."和".."
            if (pInfo->FileNameLength == 2 && pInfo->FileName[0] == L'.' ||
                pInfo->FileNameLength == 4 && pInfo->FileName[0] == L'.' && pInfo->FileName[1] == L'.') {
                if (pInfo->NextEntryOffset == 0) {
                    break;
                }
                pInfo = (PFILE_BOTH_DIR_INFORMATION)((BYTE*)pInfo + pInfo->NextEntryOffset);
                continue;
            }
            
            // 构建完整路径
            WCHAR fullPath[MAX_PATH_EXT];
            swprintf_s(fullPath, MAX_PATH_EXT, L"%s\\%.*s",
                lpRootPath,
                pInfo->FileNameLength / sizeof(WCHAR),
                pInfo->FileName);
            
            // 构建相对路径
            WCHAR relativePath[MAX_FILE_PATH];
            // 从完整路径中提取相对路径（相对于LocalRoot）
            const WCHAR* pRelative = wcsstr(fullPath, g_Engine.Config.LocalRoot);
            if (pRelative) {
                pRelative += wcslen(g_Engine.Config.LocalRoot);
                if (*pRelative == L'\\') pRelative++;
                wcscpy_s(relativePath, MAX_FILE_PATH, pRelative);
            } else {
                wcscpy_s(relativePath, MAX_FILE_PATH, fullPath);
            }
            
            if (pInfo->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                // 目录处理
                if (bRecursive && (dwMaxDepth == 0 || dwMaxDepth > 1)) {
                    NTAPI_EnumerateFiles(fullPath, TRUE, dwMaxDepth > 0 ? dwMaxDepth - 1 : 0);
                }
            } else {
                // 文件处理
                WIN32_FILE_ATTRIBUTE_DATA fileAttr;
                fileAttr.dwFileAttributes = pInfo->FileAttributes;
                fileAttr.ftCreationTime.dwLowDateTime = pInfo->CreationTime.LowPart;
                fileAttr.ftCreationTime.dwHighDateTime = pInfo->CreationTime.HighPart;
                fileAttr.ftLastAccessTime.dwLowDateTime = pInfo->LastAccessTime.LowPart;
                fileAttr.ftLastAccessTime.dwHighDateTime = pInfo->LastAccessTime.HighPart;
                fileAttr.ftLastWriteTime.dwLowDateTime = pInfo->LastWriteTime.LowPart;
                fileAttr.ftLastWriteTime.dwHighDateTime = pInfo->LastWriteTime.HighPart;
                fileAttr.nFileSizeHigh = pInfo->EndOfFile.HighPart;
                fileAttr.nFileSizeLow = pInfo->EndOfFile.LowPart;
                
                ProcessDiscoveredFile(fullPath, relativePath, &fileAttr);
            }
            
            if (pInfo->NextEntryOffset == 0) {
                break;
            }
            
            pInfo = (PFILE_BOTH_DIR_INFORMATION)((BYTE*)pInfo + pInfo->NextEntryOffset);
        }
    }
    
    // 清理
    PB11_FreeAligned(pBuffer);
    NtClose(hDirectory);
    
    return TRUE;
}

BOOL ProcessDiscoveredFile(_In_ LPCWSTR lpFilePath, _In_ LPCWSTR lpRelativePath,
                          _In_ const WIN32_FILE_ATTRIBUTE_DATA* pFileAttr) {
    // 检查文件过滤器
    if (g_pfnFileFilter) {
        if (!g_pfnFileFilter(lpFilePath, pFileAttr, g_pFilterContext)) {
            return TRUE; // 跳过文件
        }
    }
    
    // 计算文件大小
    ULONGLONG fileSize = ((ULONGLONG)pFileAttr->nFileSizeHigh << 32) |
                        pFileAttr->nFileSizeLow;
    
    // 检查文件大小限制
    if (g_Engine.Config.MaxFileSize > 0 && fileSize > g_Engine.Config.MaxFileSize) {
        DebugLogW(L"File %s exceeds size limit (%llu > %u), skipping",
                 lpFilePath, fileSize, g_Engine.Config.MaxFileSize);
        return TRUE;
    }
    
    // 构建远程路径
    WCHAR remotePath[MAX_PATH_EXT];
    if (g_Engine.Config.RemoteRoot[0] == L'\0') {
        // 使用相对路径作为远程路径
        wcscpy_s(remotePath, MAX_PATH_EXT, lpRelativePath);
    } else {
        // 组合远程根路径和相对路径
        swprintf_s(remotePath, MAX_PATH_EXT, L"%s\\%s",
                  g_Engine.Config.RemoteRoot, lpRelativePath);
    }
    
    // 将反斜杠转换为斜杠（FTP使用斜杠）
    for (WCHAR* p = remotePath; *p; p++) {
        if (*p == L'\\') {
            *p = L'/';
        }
    }
    
    // 确定NUMA节点（简单的轮询）
    static DWORD s_CurrentNumaNode = 0;
    DWORD numaNode = s_CurrentNumaNode % g_Engine.NumaNodeCount;
    s_CurrentNumaNode++;
    
    // 根据文件大小选择传输策略
    if (ShouldUseSuperBatch(fileSize) && g_Engine.Config.EnableAggregation) {
        // 小文件，添加到超级批处理
        if (!PB11_AddFileToBatch(numaNode, lpFilePath, remotePath, fileSize)) {
            DebugLogW(L"Failed to add file to super batch: %s", lpFilePath);
            return FALSE;
        }
    } else {
        // 大文件，创建独立任务
        TRANSFER_TASK_V11* pTask = (TRANSFER_TASK_V11*)PB11_Allocate(
            sizeof(TRANSFER_TASK_V11), numaNode);
        
        if (!pTask) {
            DebugLogW(L"Failed to allocate task for file: %s", lpFilePath);
            return FALSE;
        }
        
        ZeroMemory(pTask, sizeof(TRANSFER_TASK_V11));
        wcscpy_s(pTask->LocalPath, MAX_PATH_EXT, lpFilePath);
        wcscpy_s(pTask->RemotePath, MAX_FILE_PATH, remotePath);
        pTask->FileSize.QuadPart = fileSize;
        pTask->NumaNode = numaNode;
        pTask->State = TASK_STATE_PENDING;
        
        // 计算文件指纹（可选）
        if (g_Engine.Config.EnableResume) {
            // 这里可以计算文件指纹用于断点续传
        }
        
        // 添加到任务队列
        if (!EnqueueTask(g_Engine.NumaNodes[numaNode].WorkThreads[numaNode], pTask)) {
            DebugLogW(L"Failed to enqueue task for file: %s", lpFilePath);
            PB11_Free(pTask);
            return FALSE;
        }
        
        DebugLogW(L"Queued file for transfer: %s -> %s (size: %llu, node: %u)",
                 lpFilePath, remotePath, fileSize, numaNode);
    }
    
    return TRUE;
}

// ====================== 流控实现 ======================

BOOL PB11_InitFlowControl(_In_ DWORD MaxConcurrency, _In_ DWORD TargetLatencyMs) {
    ZeroMemory(&g_Engine.FlowControl, sizeof(FLOW_CONTROLLER));
    
    g_Engine.FlowControl.MaxConcurrency = MaxConcurrency;
    g_Engine.FlowControl.TargetLatencyMs = TargetLatencyMs;
    g_Engine.FlowControl.AdjustmentInterval = 1000; // 1秒调整一次
    g_Engine.FlowControl.BackoffFactor = 1;
    
    QueryPerformanceCounter(&g_Engine.FlowControl.LastAdjustmentTime);
    
    DebugLog("Initialized flow control: max concurrency=%u, target latency=%ums",
            MaxConcurrency, TargetLatencyMs);
    
    return TRUE;
}

BOOL PB11_AdjustFlowControl() {
    if (!g_Engine.Config.EnableFlowControl) {
        return TRUE;
    }
    
    LARGE_INTEGER currentTime;
    QueryPerformanceCounter(&currentTime);
    
    LARGE_INTEGER frequency;
    QueryPerformanceFrequency(&frequency);
    
    // 计算距离上次调整的时间
    ULONGLONG elapsedMs = (currentTime.QuadPart - 
                          g_Engine.FlowControl.LastAdjustmentTime.QuadPart) * 1000ULL /
                          frequency.QuadPart;
    
    if (elapsedMs < g_Engine.FlowControl.AdjustmentInterval) {
        return TRUE;
    }
    
    // 计算当前吞吐量
    ULONGLONG bytesPerSecond = g_Engine.Stats.TransferredBytes * 1000ULL / elapsedMs;
    g_Engine.FlowControl.BytesPerSecond = bytesPerSecond;
    
    if (bytesPerSecond > g_Engine.FlowControl.PeakBytesPerSecond) {
        g_Engine.FlowControl.PeakBytesPerSecond = bytesPerSecond;
    }
    
    // 检查带宽限制
    if (g_Engine.Config.BandwidthLimit > 0) {
        if (bytesPerSecond > g_Engine.Config.BandwidthLimit * 1.1) {
            // 超过带宽限制，降低并发度
            if (g_Engine.FlowControl.CurrentConcurrency > 1) {
                g_Engine.FlowControl.CurrentConcurrency--;
                g_Engine.FlowControl.SuccessiveFailures = 0;
                DebugLog("Bandwidth limit exceeded, reducing concurrency to %u",
                        g_Engine.FlowControl.CurrentConcurrency);
            }
        }
    }
    
    // 根据延迟调整并发度
    if (g_Engine.FlowControl.CurrentLatencyMs > 
        g_Engine.FlowControl.TargetLatencyMs * 1.2) {
        // 延迟过高，降低并发度
        if (g_Engine.FlowControl.CurrentConcurrency > 1) {
            g_Engine.FlowControl.CurrentConcurrency--;
            g_Engine.FlowControl.SuccessiveFailures++;
            g_Engine.FlowControl.BackoffFactor = min(g_Engine.FlowControl.BackoffFactor * 2, 16);
            
            DebugLog("High latency (%ums > %ums), reducing concurrency to %u (backoff: %u)",
                    g_Engine.FlowControl.CurrentLatencyMs,
                    g_Engine.FlowControl.TargetLatencyMs,
                    g_Engine.FlowControl.CurrentConcurrency,
                    g_Engine.FlowControl.BackoffFactor);
        }
    } else if (g_Engine.FlowControl.CurrentLatencyMs < 
               g_Engine.FlowControl.TargetLatencyMs * 0.8) {
        // 延迟过低，增加并发度
        if (g_Engine.FlowControl.CurrentConcurrency < 
            g_Engine.FlowControl.MaxConcurrency) {
            
            if (g_Engine.FlowControl.SuccessiveFailures > 0) {
                g_Engine.FlowControl.SuccessiveFailures--;
            }
            
            if (g_Engine.FlowControl.SuccessiveFailures == 0) {
                g_Engine.FlowControl.CurrentConcurrency++;
                g_Engine.FlowControl.BackoffFactor = 1;
                
                DebugLog("Low latency (%ums < %ums), increasing concurrency to %u",
                        g_Engine.FlowControl.CurrentLatencyMs,
                        g_Engine.FlowControl.TargetLatencyMs,
                        g_Engine.FlowControl.CurrentConcurrency);
            }
        }
    }
    
    // 更新调整时间
    g_Engine.FlowControl.LastAdjustmentTime = currentTime;
    
    return TRUE;
}

BOOL PB11_CanSubmitTask(_In_ DWORD NumaNode) {
    if (!g_Engine.Config.EnableFlowControl) {
        return TRUE;
    }
    
    // 检查当前并发度
    if (g_Engine.FlowControl.CurrentConcurrency >= 
        g_Engine.FlowControl.MaxConcurrency) {
        return FALSE;
    }
    
    // 检查NUMA节点的活动任务数
    if (g_Engine.NumaNodes[NumaNode].ActiveTasks >= 
        g_Engine.FlowControl.CurrentConcurrency / g_Engine.NumaNodeCount) {
        return FALSE;
    }
    
    // 应用退避因子
    static DWORD s_LastSubmissionCount = 0;
    DWORD currentCount = g_Engine.Stats.TransferredFiles + g_Engine.Stats.FailedFiles;
    
    if (g_Engine.FlowControl.BackoffFactor > 1) {
        if ((currentCount - s_LastSubmissionCount) < g_Engine.FlowControl.BackoffFactor) {
            return FALSE;
        }
        s_LastSubmissionCount = currentCount;
    }
    
    return TRUE;
}

// ====================== 主引擎初始化 ======================

BOOL PB11_Initialize(_In_ TRANSFER_CONFIG_V11* pConfig) {
    if (InterlockedCompareExchange(&g_EngineInitialized, 1, 0) != 0) {
        DebugLog("Engine already initialized");
        return TRUE;
    }
    
    DebugLog("Initializing PB FastCopy Engine v11.0...");
    
    // 初始化锁
    InitializeCriticalSection(&g_Engine.EngineLock);
    
    // 保存配置
    memcpy(&g_Engine.Config, pConfig, sizeof(TRANSFER_CONFIG_V11));
    
    // 初始化统计
    ZeroMemory(&g_Engine.Stats, sizeof(g_Engine.Stats));
    QueryPerformanceCounter(&g_Engine.Stats.StartTime);
    
    // 初始化Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        DebugLog("WSAStartup failed");
        goto Cleanup;
    }
    
    // 初始化NUMA系统
    if (!PB11_QueryNumaTopology()) {
        DebugLog("Failed to initialize NUMA system");
        goto Cleanup;
    }
    
    // 初始化Slab分配器
    for (DWORD i = 0; i < g_Engine.NumaNodeCount; i++) {
        g_Engine.SlabAllocators[i] = CreateSlabAllocator(i);
        if (!g_Engine.SlabAllocators[i]) {
            DebugLog("Failed to create slab allocator for NUMA node %u", i);
            goto Cleanup;
        }
    }
    
    // 初始化任务队列
    for (DWORD i = 0; i < g_Engine.NumaNodeCount; i++) {
        g_Engine.TaskQueues[i] = CreateLockfreeQueue(i);
        if (!g_Engine.TaskQueues[i]) {
            DebugLog("Failed to create task queue for NUMA node %u", i);
            goto Cleanup;
        }
    }
    
    // 初始化批处理锁
    for (DWORD i = 0; i < g_Engine.NumaNodeCount; i++) {
        InitializeCriticalSection(&g_Engine.BatchLock[i]);
        if (g_Engine.Config.EnableAggregation) {
            PB11_CreateSuperBatch(i);
        }
    }
    
    // 初始化流控
    if (g_Engine.Config.EnableFlowControl) {
        DWORD maxConcurrency = g_Engine.Config.MaxConcurrentFiles;
        if (maxConcurrency == 0) {
            maxConcurrency = g_Engine.NumaNodeCount * 32; // 默认值
        }
        
        PB11_InitFlowControl(maxConcurrency, 50); // 目标延迟50ms
    }
    
    // 创建工作线程
    DWORD totalThreads = 0;
    for (DWORD node = 0; node < g_Engine.NumaNodeCount; node++) {
        NUMA_NODE_INFO* pNode = &g_Engine.NumaNodes[node];
        
        DWORD threadsPerNode = g_Engine.Config.IoThreadPerNuma;
        if (threadsPerNode == 0) {
            threadsPerNode = pNode->CpuCount * 2;
        }
        
        threadsPerNode = min(threadsPerNode, MAX_IO_THREADS / g_Engine.NumaNodeCount);
        
        for (DWORD i = 0; i < threadsPerNode; i++) {
            HANDLE hThread = CreateThread(
                NULL,
                0,
                NumaWorkerThread,
                (LPVOID)(ULONG_PTR)node,
                CREATE_SUSPENDED,
                NULL
            );
            
            if (!hThread) {
                DebugLog("Failed to create worker thread for NUMA node %u", node);
                goto Cleanup;
            }
            
            if (pNode->WorkThreadCount < (MAX_IO_THREADS / MAX_NUMA_NODES)) {
                pNode->WorkThreads[pNode->WorkThreadCount++] = hThread;
            }
            
            ResumeThread(hThread);
            totalThreads++;
        }
    }
    
    if (totalThreads == 0) {
        DebugLog("No worker threads created");
        goto Cleanup;
    }
    
    g_Engine.bRunning = TRUE;
    
    DebugLog("Engine initialized successfully with %u NUMA nodes, %u total threads",
            g_Engine.NumaNodeCount, totalThreads);
    
    return TRUE;
    
Cleanup:
    CleanupEngine();
    return FALSE;
}

BOOL PB11_StartTransfer(_In_ LPCWSTR lpSource, _In_ LPCWSTR lpTarget) {
    if (!g_Engine.bRunning) {
        return FALSE;
    }
    
    // 保存路径配置
    if (lpSource) {
        wcscpy_s(g_Engine.Config.LocalRoot, MAX_PATH_EXT, lpSource);
    }
    
    if (lpTarget) {
        wcscpy_s(g_Engine.Config.RemoteRoot, MAX_PATH_EXT, lpTarget);
    }
    
    // 启动枚举线程
    g_Engine.hEnumThread = CreateThread(
        NULL,
        0,
        EnumerationThread,
        NULL,
        0,
        NULL
    );
    
    if (!g_Engine.hEnumThread) {
        DebugLog("Failed to create enumeration thread");
        return FALSE;
    }
    
    DebugLog("Transfer started from %ls to %ls",
            g_Engine.Config.LocalRoot, g_Engine.Config.RemoteRoot);
    
    return TRUE;
}

BOOL PB11_StopTransfer() {
    g_Engine.bRunning = FALSE;
    g_Engine.bPaused = FALSE;
    
    // 等待枚举线程结束
    if (g_Engine.hEnumThread) {
        WaitForSingleObject(g_Engine.hEnumThread, INFINITE);
        CloseHandle(g_Engine.hEnumThread);
        g_Engine.hEnumThread = NULL;
    }
    
    // 等待工作线程结束
    for (DWORD node = 0; node < g_Engine.NumaNodeCount; node++) {
        NUMA_NODE_INFO* pNode = &g_Engine.NumaNodes[node];
        
        for (DWORD i = 0; i < pNode->WorkThreadCount; i++) {
            if (pNode->WorkThreads[i]) {
                WaitForSingleObject(pNode->WorkThreads[i], 5000);
                CloseHandle(pNode->WorkThreads[i]);
                pNode->WorkThreads[i] = NULL;
            }
        }
        pNode->WorkThreadCount = 0;
    }
    
    // 更新结束时间
    QueryPerformanceCounter(&g_Engine.Stats.EndTime);
    
    DebugLog("Transfer stopped");
    
    return TRUE;
}

VOID CleanupEngine() {
    DebugLog("Cleaning up engine...");
    
    // 停止传输
    PB11_StopTransfer();
    
    // 清理批处理
    for (DWORD i = 0; i < g_Engine.NumaNodeCount; i++) {
        if (g_Engine.BatchContexts[i]) {
            PB11_FreeAligned(g_Engine.BatchContexts[i]->FtpBatch.pBatch);
            PB11_Free(g_Engine.BatchContexts[i]);
            g_Engine.BatchContexts[i] = NULL;
        }
        DeleteCriticalSection(&g_Engine.BatchLock[i]);
    }
    
    // 清理FTP连接池
    for (DWORD i = 0; i < g_Engine.NumaNodeCount; i++) {
        if (g_Engine.NumaNodes[i].FtpPool) {
            FTP_DestroyConnectionPool(g_Engine.NumaNodes[i].FtpPool);
            g_Engine.NumaNodes[i].FtpPool = NULL;
        }
    }
    
    // 清理任务队列
    for (DWORD i = 0; i < g_Engine.NumaNodeCount; i++) {
        if (g_Engine.TaskQueues[i]) {
            DestroyLockfreeQueue(g_Engine.TaskQueues[i]);
            g_Engine.TaskQueues[i] = NULL;
        }
    }
    
    // 清理Slab分配器
    for (DWORD i = 0; i < MAX_NUMA_NODES; i++) {
        if (g_Engine.SlabAllocators[i]) {
            DestroySlabAllocator(g_Engine.SlabAllocators[i]);
            g_Engine.SlabAllocators[i] = NULL;
        }
    }
    
    // 清理IOCP
    for (DWORD i = 0; i < g_Engine.NumaNodeCount; i++) {
        if (g_Engine.NumaNodes[i].IoCompletionPort) {
            CloseHandle(g_Engine.NumaNodes[i].IoCompletionPort);
            g_Engine.NumaNodes[i].IoCompletionPort = NULL;
        }
    }
    
    // 清理网络
    WSACleanup();
    
    // 清理锁
    DeleteCriticalSection(&g_Engine.EngineLock);
    
    InterlockedExchange(&g_EngineInitialized, 0);
    
    DebugLog("Engine cleanup completed");
}

VOID PB11_Shutdown() {
    CleanupEngine();
}

// ====================== 统计函数 ======================

BOOL PB11_GetStatistics(_Out_ PB_ENGINE_V11* pEngineCopy) {
    if (!pEngineCopy) {
        return FALSE;
    }
    
    EnterCriticalSection(&g_Engine.EngineLock);
    memcpy(pEngineCopy, &g_Engine, sizeof(PB_ENGINE_V11));
    LeaveCriticalSection(&g_Engine.EngineLock);
    
    return TRUE;
}

VOID PB11_DumpStats() {
    LARGE_INTEGER frequency;
    QueryPerformanceFrequency(&frequency);
    
    ULONGLONG elapsedNs = (g_Engine.Stats.EndTime.QuadPart - 
                          g_Engine.Stats.StartTime.QuadPart) * 1000000000ULL /
                          frequency.QuadPart;
    
    double elapsedSeconds = elapsedNs / 1000000000.0;
    double throughput = elapsedSeconds > 0 ? 
        (double)g_Engine.Stats.TransferredBytes / elapsedSeconds / (1024 * 1024) : 0;
    
    printf("=== PB FastCopy v11 Statistics ===\n");
    printf("Files: %llu total, %llu transferred, %llu failed\n", 
           g_Engine.Stats.TotalFiles, g_Engine.Stats.TransferredFiles,
           g_Engine.Stats.FailedFiles);
    printf("Bytes: %llu total, %llu transferred, %.2f MB/s\n", 
           g_Engine.Stats.TotalBytes, g_Engine.Stats.TransferredBytes,
           throughput);
    printf("Time: %.2f seconds\n", elapsedSeconds);
    printf("Zero-copy operations: %u\n", g_Engine.Stats.ZeroCopyOps);
    printf("Super batches: %u\n", g_Engine.Stats.SuperBatches);
    printf("Async completions: %u\n", g_Engine.Stats.AsyncCompletions);
    printf("FTP connections: %u, reconnects: %u\n",
           g_Engine.Stats.FtpConnections, g_Engine.Stats.FtpReconnects);
    printf("NUMA local/remote: %u/%u\n", 
           g_Engine.Stats.NumaLocalAccess, g_Engine.Stats.NumaRemoteAccess);
    printf("Concurrency: %u current, %u peak\n",
           g_Engine.Stats.CurrentConcurrency, g_Engine.Stats.PeakConcurrency);
    printf("Memory: %u allocations, %u frees\n",
           g_Engine.Stats.MemoryAllocations, g_Engine.Stats.MemoryFrees);
    
    // NUMA节点统计
    for (DWORD i = 0; i < g_Engine.NumaNodeCount; i++) {
        printf("NUMA Node %u: %llu bytes, %u active tasks\n",
               i, g_Engine.NumaNodes[i].BytesTransferred,
               g_Engine.NumaNodes[i].ActiveTasks);
    }
}

// ====================== 导出函数实现 ======================

__declspec(dllexport) BOOL PB11_InitializeEngine(_In_ TRANSFER_CONFIG_V11* pConfig) {
    return PB11_Initialize(pConfig);
}

__declspec(dllexport) BOOL PB11_StartFileTransfer(_In_ LPCWSTR lpSource,
                                                 _In_ LPCWSTR lpTarget,
                                                 _In_ BOOL bResume) {
    UNREFERENCED_PARAMETER(bResume); // 断点续传功能暂未实现
    return PB11_StartTransfer(lpSource, lpTarget);
}

__declspec(dllexport) BOOL PB11_GetTransferStatus(_Out_ PB_ENGINE_V11* pStats) {
    return PB11_GetStatistics(pStats);
}

__declspec(dllexport) VOID PB11_StopEngine() {
    PB11_Shutdown();
}

__declspec(dllexport) BOOL PB11_TestFtpConnection(_In_ LPCSTR Server,
                                                 _In_ DWORD Port,
                                                 _In_ LPCSTR Username,
                                                 _In_ LPCSTR Password) {
    FTP_SESSION* pSession = FTP_CreateSession(Server, Port, Username, Password, 0);
    if (!pSession) {
        return FALSE;
    }
    
    BOOL connected = FTP_Connect(pSession);
    if (connected) {
        BOOL loggedIn = FTP_Login(pSession);
        FTP_Disconnect(pSession);
        FTP_DestroySession(pSession);
        return loggedIn;
    }
    
    FTP_DestroySession(pSession);
    return FALSE;
}

// ====================== 回调设置 ======================

BOOL PB11_SetTaskCompleteCallback(_In_ PFN_TASK_COMPLETE_CALLBACK pfnCallback,
                                 _In_opt_ PVOID UserContext) {
    if (!pfnCallback) {
        return FALSE;
    }
    
    g_pfnTaskComplete = pfnCallback;
    g_pTaskCompleteContext = UserContext;
    
    return TRUE;
}

BOOL PB11_SetProgressCallback(_In_ PFN_PROGRESS_CALLBACK pfnCallback,
                             _In_opt_ PVOID UserContext) {
    if (!pfnCallback) {
        return FALSE;
    }
    
    g_pfnProgress = pfnCallback;
    g_pProgressContext = UserContext;
    
    return TRUE;
}

BOOL PB11_SetFileFilterCallback(_In_ PFN_FILE_FILTER_CALLBACK pfnCallback,
                               _In_opt_ PVOID UserContext) {
    g_pfnFileFilter = pfnCallback;
    g_pFilterContext = UserContext;
    
    return TRUE;
}

// ====================== 高级功能 ======================

BOOL PB11_EnableCompression(_In_ BOOL Enable) {
    // 压缩功能暂未实现
    DebugLog("Compression %s (not implemented)", Enable ? "enabled" : "disabled");
    return FALSE;
}

BOOL PB11_EnableEncryption(_In_ BOOL Enable) {
    // 加密功能暂未实现
    DebugLog("Encryption %s (not implemented)", Enable ? "enabled" : "disabled");
    return FALSE;
}

BOOL PB11_SetBandwidthLimit(_In_ ULONGLONG BytesPerSecond) {
    g_Engine.Config.BandwidthLimit = BytesPerSecond;
    DebugLog("Bandwidth limit set to %llu bytes/sec", BytesPerSecond);
    return TRUE;
}

// ====================== 调试支持 ======================

VOID PB11_EnableDebugLogging(_In_ BOOL Enable) {
    g_bDebugLogging = Enable;
    DebugLog("Debug logging %s", Enable ? "enabled" : "disabled");
}

VOID PB11_DumpMemoryStats() {
    PROCESS_MEMORY_COUNTERS_EX pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), 
                            (PROCESS_MEMORY_COUNTERS*)&pmc, 
                            sizeof(pmc))) {
        DebugLog("Memory usage: WorkingSet=%llu, PeakWorkingSet=%llu, "
                "PrivateUsage=%llu, Pagefile=%llu",
                pmc.WorkingSetSize,
                pmc.PeakWorkingSetSize,
                pmc.PrivateUsage,
                pmc.PagefileUsage);
    }
}

// ====================== 示例主函数 ======================

#ifdef STANDALONE_BUILD
int wmain(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        wprintf(L"Usage: %s <source> <target> [options]\n", argv[0]);
        wprintf(L"Options:\n");
        wprintf(L"  /ftp:server:port:user:pass    FTP server details\n");
        wprintf(L"  /threads:N                    Threads per NUMA node\n");
        wprintf(L"  /batch                        Enable super batching\n");
        wprintf(L"  /zerocopy                     Enable zero-copy\n");
        wprintf(L"  /resume                       Enable resume support\n");
        return 1;
    }
    
    // 初始化配置
    TRANSFER_CONFIG_V11 config = {0};
    
    wcscpy_s(config.LocalRoot, MAX_PATH_EXT, argv[1]);
    
    // 检查目标是否是FTP URL
    if (wcsstr(argv[2], L"ftp://") == argv[2]) {
        config.EnableFtp = TRUE;
        
        // 简单解析FTP URL（实际应用中应该使用更健壮的解析器）
        const wchar_t* p = argv[2] + 6; // 跳过"ftp://"
        const wchar_t* atPos = wcschr(p, L'@');
        
        if (atPos) {
            // 有认证信息
            const wchar_t* colonPos = wcschr(p, L':');
            if (colonPos && colonPos < atPos) {
                wcsncpy_s(config.Username, 64, p, colonPos - p);
                wcsncpy_s(config.Password, 64, colonPos + 1, atPos - colonPos - 1);
                p = atPos + 1;
            }
        }
        
        const wchar_t* slashPos = wcschr(p, L'/');
        if (slashPos) {
            wcsncpy_s(config.Server, 256, p, slashPos - p);
            wcscpy_s(config.RemoteRoot, MAX_PATH_EXT, slashPos);
        } else {
            wcscpy_s(config.Server, 256, p);
            config.RemoteRoot[0] = L'/';
        }
        
        config.Port = 21;
    } else {
        // 本地路径
        wcscpy_s(config.RemoteRoot, MAX_PATH_EXT, argv[2]);
    }
    
    // 性能配置
    config.IoThreadPerNuma = 4;
    config.EnableSuperBatching = TRUE;
    config.EnableZeroCopy = TRUE;
    config.EnableNumaAwareness = TRUE;
    config.EnableFlowControl = TRUE;
    config.MaxConcurrentFiles = 1000;
    
    // FTP配置
    config.FtpPassiveMode = TRUE;
    config.FtpBinaryMode = TRUE;
    config.FtpUseRestart = TRUE;
    config.FtpConnectionPooling = TRUE;
    config.FtpMaxSessionsPerNode = 8;
    config.FtpMaxRetries = 3;
    
    // 启用调试日志
    PB11_EnableDebugLogging(TRUE);
    
    // 初始化引擎
    if (!PB11_InitializeEngine(&config)) {
        wprintf(L"Failed to initialize engine\n");
        return 1;
    }
    
    // 设置进度回调
    PB11_SetProgressCallback([](
        ULONGLONG transferredFiles,
        ULONGLONG totalFiles,
        ULONGLONG transferredBytes,
        ULONGLONG totalBytes,
        PVOID context) {
        
        double percent = totalFiles > 0 ? 
            (double)transferredFiles * 100.0 / totalFiles : 0.0;
        
        wprintf(L"\rProgress: %.2f%% (%llu/%llu files, %llu/%llu bytes)",
                percent, transferredFiles, totalFiles,
                transferredBytes, totalBytes);
    }, NULL);
    
    // 开始传输
    if (!PB11_StartFileTransfer(argv[1], argv[2], FALSE)) {
        wprintf(L"Failed to start transfer\n");
        PB11_StopEngine();
        return 1;
    }
    
    wprintf(L"\nTransfer started...\n");
    
    // 等待传输完成
    while (g_Engine.bRunning) {
        Sleep(1000);
        
        // 显示统计信息
        PB11_DumpStats();
        
        // 检查是否完成
        if (g_Engine.Stats.TransferredFiles >= g_Engine.Stats.TotalFiles &&
            g_Engine.Stats.TotalFiles > 0) {
            break;
        }
    }
    
    // 最终统计
    wprintf(L"\n=== Final Statistics ===\n");
    PB11_DumpStats();
    
    // 关闭引擎
    PB11_StopEngine();
    
    return 0;
}
#endif // STANDALONE_BUILD