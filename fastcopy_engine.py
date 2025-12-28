#!/usr/bin/env python3
"""
PB_fastcopy_engine Python接口封装
使用ctypes调用底层C引擎库
"""

import os
import sys
import ctypes
import ctypes.wintypes as wintypes
from ctypes import Structure, Union, POINTER, CFUNCTYPE, c_char_p, c_void_p
from enum import IntEnum
from typing import Optional, Callable, Dict, Any, List
import uuid
import json
from dataclasses import dataclass
from datetime import datetime
import threading
import queue

# ============================================================================
# 常量定义
# ============================================================================

MAX_PATH = 260

# ============================================================================
# ctypes类型定义
# ============================================================================

class EngineErrorCode(IntEnum):
    """引擎错误码"""
    ENGINE_SUCCESS = 0
    ENGINE_ERROR_INIT_FAILED = -1
    ENGINE_ERROR_MODULE_INIT_FAILED = -2
    ENGINE_ERROR_INVALID_PARAM = -3
    ENGINE_ERROR_TASK_SUBMIT_FAILED = -4
    ENGINE_ERROR_RESOURCE_LIMIT = -5
    ENGINE_ERROR_IO_FAILED = -6
    ENGINE_ERROR_NETWORK_FAILED = -7
    ENGINE_ERROR_INVALID_STATE = -8
    ENGINE_ERROR_TIMEOUT = -9
    ENGINE_ERROR_MEMORY_ALLOC = -10
    ENGINE_ERROR_INTERNAL = -100

class EngineState(IntEnum):
    """引擎状态枚举"""
    ENGINE_STATE_UNINITIALIZED = 0
    ENGINE_STATE_INITIALIZED = 1
    ENGINE_STATE_RUNNING = 2
    ENGINE_STATE_PAUSED = 3
    ENGINE_STATE_STOPPING = 4
    ENGINE_STATE_STOPPED = 5
    ENGINE_STATE_ERROR = 6

class TaskType(IntEnum):
    """任务类型枚举"""
    TASK_TYPE_FILE_COPY = 0
    TASK_TYPE_FILE_MOVE = 1
    TASK_TYPE_FILE_DELETE = 2
    TASK_TYPE_FILE_SYNC = 3
    TASK_TYPE_NETWORK_UPLOAD = 4
    TASK_TYPE_NETWORK_DOWNLOAD = 5
    TASK_TYPE_BATCH_OPERATION = 6

class TaskPriority(IntEnum):
    """任务优先级枚举"""
    TASK_PRIORITY_LOW = 0
    TASK_PRIORITY_NORMAL = 1
    TASK_PRIORITY_HIGH = 2
    TASK_PRIORITY_CRITICAL = 3

# ============================================================================
# 结构体定义
# ============================================================================

class EngineConfig(Structure):
    """引擎配置结构体"""
    _fields_ = [
        ("max_concurrent_tasks", wintypes.DWORD),
        ("memory_limit_mb", ctypes.c_uint64),
        ("io_thread_count", wintypes.DWORD),
        ("network_thread_count", wintypes.DWORD),
        ("enable_direct_io", wintypes.BOOL),
        ("enable_write_through", wintypes.BOOL),
        ("buffer_size_kb", wintypes.DWORD),
        ("batch_size", wintypes.DWORD),
        ("work_directory", ctypes.c_char * MAX_PATH),
        ("temp_directory", ctypes.c_char * MAX_PATH),
        ("max_network_connections", wintypes.DWORD),
        ("network_timeout_ms", wintypes.DWORD),
        ("network_retry_count", wintypes.DWORD),
        ("progress_callback", c_void_p),  # 函数指针
        ("status_callback", c_void_p),    # 函数指针
        ("error_callback", c_void_p),     # 函数指针
        ("callback_user_data", c_void_p),
    ]

class FileOpParams(Structure):
    """文件操作参数"""
    _fields_ = [
        ("source_path", ctypes.c_char * (MAX_PATH * 4)),
        ("destination_path", ctypes.c_char * MAX_PATH),
    ]

class NetworkOpParams(Structure):
    """网络操作参数"""
    _fields_ = [
        ("local_path", ctypes.c_char * MAX_PATH),
        ("remote_url", ctypes.c_char * 1024),
    ]

class BatchOpParams(Structure):
    """批量操作参数"""
    _fields_ = [
        ("source_pattern", ctypes.c_char * 1024),
        ("destination_base", ctypes.c_char * MAX_PATH),
    ]

class TaskParams(Union):
    """任务参数联合体"""
    _fields_ = [
        ("file_op", FileOpParams),
        ("network_op", NetworkOpParams),
        ("batch_op", BatchOpParams),
    ]

class EngineTask(Structure):
    """引擎任务结构体"""
    _fields_ = [
        ("task_id", ctypes.c_char * 64),
        ("type", ctypes.c_int),
        ("priority", ctypes.c_int),
        ("params", TaskParams),
        ("retry_count", wintypes.DWORD),
        ("timeout_ms", wintypes.DWORD),
        ("verify_after_completion", wintypes.BOOL),
        ("preserve_attributes", wintypes.BOOL),
        ("internal_data", c_void_p),
    ]

class EngineStatistics(Structure):
    """引擎统计信息结构体"""
    _fields_ = [
        ("start_time", ctypes.c_uint64),
        ("running_time_ms", ctypes.c_uint64),
        ("total_tasks_submitted", ctypes.c_uint64),
        ("total_tasks_completed", ctypes.c_uint64),
        ("total_tasks_failed", ctypes.c_uint64),
        ("total_tasks_cancelled", ctypes.c_uint64),
        ("total_bytes_processed", ctypes.c_uint64),
        ("total_files_processed", ctypes.c_uint64),
        ("peak_memory_usage_mb", ctypes.c_uint64),
        ("average_speed_mbps", ctypes.c_float),
        ("active_tasks", wintypes.DWORD),
        ("queued_tasks", wintypes.DWORD),
        ("paused_tasks", wintypes.DWORD),
    ]

# ============================================================================
# 回调函数类型定义
# ============================================================================

# C回调函数类型
ENGINE_PROGRESS_CALLBACK = CFUNCTYPE(
    None,
    c_char_p,      # task_id
    ctypes.c_uint64,  # bytes_processed
    ctypes.c_uint64,  # bytes_total
    ctypes.c_float,   # progress_percent
    c_void_p       # user_data
)

ENGINE_STATUS_CALLBACK = CFUNCTYPE(
    None,
    ctypes.c_int,  # state
    c_char_p,      # status_message
    c_void_p       # user_data
)

ENGINE_ERROR_CALLBACK = CFUNCTYPE(
    None,
    c_char_p,      # task_id
    ctypes.c_int,  # error_code
    c_char_p,      # error_message
    c_void_p       # user_data
)

# ============================================================================
# 主引擎类
# ============================================================================

class FastCopyEngine:
    """PB_fastcopy_engine Python封装类"""
    
    def __init__(self, dll_path: Optional[str] = None):
        """
        初始化引擎封装
        
        Args:
            dll_path: 引擎DLL路径，如果为None则尝试默认路径
        """
        # 尝试加载DLL
        if dll_path is None:
            # 默认查找路径
            possible_paths = [
                "./PB_fastcopy_engine.dll",
                "../build/PB_fastcopy_engine.dll",
                os.path.join(os.path.dirname(__file__), "PB_fastcopy_engine.dll"),
            ]
            
            for path in possible_paths:
                if os.path.exists(path):
                    dll_path = path
                    break
        
        if dll_path is None or not os.path.exists(dll_path):
            raise FileNotFoundError(f"无法找到引擎DLL文件: {dll_path}")
        
        # 加载DLL
        self._dll = ctypes.WinDLL(dll_path)
        self._setup_function_prototypes()
        
        # 引擎句柄
        self._engine_handle = None
        
        # Python回调函数引用（防止被垃圾回收）
        self._python_callbacks = {}
        
        # 任务队列
        self._task_queue = queue.Queue()
        self._task_results = {}
        self._task_lock = threading.Lock()
        
        # 事件线程
        self._event_thread = None
        self._stop_event = threading.Event()
        
    def _setup_function_prototypes(self):
        """设置DLL函数原型"""
        
        # 创建和销毁引擎
        self._dll.engine_create.argtypes = [POINTER(EngineConfig)]
        self._dll.engine_create.restype = c_void_p
        
        self._dll.engine_initialize.argtypes = [c_void_p]
        self._dll.engine_initialize.restype = ctypes.c_int
        
        self._dll.engine_destroy.argtypes = [c_void_p]
        self._dll.engine_destroy.restype = ctypes.c_int
        
        # 引擎控制
        self._dll.engine_start.argtypes = [c_void_p]
        self._dll.engine_start.restype = ctypes.c_int
        
        self._dll.engine_pause.argtypes = [c_void_p]
        self._dll.engine_pause.restype = ctypes.c_int
        
        self._dll.engine_resume.argtypes = [c_void_p]
        self._dll.engine_resume.restype = ctypes.c_int
        
        self._dll.engine_stop.argtypes = [c_void_p, wintypes.BOOL]
        self._dll.engine_stop.restype = ctypes.c_int
        
        # 任务管理
        self._dll.engine_submit_task.argtypes = [c_void_p, POINTER(EngineTask)]
        self._dll.engine_submit_task.restype = ctypes.c_int
        
        self._dll.engine_cancel_task.argtypes = [c_void_p, c_char_p]
        self._dll.engine_cancel_task.restype = ctypes.c_int
        
        # 状态查询
        self._dll.engine_get_state.argtypes = [c_void_p]
        self._dll.engine_get_state.restype = ctypes.c_int
        
        self._dll.engine_get_task_status.argtypes = [c_void_p, c_char_p, 
                                                    c_char_p, ctypes.c_size_t]
        self._dll.engine_get_task_status.restype = ctypes.c_int
        
        self._dll.engine_get_statistics.argtypes = [c_void_p, POINTER(EngineStatistics)]
        self._dll.engine_get_statistics.restype = ctypes.c_int
        
        # 工具函数
        self._dll.engine_get_error_message.argtypes = [ctypes.c_int]
        self._dll.engine_get_error_message.restype = c_char_p
        
        self._dll.engine_get_version.argtypes = []
        self._dll.engine_get_version.restype = ctypes.c_uint64
    
    def create(self, config_dict: Dict[str, Any]) -> bool:
        """
        创建引擎实例
        
        Args:
            config_dict: 配置字典
            
        Returns:
            bool: 是否创建成功
        """
        # 填充配置结构
        config = EngineConfig()
        
        # 基本配置
        config.max_concurrent_tasks = config_dict.get('max_concurrent_tasks', 4)
        config.memory_limit_mb = config_dict.get('memory_limit_mb', 4096)
        config.io_thread_count = config_dict.get('io_thread_count', 4)
        config.network_thread_count = config_dict.get('network_thread_count', 2)
        
        # 性能配置
        config.enable_direct_io = config_dict.get('enable_direct_io', True)
        config.enable_write_through = config_dict.get('enable_write_through', True)
        config.buffer_size_kb = config_dict.get('buffer_size_kb', 4096)
        config.batch_size = config_dict.get('batch_size', 100)
        
        # 路径配置
        work_dir = config_dict.get('work_directory', os.getcwd())
        temp_dir = config_dict.get('temp_directory', os.environ.get('TEMP', os.getcwd()))
        
        config.work_directory = work_dir.encode('utf-8')
        config.temp_directory = temp_dir.encode('utf-8')
        
        # 网络配置
        config.max_network_connections = config_dict.get('max_network_connections', 8)
        config.network_timeout_ms = config_dict.get('network_timeout_ms', 30000)
        config.network_retry_count = config_dict.get('network_retry_count', 3)
        
        # 设置Python回调包装器
        if 'progress_callback' in config_dict:
            self._setup_python_callbacks(config_dict, config)
        else:
            config.progress_callback = None
            config.status_callback = None
            config.error_callback = None
            config.callback_user_data = None
        
        # 创建引擎
        self._engine_handle = self._dll.engine_create(ctypes.byref(config))
        
        if not self._engine_handle:
            return False
        
        # 初始化引擎
        result = self._dll.engine_initialize(self._engine_handle)
        
        return result == EngineErrorCode.ENGINE_SUCCESS
    
    def _setup_python_callbacks(self, config_dict: Dict[str, Any], config: EngineConfig):
        """设置Python回调函数包装器"""
        
        # 创建包装函数
        def progress_wrapper(task_id, bytes_processed, bytes_total, progress, user_data):
            if 'progress_callback' in config_dict:
                try:
                    task_id_str = task_id.decode('utf-8') if task_id else ""
                    config_dict['progress_callback'](
                        task_id_str,
                        bytes_processed,
                        bytes_total,
                        progress
                    )
                except Exception as e:
                    print(f"Progress callback error: {e}")
        
        def status_wrapper(state, status_message, user_data):
            if 'status_callback' in config_dict:
                try:
                    message = status_message.decode('utf-8') if status_message else ""
                    config_dict['status_callback'](state, message)
                except Exception as e:
                    print(f"Status callback error: {e}")
        
        def error_wrapper(task_id, error_code, error_message, user_data):
            if 'error_callback' in config_dict:
                try:
                    task_id_str = task_id.decode('utf-8') if task_id else ""
                    message = error_message.decode('utf-8') if error_message else ""
                    config_dict['error_callback'](task_id_str, error_code, message)
                except Exception as e:
                    print(f"Error callback error: {e}")
        
        # 保存引用
        self._python_callbacks['progress'] = ENGINE_PROGRESS_CALLBACK(progress_wrapper)
        self._python_callbacks['status'] = ENGINE_STATUS_CALLBACK(status_wrapper)
        self._python_callbacks['error'] = ENGINE_ERROR_CALLBACK(error_wrapper)
        
        # 设置到配置
        config.progress_callback = ctypes.cast(
            self._python_callbacks['progress'], c_void_p
        )
        config.status_callback = ctypes.cast(
            self._python_callbacks['status'], c_void_p
        )
        config.error_callback = ctypes.cast(
            self._python_callbacks['error'], c_void_p
        )
        config.callback_user_data = None
    
    def start(self) -> bool:
        """启动引擎"""
        if not self._engine_handle:
            return False
        
        result = self._dll.engine_start(self._engine_handle)
        return result == EngineErrorCode.ENGINE_SUCCESS
    
    def stop(self, graceful: bool = True) -> bool:
        """停止引擎"""
        if not self._engine_handle:
            return False
        
        result = self._dll.engine_stop(self._engine_handle, graceful)
        return result == EngineErrorCode.ENGINE_SUCCESS
    
    def submit_file_copy_task(self, source_path: str, dest_path: str, 
                             priority: TaskPriority = TaskPriority.TASK_PRIORITY_NORMAL,
                             **kwargs) -> Optional[str]:
        """
        提交文件复制任务
        
        Args:
            source_path: 源文件路径
            dest_path: 目标文件路径
            priority: 任务优先级
            **kwargs: 其他任务参数
            
        Returns:
            str: 任务ID，如果提交失败则返回None
        """
        # 创建任务
        task = EngineTask()
        
        # 生成任务ID
        task_id = str(uuid.uuid4())
        task.task_id = task_id.encode('utf-8')
        
        # 设置任务类型和优先级
        task.type = TaskType.TASK_TYPE_FILE_COPY.value
        task.priority = priority.value
        
        # 设置文件操作参数
        task.params.file_op.source_path = source_path.encode('utf-8')
        task.params.file_op.destination_path = dest_path.encode('utf-8')
        
        # 设置其他参数
        task.retry_count = kwargs.get('retry_count', 3)
        task.timeout_ms = kwargs.get('timeout_ms', 300000)  # 5分钟
        task.verify_after_completion = kwargs.get('verify', True)
        task.preserve_attributes = kwargs.get('preserve_attributes', True)
        
        # 提交任务
        result = self._dll.engine_submit_task(self._engine_handle, ctypes.byref(task))
        
        if result == EngineErrorCode.ENGINE_SUCCESS.value:
            # 记录任务
            with self._task_lock:
                self._task_results[task_id] = {
                    'status': 'submitted',
                    'submit_time': datetime.now(),
                    'type': 'file_copy',
                    'source': source_path,
                    'destination': dest_path
                }
            return task_id
        else:
            error_msg = self.get_error_message(result)
            print(f"Failed to submit task: {error_msg}")
            return None
    
    def submit_batch_copy_task(self, source_pattern: str, dest_base: str,
                              priority: TaskPriority = TaskPriority.TASK_PRIORITY_NORMAL,
                              **kwargs) -> Optional[str]:
        """
        提交批量复制任务
        
        Args:
            source_pattern: 源文件模式（支持通配符）
            dest_base: 目标基础目录
            priority: 任务优先级
            **kwargs: 其他任务参数
            
        Returns:
            str: 任务ID
        """
        task = EngineTask()
        
        task_id = str(uuid.uuid4())
        task.task_id = task_id.encode('utf-8')
        
        task.type = TaskType.TASK_TYPE_BATCH_OPERATION.value
        task.priority = priority.value
        
        task.params.batch_op.source_pattern = source_pattern.encode('utf-8')
        task.params.batch_op.destination_base = dest_base.encode('utf-8')
        
        task.retry_count = kwargs.get('retry_count', 3)
        task.timeout_ms = kwargs.get('timeout_ms', 1800000)  # 30分钟
        task.verify_after_completion = kwargs.get('verify', True)
        task.preserve_attributes = kwargs.get('preserve_attributes', True)
        
        result = self._dll.engine_submit_task(self._engine_handle, ctypes.byref(task))
        
        if result == EngineErrorCode.ENGINE_SUCCESS.value:
            with self._task_lock:
                self._task_results[task_id] = {
                    'status': 'submitted',
                    'submit_time': datetime.now(),
                    'type': 'batch_copy',
                    'pattern': source_pattern,
                    'dest_base': dest_base
                }
            return task_id
        else:
            error_msg = self.get_error_message(result)
            print(f"Failed to submit batch task: {error_msg}")
            return None
    
    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """
        获取任务状态
        
        Args:
            task_id: 任务ID
            
        Returns:
            Dict: 任务状态信息
        """
        if not self._engine_handle:
            return None
        
        # 查询C引擎
        status_buffer = ctypes.create_string_buffer(1024)
        result = self._dll.engine_get_task_status(
            self._engine_handle,
            task_id.encode('utf-8'),
            status_buffer,
            ctypes.sizeof(status_buffer)
        )
        
        if result == EngineErrorCode.ENGINE_SUCCESS.value:
            status_info = json.loads(status_buffer.value.decode('utf-8'))
            
            # 合并Python端记录的信息
            with self._task_lock:
                if task_id in self._task_results:
                    status_info.update(self._task_results[task_id])
            
            return status_info
        
        return None
    
    def get_statistics(self) -> Optional[Dict[str, Any]]:
        """
        获取引擎统计信息
        
        Returns:
            Dict: 统计信息
        """
        if not self._engine_handle:
            return None
        
        stats = EngineStatistics()
        result = self._dll.engine_get_statistics(self._engine_handle, ctypes.byref(stats))
        
        if result == EngineErrorCode.ENGINE_SUCCESS.value:
            # 转换为Python字典
            stats_dict = {}
            for field_name, _ in stats._fields_:
                value = getattr(stats, field_name)
                # 处理特殊类型
                if isinstance(value, bytes):
                    value = value.decode('utf-8')
                stats_dict[field_name] = value
            
            return stats_dict
        
        return None
    
    def get_state(self) -> EngineState:
        """
        获取引擎状态
        
        Returns:
            EngineState: 引擎状态
        """
        if not self._engine_handle:
            return EngineState.ENGINE_STATE_UNINITIALIZED
        
        state_value = self._dll.engine_get_state(self._engine_handle)
        return EngineState(state_value)
    
    def get_error_message(self, error_code: int) -> str:
        """
        获取错误消息
        
        Args:
            error_code: 错误码
            
        Returns:
            str: 错误消息
        """
        error_msg = self._dll.engine_get_error_message(error_code)
        if error_msg:
            return error_msg.decode('utf-8')
        return f"Unknown error code: {error_code}"
    
    def get_version(self) -> str:
        """获取引擎版本"""
        version_number = self._dll.engine_get_version()
        major = (version_number >> 48) & 0xFFFF
        minor = (version_number >> 32) & 0xFFFF
        patch = (version_number >> 16) & 0xFFFF
        build = version_number & 0xFFFF
        return f"{major}.{minor}.{patch}.{build}"
    
    def __del__(self):
        """析构函数"""
        if self._engine_handle:
            self._dll.engine_destroy(self._engine_handle)
            self._engine_handle = None

# ============================================================================
# 高级API和工具函数
# ============================================================================

class FastCopyAPI:
    """高级API，提供更方便的接口"""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        初始化高级API
        
        Args:
            config_path: 配置文件路径
        """
        self.engine = FastCopyEngine()
        self.config = self._load_config(config_path)
        
        # 事件处理器
        self.event_handlers = {
            'progress': [],
            'status': [],
            'error': [],
            'task_complete': []
        }
        
        # 启动引擎
        self._start_engine()
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """加载配置文件"""
        default_config = {
            'max_concurrent_tasks': 8,
            'memory_limit_mb': 8192,
            'work_directory': os.getcwd(),
            'enable_direct_io': True,
            'buffer_size_kb': 8192
        }
        
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    user_config = json.load(f)
                default_config.update(user_config)
            except Exception as e:
                print(f"Failed to load config file: {e}")
        
        return default_config
    
    def _start_engine(self):
        """启动引擎"""
        # 设置回调
        self.config['progress_callback'] = self._handle_progress
        self.config['status_callback'] = self._handle_status
        self.config['error_callback'] = self._handle_error
        
        # 创建并启动引擎
        if not self.engine.create(self.config):
            raise RuntimeError("Failed to create engine")
        
        if not self.engine.start():
            raise RuntimeError("Failed to start engine")
    
    def _handle_progress(self, task_id: str, bytes_processed: int, 
                        bytes_total: int, progress: float):
        """处理进度事件"""
        for handler in self.event_handlers['progress']:
            try:
                handler(task_id, bytes_processed, bytes_total, progress)
            except Exception as e:
                print(f"Progress handler error: {e}")
    
    def _handle_status(self, state: int, message: str):
        """处理状态事件"""
        for handler in self.event_handlers['status']:
            try:
                handler(EngineState(state), message)
            except Exception as e:
                print(f"Status handler error: {e}")
    
    def _handle_error(self, task_id: str, error_code: int, error_message: str):
        """处理错误事件"""
        for handler in self.event_handlers['error']:
            try:
                handler(task_id, error_code, error_message)
            except Exception as e:
                print(f"Error handler error: {e}")
    
    def register_event_handler(self, event_type: str, handler: Callable):
        """
        注册事件处理器
        
        Args:
            event_type: 事件类型（progress, status, error, task_complete）
            handler: 处理函数
        """
        if event_type in self.event_handlers:
            self.event_handlers[event_type].append(handler)
    
    def copy_file(self, source: str, destination: str, 
                  priority: str = "normal", **kwargs) -> Optional[str]:
        """
        复制文件（高级接口）
        
        Args:
            source: 源文件路径
            destination: 目标文件路径
            priority: 优先级（low, normal, high, critical）
            **kwargs: 其他参数
            
        Returns:
            str: 任务ID
        """
        priority_map = {
            'low': TaskPriority.TASK_PRIORITY_LOW,
            'normal': TaskPriority.TASK_PRIORITY_NORMAL,
            'high': TaskPriority.TASK_PRIORITY_HIGH,
            'critical': TaskPriority.TASK_PRIORITY_CRITICAL
        }
        
        priority_enum = priority_map.get(priority.lower(), TaskPriority.TASK_PRIORITY_NORMAL)
        
        return self.engine.submit_file_copy_task(
            source, destination, priority_enum, **kwargs
        )
    
    def copy_directory(self, source_dir: str, dest_dir: str,
                       recursive: bool = True, **kwargs) -> List[str]:
        """
        复制目录
        
        Args:
            source_dir: 源目录
            dest_dir: 目标目录
            recursive: 是否递归复制
            **kwargs: 其他参数
            
        Returns:
            List[str]: 任务ID列表
        """
        task_ids = []
        
        # 确保目标目录存在
        os.makedirs(dest_dir, exist_ok=True)
        
        # 遍历源目录
        for root, dirs, files in os.walk(source_dir):
            # 计算相对路径
            rel_path = os.path.relpath(root, source_dir)
            if rel_path == '.':
                rel_path = ''
            
            # 创建目标子目录
            target_dir = os.path.join(dest_dir, rel_path)
            if rel_path:  # 不是根目录
                os.makedirs(target_dir, exist_ok=True)
            
            # 提交文件复制任务
            for file in files:
                source_file = os.path.join(root, file)
                dest_file = os.path.join(target_dir, file)
                
                task_id = self.copy_file(source_file, dest_file, **kwargs)
                if task_id:
                    task_ids.append(task_id)
            
            # 如果不递归，跳出循环
            if not recursive:
                break
        
        return task_ids
    
    def wait_for_tasks(self, task_ids: List[str], timeout: Optional[float] = None) -> Dict[str, Any]:
        """
        等待任务完成
        
        Args:
            task_ids: 任务ID列表
            timeout: 超时时间（秒）
            
        Returns:
            Dict: 任务完成统计
        """
        start_time = time.time()
        completed_tasks = set()
        results = {
            'total': len(task_ids),
            'completed': 0,
            'failed': 0,
            'pending': len(task_ids),
            'task_results': {}
        }
        
        while len(completed_tasks) < len(task_ids):
            # 检查超时
            if timeout and (time.time() - start_time) > timeout:
                break
            
            for task_id in task_ids:
                if task_id in completed_tasks:
                    continue
                
                status = self.engine.get_task_status(task_id)
                if status:
                    current_status = status.get('status', 'unknown')
                    
                    if current_status in ['completed', 'failed', 'cancelled']:
                        completed_tasks.add(task_id)
                        results['task_results'][task_id] = status
                        
                        if current_status == 'completed':
                            results['completed'] += 1
                        else:
                            results['failed'] += 1
                        
                        results['pending'] = results['total'] - len(completed_tasks)
            
            # 短暂休眠
            time.sleep(0.1)
        
        return results
    
    def get_dashboard_info(self) -> Dict[str, Any]:
        """
        获取仪表板信息
        
        Returns:
            Dict: 仪表板信息
        """
        state = self.engine.get_state()
        stats = self.engine.get_statistics()
        
        dashboard = {
            'engine_state': state.name,
            'statistics': stats or {},
            'version': self.engine.get_version(),
            'timestamp': datetime.now().isoformat()
        }
        
        return dashboard
    
    def shutdown(self, graceful: bool = True):
        """关闭引擎"""
        self.engine.stop(graceful)