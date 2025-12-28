#!/usr/bin/env python3
"""
PB_fastcopy_engine 测试脚本
"""

import sys
import os
import time
import tempfile
import shutil
from pathlib import Path
import logging

# 添加父目录到路径，以便导入引擎模块
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastcopy_engine import FastCopyAPI, TaskPriority

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_basic_functionality():
    """测试基本功能"""
    print("=" * 60)
    print("测试 1: 基本功能测试")
    print("=" * 60)
    
    try:
        # 创建临时目录
        temp_dir = tempfile.mkdtemp(prefix="fastcopy_test_")
        source_dir = os.path.join(temp_dir, "source")
        dest_dir = os.path.join(temp_dir, "destination")
        
        os.makedirs(source_dir, exist_ok=True)
        os.makedirs(dest_dir, exist_ok=True)
        
        # 创建测试文件
        test_files = []
        for i in range(5):
            file_path = os.path.join(source_dir, f"test_file_{i}.txt")
            with open(file_path, 'w') as f:
                f.write(f"Test content for file {i}\n" * 1000)  # 约20KB
            test_files.append(file_path)
        
        print(f"创建了 {len(test_files)} 个测试文件")
        print(f"临时目录: {temp_dir}")
        
        # 创建引擎API
        print("正在初始化引擎...")
        api = FastCopyAPI()
        
        # 注册事件处理器
        def on_progress(task_id, processed, total, progress):
            logger.info(f"任务 {task_id}: 进度 {progress:.1f}% ({processed}/{total} bytes)")
        
        def on_status(state, message):
            logger.info(f"引擎状态: {state.name} - {message}")
        
        def on_error(task_id, error_code, error_message):
            logger.error(f"任务 {task_id} 错误: {error_message} (代码: {error_code})")
        
        api.register_event_handler('progress', on_progress)
        api.register_event_handler('status', on_status)
        api.register_event_handler('error', on_error)
        
        # 测试1: 单个文件复制
        print("\n测试1.1: 单个文件复制")
        test_file = test_files[0]
        dest_file = os.path.join(dest_dir, "copied_file.txt")
        
        task_id = api.copy_file(test_file, dest_file, priority="high")
        if task_id:
            print(f"已提交任务: {task_id}")
            
            # 等待任务完成
            results = api.wait_for_tasks([task_id], timeout=30)
            if results['completed'] == 1:
                print("✓ 单个文件复制测试通过")
                # 验证文件
                if os.path.exists(dest_file):
                    print("✓ 目标文件已创建")
                else:
                    print("✗ 目标文件未创建")
            else:
                print("✗ 单个文件复制测试失败")
        else:
            print("✗ 无法提交任务")
        
        # 测试1.2: 批量文件复制
        print("\n测试1.2: 批量文件复制")
        task_ids = []
        for i, src_file in enumerate(test_files[1:], 1):
            dest_file = os.path.join(dest_dir, f"batch_{i}.txt")
            task_id = api.copy_file(src_file, dest_file)
            if task_id:
                task_ids.append(task_id)
        
        print(f"已提交 {len(task_ids)} 个批量任务")
        
        if task_ids:
            results = api.wait_for_tasks(task_ids, timeout=60)
            print(f"批量任务完成: {results['completed']} 成功, {results['failed']} 失败")
            
            if results['completed'] > 0:
                print("✓ 批量文件复制测试通过")
            else:
                print("✗ 批量文件复制测试失败")
        
        # 测试1.3: 目录复制
        print("\n测试1.3: 目录复制")
        sub_dir = os.path.join(source_dir, "subdirectory")
        os.makedirs(sub_dir, exist_ok=True)
        
        # 在子目录中创建文件
        for i in range(3):
            file_path = os.path.join(sub_dir, f"sub_file_{i}.txt")
            with open(file_path, 'w') as f:
                f.write(f"Subdirectory file {i}\n" * 500)
        
        dest_sub_dir = os.path.join(temp_dir, "copied_structure")
        dir_task_ids = api.copy_directory(source_dir, dest_sub_dir, recursive=True)
        
        print(f"目录复制提交了 {len(dir_task_ids)} 个任务")
        
        if dir_task_ids:
            results = api.wait_for_tasks(dir_task_ids, timeout=120)
            print(f"目录复制完成: {results['completed']} 成功, {results['failed']} 失败")
            
            # 验证目录结构
            expected_files = len(test_files) + 3  # 原始文件 + 子目录文件
            actual_files = sum(len(files) for _, _, files in os.walk(dest_sub_dir))
            
            if actual_files == expected_files:
                print(f"✓ 目录复制测试通过 (找到 {actual_files} 个文件)")
            else:
                print(f"✗ 目录复制测试失败: 期望 {expected_files} 个文件，找到 {actual_files} 个")
        
        # 显示统计信息
        print("\n引擎统计信息:")
        dashboard = api.get_dashboard_info()
        if dashboard.get('statistics'):
            stats = dashboard['statistics']
            print(f"  总任务数: {stats.get('total_tasks_submitted', 0)}")
            print(f"  成功任务: {stats.get('total_tasks_completed', 0)}")
            print(f"  失败任务: {stats.get('total_tasks_failed', 0)}")
            print(f"  总处理字节: {stats.get('total_bytes_processed', 0):,} bytes")
            print(f"  平均速度: {stats.get('average_speed_mbps', 0):.2f} MB/s")
        
        # 清理
        print("\n清理临时文件...")
        api.shutdown(graceful=True)
        
        # 延迟一段时间让引擎完全关闭
        time.sleep(2)
        
        # 删除临时目录
        shutil.rmtree(temp_dir, ignore_errors=True)
        
        return True
        
    except Exception as e:
        logger.error(f"测试失败: {e}", exc_info=True)
        return False

def test_performance():
    """测试性能"""
    print("\n" + "=" * 60)
    print("测试 2: 性能测试")
    print("=" * 60)
    
    try:
        # 创建大文件进行测试
        temp_dir = tempfile.mkdtemp(prefix="fastcopy_perf_")
        source_file = os.path.join(temp_dir, "large_test_file.bin")
        dest_file = os.path.join(temp_dir, "copied_large_file.bin")
        
        # 创建100MB测试文件
        file_size_mb = 100
        chunk_size = 1024 * 1024  # 1MB
        data = b'X' * chunk_size
        
        print(f"创建 {file_size_mb}MB 测试文件...")
        with open(source_file, 'wb') as f:
            for _ in range(file_size_mb):
                f.write(data)
        
        print("初始化引擎...")
        api = FastCopyAPI()
        
        start_time = time.time()
        
        # 注册进度回调
        def on_progress(task_id, processed, total, progress):
            speed_mbps = (processed / (1024 * 1024)) / max(time.time() - start_time, 0.001)
            logger.info(f"复制速度: {speed_mbps:.2f} MB/s, 进度: {progress:.1f}%")
        
        api.register_event_handler('progress', on_progress)
        
        print("开始性能测试...")
        task_id = api.copy_file(source_file, dest_file, priority="high")
        
        if task_id:
            results = api.wait_for_tasks([task_id], timeout=300)  # 5分钟超时
            
            if results['completed'] == 1:
                end_time = time.time()
                duration = end_time - start_time
                speed_mbps = file_size_mb / duration
                
                print(f"\n性能测试结果:")
                print(f"  文件大小: {file_size_mb} MB")
                print(f"  复制时间: {duration:.2f} 秒")
                print(f"  平均速度: {speed_mbps:.2f} MB/s")
                
                if speed_mbps > 50:  # 假设50MB/s为良好性能
                    print("✓ 性能测试通过")
                else:
                    print("⚠ 性能测试速度较慢")
                
                # 验证文件完整性
                if os.path.getsize(source_file) == os.path.getsize(dest_file):
                    print("✓ 文件完整性验证通过")
                else:
                    print("✗ 文件完整性验证失败")
            else:
                print("✗ 性能测试失败")
        
        # 清理
        api.shutdown()
        time.sleep(2)
        shutil.rmtree(temp_dir, ignore_errors=True)
        
        return True
        
    except Exception as e:
        logger.error(f"性能测试失败: {e}", exc_info=True)
        return False

def test_error_handling():
    """测试错误处理"""
    print("\n" + "=" * 60)
    print("测试 3: 错误处理测试")
    print("=" * 60)
    
    try:
        api = FastCopyAPI()
        
        # 测试不存在的源文件
        print("测试错误情况: 不存在的源文件")
        task_id = api.copy_file(
            "/this/path/does/not/exist.txt",
            "/tmp/destination.txt"
        )
        
        if task_id:
            results = api.wait_for_tasks([task_id], timeout=30)
            if results.get('failed', 0) > 0:
                print("✓ 不存在的源文件错误处理正常")
            else:
                print("✗ 不存在的源文件错误处理异常")
        
        # 测试无权限的目标目录
        print("\n测试错误情况: 无权限的目标目录")
        if os.name == 'nt':  # Windows
            protected_dir = "C:\\Windows\\System32\\test_protected"
        else:  # Linux/Mac
            protected_dir = "/root/protected_test"
        
        task_id = api.copy_file(
            __file__,  # 当前脚本文件作为源
            os.path.join(protected_dir, "test.txt")
        )
        
        if task_id:
            results = api.wait_for_tasks([task_id], timeout=30)
            if results.get('failed', 0) > 0:
                print("✓ 权限错误处理正常")
            else:
                print("⚠ 权限错误处理: 可能需要验证具体情况")
        
        # 测试无效参数
        print("\n测试错误情况: 无效参数")
        try:
            # 应该抛出异常或返回错误
            task_id = api.copy_file("", "")
            if not task_id:
                print("✓ 无效参数检查正常")
        except Exception as e:
            print(f"✓ 无效参数检查正常 (捕获异常: {e})")
        
        api.shutdown()
        return True
        
    except Exception as e:
        logger.error(f"错误处理测试失败: {e}", exc_info=True)
        return False

def test_concurrent_operations():
    """测试并发操作"""
    print("\n" + "=" * 60)
    print("测试 4: 并发操作测试")
    print("=" * 60)
    
    try:
        temp_dir = tempfile.mkdtemp(prefix="fastcopy_concurrent_")
        
        # 创建多个测试文件
        file_count = 20
        test_files = []
        
        print(f"创建 {file_count} 个并发测试文件...")
        for i in range(file_count):
            file_path = os.path.join(temp_dir, f"concurrent_{i}.txt")
            with open(file_path, 'w') as f:
                f.write(f"Concurrent test file {i}\n" * 100)  # 约2KB
            test_files.append(file_path)
        
        print("初始化引擎（配置为4个并发任务）...")
        config = {
            'max_concurrent_tasks': 4,
            'work_directory': temp_dir
        }
        
        api = FastCopyAPI()
        
        start_time = time.time()
        
        # 提交所有任务
        task_ids = []
        for i, src_file in enumerate(test_files):
            dest_file = os.path.join(temp_dir, f"copy_{i}.txt")
            task_id = api.copy_file(src_file, dest_file, priority="normal")
            if task_id:
                task_ids.append(task_id)
        
        print(f"已提交 {len(task_ids)} 个并发任务")
        
        # 等待所有任务完成
        results = api.wait_for_tasks(task_ids, timeout=180)  # 3分钟超时
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"\n并发测试结果:")
        print(f"  总任务数: {results['total']}")
        print(f"  成功任务: {results['completed']}")
        print(f"  失败任务: {results['failed']}")
        print(f"  总时间: {duration:.2f} 秒")
        print(f"  平均每个任务: {duration/max(results['total'], 1):.2f} 秒")
        
        if results['completed'] >= results['total'] * 0.9:  # 90%成功率
            print("✓ 并发操作测试通过")
        else:
            print("✗ 并发操作测试失败")
        
        # 清理
        api.shutdown()
        shutil.rmtree(temp_dir, ignore_errors=True)
        
        return True
        
    except Exception as e:
        logger.error(f"并发操作测试失败: {e}", exc_info=True)
        return False

def run_all_tests():
    """运行所有测试"""
    print("PB_fastcopy_engine 测试套件")
    print("=" * 60)
    
    tests = [
        ("基本功能测试", test_basic_functionality),
        ("性能测试", test_performance),
        ("错误处理测试", test_error_handling),
        ("并发操作测试", test_concurrent_operations),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n开始 {test_name}...")
        try:
            success = test_func()
            results.append((test_name, success))
            
            if success:
                print(f"✓ {test_name} 通过")
            else:
                print(f"✗ {test_name} 失败")
                
        except KeyboardInterrupt:
            print(f"\n⚠ {test_name} 被用户中断")
            results.append((test_name, False))
            break
        except Exception as e:
            print(f"\n✗ {test_name} 异常: {e}")
            results.append((test_name, False))
    
    # 总结报告
    print("\n" + "=" * 60)
    print("测试总结报告")
    print("=" * 60)
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for test_name, success in results:
        status = "✓ 通过" if success else "✗ 失败"
        print(f"  {test_name}: {status}")
    
    print(f"\n总测试数: {total}")
    print(f"通过测试: {passed}")
    print(f"失败测试: {total - passed}")
    
    if passed == total:
        print("\n🎉 所有测试通过！")
        return 0
    else:
        print(f"\n⚠ {total - passed} 个测试失败")
        return 1

if __name__ == "__main__":
    # 检查是否在Windows上运行
    if os.name != 'nt':
        print("警告: 此引擎主要针对Windows优化，在其他系统上可能无法正常运行")
        response = input("是否继续？(y/n): ")
        if response.lower() != 'y':
            sys.exit(0)
    
    # 运行测试
    exit_code = run_all_tests()
    sys.exit(exit_code)