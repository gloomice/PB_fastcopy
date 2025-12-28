@echo off
setlocal enabledelayedexpansion

echo PB_fastcopy_engine 构建脚本
echo ========================================

REM 检查是否安装了CMake
where cmake >nul 2>nul
if errorlevel 1 (
    echo 错误: 未找到CMake，请先安装CMake
    exit /b 1
)

REM 检查是否安装了Visual Studio
if not defined VisualStudioVersion (
    echo 警告: 未检测到Visual Studio环境
    echo 正在尝试查找vcvarsall.bat...
    
    REM 尝试常见路径
    set VS_PATHS=
    set VS_PATHS=!VS_PATHS! "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
    set VS_PATHS=!VS_PATHS! "C:\Program Files\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat"
    set VS_PATHS=!VS_PATHS! "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat"
    
    for %%p in (!VS_PATHS!) do (
        if exist %%p (
            echo 找到Visual Studio: %%p
            call "%%p" x64
            goto :vs_found
        )
    )
    
    echo 错误: 未找到Visual Studio，请安装Visual Studio 2019或更高版本
    exit /b 1
)

:vs_found
echo 使用Visual Studio版本: %VisualStudioVersion%

REM 创建构建目录
if not exist "build" mkdir build
cd build

REM 配置CMake
echo.
echo 配置CMake...
cmake .. -G "Visual Studio 16 2019" -A x64 -DCMAKE_BUILD_TYPE=Release

if errorlevel 1 (
    echo CMake配置失败
    exit /b 1
)

REM 构建项目
echo.
echo 构建项目...
cmake --build . --config Release --target ALL_BUILD

if errorlevel 1 (
    echo 构建失败
    exit /b 1
)

REM 运行测试
echo.
echo 运行测试...
if exist "bin\Release\fastcopy_test.exe" (
    bin\Release\fastcopy_test.exe
) else if exist "bin\fastcopy_test.exe" (
    bin\fastcopy_test.exe
)

REM 复制文件到输出目录
echo.
echo 复制文件...
if not exist "..\dist" mkdir ..\dist
if not exist "..\dist\bin" mkdir ..\dist\bin
if not exist "..\dist\include" mkdir ..\dist\include
if not exist "..\dist\python" mkdir ..\dist\python

REM 复制DLL和可执行文件
copy /Y "bin\Release\*.dll" "..\dist\bin\" >nul
copy /Y "bin\Release\*.exe" "..\dist\bin\" >nul
copy /Y "bin\*.dll" "..\dist\bin\" >nul
copy /Y "bin\*.exe" "..\dist\bin\" >nul

REM 复制头文件
copy /Y "..\*.h" "..\dist\include\" >nul

REM 复制Python接口
copy /Y "..\fastcopy_engine.py" "..\dist\python\" >nul
copy /Y "..\test_engine.py" "..\dist\python\" >nul

echo.
echo 构建完成！
echo 输出文件在: %cd%\..\dist
echo.
echo 文件结构:
echo   dist\bin\PB_fastcopy_engine.dll    - 引擎动态库
echo   dist\include\*.h                   - 头文件
echo   dist\python\fastcopy_engine.py     - Python接口
echo   dist\python\test_engine.py         - 测试脚本

cd ..

REM 创建Python虚拟环境（可选）
echo.
set /p CREATE_VENV="是否创建Python虚拟环境？(y/n): "
if /i "%CREATE_VENV%"=="y" (
    echo 创建Python虚拟环境...
    python -m venv venv
    echo.
    echo 虚拟环境已创建，激活命令:
    echo   venv\Scripts\activate
)

pause