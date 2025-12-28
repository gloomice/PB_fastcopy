cmake_minimum_required(VERSION 3.15)
project(PB_fastcopy_engine VERSION 1.0.0 LANGUAGES C)

# 设置C标准
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# 编译器选项
if(MSVC)
    # MSVC编译器选项
    add_compile_options(/W4 /WX /O2 /MT)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS -DNOMINMAX)
else()
    # GCC/Clang编译器选项
    add_compile_options(-Wall -Wextra -Werror -O3)
endif()

# 设置输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# 包含目录
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

# 查找Windows SDK
if(WIN32)
    find_package(Winsdk REQUIRED)
endif()

# 源文件列表
set(ENGINE_SOURCES
    pb_engine_core.c
    pb_engine_adapters.c
    pb_engine_scheduler.c
    pb_engine_error.c
    pb_engine_monitor.c
    pb_engine_api.c
)

# 头文件列表
set(ENGINE_HEADERS
    PB_fastcopy_engine.h
    pb_engine_adapters.h
    pb_engine_scheduler.h
    pb_engine_error.h
    pb_engine_monitor.h
    pb_engine_api.h
)

# 添加可执行文件（测试程序）
add_executable(fastcopy_test
    test_engine.c
    ${ENGINE_SOURCES}
)

# 添加动态库
add_library(fastcopy_engine SHARED
    ${ENGINE_SOURCES}
    ${ENGINE_HEADERS}
)

# 设置库属性
set_target_properties(fastcopy_engine PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    OUTPUT_NAME "PB_fastcopy_engine"
)

# 链接库
if(WIN32)
    target_link_libraries(fastcopy_test
        kernel32.lib
        user32.lib
        advapi32.lib
        ws2_32.lib
        mswsock.lib
    )
    
    target_link_libraries(fastcopy_engine
        kernel32.lib
        user32.lib
        advapi32.lib
        ws2_32.lib
        mswsock.lib
    )
endif()

# 安装目标
install(TARGETS fastcopy_engine
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(FILES ${ENGINE_HEADERS}
    DESTINATION include/fastcopy
)

# 添加测试
if(BUILD_TESTING)
    enable_testing()
    add_test(NAME engine_basic_test
        COMMAND fastcopy_test --test=basic
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    )
endif()

# 打包目标
set(CPACK_PACKAGE_NAME "PB_fastcopy_engine")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_VENDOR "Your Company")
set(CPACK_PACKAGE_DESCRIPTION "High-performance PB-level file copy engine")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_NAME}")

include(CPack)