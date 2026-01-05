cmake_minimum_required(VERSION 3.15)
project(HeapMasteryCourse C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# Compiler flags for security education
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -Wall -Wextra -fno-stack-protector")

# Build options
option(BUILD_SOLUTIONS "Build solution/exploit programs" OFF)
option(ENABLE_PROTECTIONS "Enable binary protections (NX, PIE, etc.)" OFF)

# Enable protections if requested
if(ENABLE_PROTECTIONS)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wformat -Wformat-security -fstack-protector-all")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro -Wl,-z,now -pie")
    message(STATUS "Building WITH binary protections")
else()
    message(STATUS "Building WITHOUT binary protections (for learning)")
endif()

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/common/include)

# Common utilities library
add_library(heap_utils STATIC
    common/src/heap_utils.c
    common/src/debug_utils.c
)

# glibc info tool
add_executable(glibc_info common/src/glibc_info.c)
target_link_libraries(glibc_info ${CMAKE_DL_LIBS})

# Add subdirectories for each level
add_subdirectory(level00_setup)
add_subdirectory(level01_overflow)
add_subdirectory(level02_uaf)
add_subdirectory(level03_fastbin_dup)
add_subdirectory(level04_tcache)
add_subdirectory(level05_heap_spray)
add_subdirectory(level06_feng_shui)
add_subdirectory(level07_advanced)

# Testing
enable_testing()
add_subdirectory(tests)

message(STATUS "")
message(STATUS "Heap Mastery Course Configuration:")
message(STATUS "  Build Solutions: ${BUILD_SOLUTIONS}")
message(STATUS "  Enable Protections: ${ENABLE_PROTECTIONS}")
message(STATUS "")
