# Level 0: Environment Setup
add_executable(check_env check_env.c)
target_link_libraries(check_env ${CMAKE_SOURCE_DIR}/build/libheap_utils.a)
