# Level 2: Use-After-Free
add_executable(l2_vuln challenge/vuln.c)

if(BUILD_SOLUTIONS)
    add_executable(l2_exploit_solution solution/exploit.c)
    target_link_libraries(l2_exploit_solution heap_utils)
endif()
