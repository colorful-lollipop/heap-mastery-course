# Level 3: Fastbin Double Free
add_executable(l3_vuln challenge/vuln.c)

if(BUILD_SOLUTIONS)
    add_executable(l3_exploit_solution solution/exploit.c)
    target_link_libraries(l3_exploit_solution heap_utils)
endif()
