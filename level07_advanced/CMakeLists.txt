# Level 7: Advanced Techniques
add_executable(l7_vuln challenge/vuln.c)

if(BUILD_SOLUTIONS)
    add_executable(l7_exploit_solution solution/exploit.c)
    target_link_libraries(l7_exploit_solution heap_utils)
endif()
