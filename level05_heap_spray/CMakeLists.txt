# Level 5: Heap Spraying
add_executable(l5_vuln challenge/vuln.c)

if(BUILD_SOLUTIONS)
    add_executable(l5_exploit_solution solution/exploit.c)
    target_link_libraries(l5_exploit_solution heap_utils)
endif()
