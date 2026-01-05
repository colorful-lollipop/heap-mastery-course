# Level 6: Heap Feng Shui
add_executable(l6_vuln challenge/vuln.c)

if(BUILD_SOLUTIONS)
    add_executable(l6_exploit_solution solution/exploit.c)
    target_link_libraries(l6_exploit_solution heap_utils)
endif()
