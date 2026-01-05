# Level 4: Tcache Poisoning
add_executable(l4_vuln challenge/vuln.c)

if(BUILD_SOLUTIONS)
    add_executable(l4_exploit_solution solution/exploit.c)
    target_link_libraries(l4_exploit_solution heap_utils)
endif()
