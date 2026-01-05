# Level 1: Heap Overflow
add_executable(l1_vuln challenge/vuln.c)

# Build solutions only if requested
if(BUILD_SOLUTIONS)
    add_executable(l1_exploit_solution solution/exploit.c)
    target_link_libraries(l1_exploit_solution heap_utils)
endif()
