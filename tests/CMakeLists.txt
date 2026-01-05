# Testing infrastructure

# Test compilation
add_test(NAME test_level01_compile COMMAND ${CMAKE_MAKE_PROGRAM} -C ${CMAKE_SOURCE_DIR}/level01_overflow/challenge)

# Add more tests as needed
# add_test(NAME test_level02_compile COMMAND ${CMAKE_MAKE_PROGRAM} -C ${CMAKE_SOURCE_DIR}/level02_uaf/challenge)

# Custom target to run verify_all.sh
add_custom_target(verify
    COMMAND ${CMAKE_SOURCE_DIR}/tests/verify_all.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running verification script for all levels..."
    VERBATIM
)

# Add a 'make test' alias for the verify target
add_custom_target(test_exploits
    DEPENDS verify
    COMMENT "Testing all exploits..."
)
