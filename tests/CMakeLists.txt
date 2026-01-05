# Testing infrastructure

# Test compilation
add_test(NAME test_level01_compile COMMAND ${CMAKE_MAKE_PROGRAM} -C ${CMAKE_SOURCE_DIR}/level01_overflow/challenge)

# Add more tests as needed
# add_test(NAME test_level02_compile COMMAND ${CMAKE_MAKE_PROGRAM} -C ${CMAKE_SOURCE_DIR}/level02_uaf/challenge)
