set(TEST_WRAPPER "${PROJECT_SOURCE_DIR}/tests/test-wrapper")

add_test(NAME test-ok
        COMMAND ${TEST_WRAPPER} test_ok.py)
add_test(NAME test-error-tlv
        COMMAND ${TEST_WRAPPER} test_error.py)


set_tests_properties(test-ok test-error-tlv PROPERTIES
    ENVIRONMENT "SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR};BUILD_DIR=${PROJECT_BINARY_DIR};TOP_SOURCE_DIR=${PROJECT_SOURCE_DIR}"
    TIMEOUT 5)

