set(TEST_WRAPPER "${PROJECT_SOURCE_DIR}/tests/test-wrapper")


foreach(TEST_CMD "curl" "wget")
    foreach(TEST_TYPE "test_ok" "test_error")
        set (test_name "${TEST_CMD}-${TEST_TYPE}")

        add_test(NAME "${test_name}"
                COMMAND ${TEST_WRAPPER} "${TEST_TYPE}.py")
        set_tests_properties("${test_name}" PROPERTIES
            ENVIRONMENT
            "SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR};BUILD_DIR=${PROJECT_BINARY_DIR};TOP_SOURCE_DIR=${PROJECT_SOURCE_DIR};TEST_CMD=${TEST_CMD}"
           TIMEOUT 5)
    endforeach()
endforeach()

