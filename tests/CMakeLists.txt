enable_testing()
set(LIBCONVERT_SOURCES ${LIBCONVERT_SOURCES} tests/check_convert_util.c PARENT_SCOPE)

# libconvert_util unit tests
find_package(PkgConfig REQUIRED)
pkg_check_modules(CHECK REQUIRED check)

include_directories(${CHECK_INCLUDE_DIRS})
link_directories(${CHECK_LIBRARY_DIRS})

set(TEST_SOURCES
    check_convert_util.c
)

include_directories(AFTER ${PROJECT_SOURCE_DIR})
add_executable(check_convert_util ${TEST_SOURCES})
target_link_libraries(check_convert_util
                      convert_util ${CHECK_LIBRARIES} ${CHECK_LDFLAGS})

add_test(NAME check_convert_util
         COMMAND check_convert_util)

# libconvert_client integration tests

set(TEST_WRAPPER "${PROJECT_SOURCE_DIR}/tests/test-wrapper")

foreach(TEST_CMD "curl" "wget")
    foreach(TEST_TYPE "test_ok" "test_error" "test_cookie_ok" "test_cookie_error")
        set (test_name "${TEST_CMD}-${TEST_TYPE}")

        add_test(NAME "${test_name}"
                COMMAND ${TEST_WRAPPER} "${TEST_TYPE}.py")
        set_tests_properties("${test_name}" PROPERTIES
            ENVIRONMENT
            "SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR};BUILD_DIR=${PROJECT_BINARY_DIR};TOP_SOURCE_DIR=${PROJECT_SOURCE_DIR};TEST_CMD=${TEST_CMD}"
           TIMEOUT 5)
    endforeach()
endforeach()

