cmake_minimum_required(VERSION 3.3)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")
project(libconvert C)

option(BUILD_TESTS "" OFF)
option(BUILD_EXAMPLES "" OFF)
add_subdirectory(lib/syscall_intercept)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -Wextra")

include_directories(lib)
include_directories(lib/syscall_intercept/include)
include_directories(lib/log.c/src)

# libconvert_util
add_library(convert_util SHARED convert_util.c)

# libconvert_client
add_library(convert_client SHARED convert_client.c lib/log.c/src/log.c)
target_link_libraries(convert_client PRIVATE syscall_intercept_static convert_util)

# Unit & integration tests
add_subdirectory(tests)

# Tests for code linting & formatting
enable_testing()

list(APPEND LIBCONVERT_SOURCES convert_client.c convert.h convert_util.c convert_util.h)

add_test(NAME uncrustify
         COMMAND uncrustify -c uncrustify.cfg --check -l C ${LIBCONVERT_SOURCES}
         WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})

add_test(NAME cppcheck
         COMMAND cppcheck -I/usr/include -q
                          --language=c --std=c99 --error-exitcode=1
                          --enable=warning,style,performance,portability
                          --suppress=unusedStructMember ${LIBCONVERT_SOURCES}
         WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})

