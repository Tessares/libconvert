cmake_minimum_required(VERSION 3.3)
project(libconvert C)

option(BUILD_TESTS "" OFF)
option(BUILD_EXAMPLES "" OFF)
add_subdirectory(lib/syscall_intercept)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -Wextra")

add_library(convert SHARED convert.c convert_util.c lib/log.c/src/log.c)

include_directories(lib)
include_directories(lib/syscall_intercept/include)
include_directories(lib/log.c/src)
target_link_libraries(convert PRIVATE syscall_intercept_static)

set(LIBCONVERT_SOURCES convert.c convert.h convert_util.c convert_util.h)

enable_testing()

add_test(NAME uncrustify
         COMMAND uncrustify -c uncrustify.cfg --check -l C ${LIBCONVERT_SOURCES}
         WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})

add_test(NAME cppcheck
         COMMAND cppcheck -I/usr/include -q
                          --language=c --std=c99 --error-exitcode=1
                          --enable=warning,style,performance,portability
                          --suppress=unusedStructMember ${LIBCONVERT_SOURCES}
         WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})

add_subdirectory(tests)
