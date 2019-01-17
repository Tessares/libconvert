cmake_minimum_required(VERSION 3.3)
project(libconvert C)

option(BUILD_TESTS "" OFF)
option(BUILD_EXAMPLES "" OFF)
add_subdirectory(lib/syscall_intercept)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -Wextra -Wno-unused-parameter")

add_library(convert SHARED convert.c convert_util.c lib/log.c/src/log.c)
include_directories(lib/syscall_intercept/include)
include_directories(lib/log.c/src)
target_link_libraries(convert PRIVATE syscall_intercept_static)
