cmake_minimum_required(VERSION 3.3)
project(libconverter C)

option(BUILD_TESTS "" OFF)
option(BUILD_EXAMPLES "" OFF)
add_subdirectory(lib/syscall_intercept)

add_library(converter SHARED converter.c)
include_directories(lib/syscall_intercept/include)
target_link_libraries(converter PRIVATE syscall_intercept_static)
