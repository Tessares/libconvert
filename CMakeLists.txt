cmake_minimum_required(VERSION 3.3)
project(libconverter C)

option(BUILD_TESTS "" OFF)
option(BUILD_EXAMPLES "" OFF)
add_subdirectory(lib/syscall_intercept)
