cmake_minimum_required(VERSION 3.7)
project(block_addr)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_COMPILER gcc)
set(CMAKE_C_FLAGS "-fPIC -shared")
set(SOURCE_FILES library.c)
add_library(block_addr SHARED ${SOURCE_FILES})