cmake_minimum_required(VERSION 3.0)
project(rpo_sve C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=armv8-a+sve -Wall -Wextra -pedantic -g -O3")

add_library(rpo_sve library.c rpo_hash.h)

add_executable(rpo_test test.c)
target_link_libraries(rpo_test rpo_sve)
