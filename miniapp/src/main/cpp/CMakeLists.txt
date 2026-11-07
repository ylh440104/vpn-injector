cmake_minimum_required(VERSION 3.18.1)

project(mini C)

add_library(native SHARED native.c)

find_library(log-lib log)
target_link_libraries(native ${log-lib})