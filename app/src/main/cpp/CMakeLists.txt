cmake_minimum_required(VERSION 3.18)
project(injnative C)

add_library(injnative SHARED native_inj.c)

find_library(log-lib log)
target_link_libraries(injnative ${log-lib})