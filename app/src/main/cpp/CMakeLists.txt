cmake_minimum_required(VERSION 3.18)
project(injnative C)

add_library(injnative SHARED native_inj.c)

find_library(log-lib log)

# pthread is part of libc on modern Android, but the race writers really do
# call pthread_create and pthread_join, so link it explicitly rather than
# relying on the platform default.
target_link_libraries(injnative ${log-lib} pthread)