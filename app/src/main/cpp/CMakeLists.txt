cmake_minimum_required(VERSION 3.18)
project(injnative C)

add_library(injnative SHARED native_inj.c)

# The race writers rely on mixed declarations and on atomics that need C99 at
# the very least; pin the standard so the toolchain default cannot change it.
set_target_properties(injnative PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON)

find_library(log-lib log)

# pthread is part of libc on modern Android, but the race writers really do
# call pthread_create and pthread_join, so link it explicitly rather than
# relying on the platform default.
target_link_libraries(injnative ${log-lib} pthread)