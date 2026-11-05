cmake_minimum_required(VERSION 3.18)
project(injnative C)

add_library(injnative SHARED native_inj.c)

# The race writers rely on mixed declarations and on atomics that need C99 at
# the very least; pin the standard so the toolchain default cannot change it.
set_target_properties(injnative PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON)

find_library(log-lib log)

# No -lpthread here on purpose: bionic merged pthread into libc and the NDK no
# longer ships a libpthread stub, so asking for it fails at link time with
# "unable to find library -lpthread".
target_link_libraries(injnative ${log-lib})