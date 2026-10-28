cmake_minimum_required(VERSION 3.16)
project(vitals_diag C)
include("$ENV{VITASDK}/share/vita.cmake" REQUIRED)

# A temporary diagnostic: logs the PS Store's calls into Sony's libhttp (see main.c)
add_executable(vitals_diag main.c)
target_compile_options(vitals_diag PRIVATE -std=gnu11 -Wall -Wextra -Werror -Os
    -fno-builtin -fno-tree-loop-distribute-patterns)
target_link_options(vitals_diag PRIVATE -nostdlib -Wl,--gc-sections
    -Wl,--undefined=module_start -Wl,--undefined=module_stop)
target_link_libraries(vitals_diag PRIVATE taihen_stub SceLibKernel_stub SceKernelModulemgr_stub gcc)
vita_create_self(vitals-diag.suprx vitals_diag CONFIG ${CMAKE_CURRENT_SOURCE_DIR}/vitals_diag.yml UNSAFE)
