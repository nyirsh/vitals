cmake_minimum_required(VERSION 3.16)
project(vitals_reauth C)
include("$ENV{VITASDK}/share/vita.cmake" REQUIRED)

# Console output: 0 none, 1 or 2 log each hook and redirect (make DEBUG=<level>)
set(VITALS_DEBUG 0 CACHE STRING "Debug output on the console: 0, 1 or 2")
if(NOT VITALS_DEBUG MATCHES "^[012]$")
    message(FATAL_ERROR "VITALS_DEBUG must be 0, 1 or 2")
endif()

add_executable(vitals_reauth main.c)
target_compile_definitions(vitals_reauth PRIVATE VITALS_DEBUG=${VITALS_DEBUG})
target_compile_options(vitals_reauth PRIVATE -std=gnu11 -Wall -Wextra -Werror -Os)
target_link_options(vitals_reauth PRIVATE -nostdlib -Wl,--gc-sections
    -Wl,--undefined=module_start -Wl,--undefined=module_stop)
target_link_libraries(vitals_reauth PRIVATE taihen_stub SceLibKernel_stub gcc)

# The module header carries the release version from ../VERSION
include(../version.cmake)
configure_file(vitals_reauth.yml.in vitals_reauth.yml @ONLY)
vita_create_self(vitals-reauth.suprx vitals_reauth
    CONFIG ${CMAKE_CURRENT_BINARY_DIR}/vitals_reauth.yml UNSAFE)
