cmake_minimum_required(VERSION 3.16)
project(vitals_libssl C)
include("$ENV{VITASDK}/share/vita.cmake" REQUIRED)

# Console output: 0 none, 1 start-up and every call to an export that isn't written yet
# (make DEBUG=<level>)
set(VITALS_DEBUG 0 CACHE STRING "Debug output on the console: 0, 1 or 2")
if(NOT VITALS_DEBUG MATCHES "^[012]$")
    message(FATAL_ERROR "VITALS_DEBUG must be 0, 1 or 2")
endif()

set(TLS13_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../tls13-vita)
# The release version from ../VERSION, which the module header carries
include(../version.cmake)

add_executable(vitals_libssl
    src/ssl.c
    src/internal.c
    src/platform_vita.c
)
target_include_directories(vitals_libssl PRIVATE src ${TLS13_DIR}/provider)
target_compile_definitions(vitals_libssl PRIVATE
    VITALS_DEBUG=${VITALS_DEBUG}
    VITALS_LOG_PREFIX="vitals-ssl"
)
target_compile_options(vitals_libssl PRIVATE -std=gnu11 -Wall -Wextra -Werror -Wshadow
    -Wstrict-prototypes -ffunction-sections -fdata-sections -Os)

# No C library, as vitals-http
target_link_options(vitals_libssl PRIVATE -nostdlib -Wl,--gc-sections
    -Wl,--undefined=module_start -Wl,--undefined=module_stop
    -Wl,-T,${CMAKE_CURRENT_SOURCE_DIR}/sce_gap.ld -Wl,--undefined=module_sdk_version)
# Nothing in the module calls its exports, so --gc-sections would drop them: each one the yml lists
# is kept
file(STRINGS libssl_api.yml.in export_lines REGEX "^ +- sceSsl[A-Za-z0-9]+:")
foreach(line ${export_lines})
    string(REGEX REPLACE "^ +- (sceSsl[A-Za-z0-9]+):.*$" "\\1" function "${line}")
    target_link_options(vitals_libssl PRIVATE "-Wl,--undefined=${function}")
endforeach()
target_link_libraries(vitals_libssl PRIVATE
    gcc
    SceLibKernel_stub
)

# Without debug output the skeleton imports nothing, which vita-elf-create refuses without -n
set(VITA_ELF_CREATE_FLAGS "-n")
configure_file(libssl_api.yml.in libssl_api.yml @ONLY)
vita_create_self(libssl.suprx vitals_libssl
    CONFIG ${CMAKE_CURRENT_BINARY_DIR}/libssl_api.yml UNSAFE)
