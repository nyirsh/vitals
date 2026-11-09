cmake_minimum_required(VERSION 3.16)
project(vitals_libssl C)
include("$ENV{VITASDK}/share/vita.cmake" REQUIRED)

# Console output: 0 none, 1 start-up, connections, failures and every call to an export that
# isn't written yet, 2 also Mbed TLS's own messages (make DEBUG=<level>)
set(VITALS_DEBUG 0 CACHE STRING "Debug output on the console: 0, 1 or 2")
if(NOT VITALS_DEBUG MATCHES "^[012]$")
    message(FATAL_ERROR "VITALS_DEBUG must be 0, 1 or 2")
endif()

# TLS is Mbed TLS 4.2 with TF-PSA-Crypto (crypto/), with the user-mode runtime every module shares
# (../common/runtime)
set(VITALS_COMMON_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../common)
include(../dependencies.cmake)
# The release version from ../../VERSION, which the module header carries
include(../../version.cmake)
vitals_download("${VITALS_MBEDTLS_URL}" "${VITALS_MBEDTLS_SHA256}" VITALS_MBEDTLS_ARCHIVE)
add_subdirectory(crypto)

add_executable(vitals_libssl
    src/core.c
    src/connection.c
    src/certificate.c
    src/vitals.c
    src/ssl.c
    src/internal.c
    src/platform_vita.c
    src/platform_shims.c
    src/ca_index.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../shared/src/ca_scan.c
    ${VITALS_COMMON_DIR}/runtime/user_runtime.c
)
target_include_directories(vitals_libssl PRIVATE src include ${VITALS_COMMON_DIR}/runtime ${VITALS_COMMON_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../shared/include)
target_compile_definitions(vitals_libssl PRIVATE
    VITALS_DEBUG=${VITALS_DEBUG}
    VITALS_LOG_NAME="vitals-ssl"
)
target_compile_options(vitals_libssl PRIVATE -std=gnu11 -Wall -Wextra -Werror -Wshadow
    -Wstrict-prototypes -ffunction-sections -fdata-sections -Os)
set_source_files_properties(${VITALS_COMMON_DIR}/runtime/user_runtime.c PROPERTIES COMPILE_OPTIONS "-fno-builtin")

# No C library, as vitals-http: the runtime's wrappers stand in for the calls this module and Mbed
# TLS make, and every allocation comes from the pool sceSslInit makes
target_link_options(vitals_libssl PRIVATE -nostdlib -Wl,--gc-sections
    -Wl,--undefined=module_start -Wl,--undefined=module_stop
    -Wl,-T,${CMAKE_CURRENT_SOURCE_DIR}/sce_gap.ld -Wl,--undefined=module_sdk_version)
foreach(function malloc calloc realloc free memchr memcmp memcpy memmove memset strchr strcmp strlen
        strstr printf puts snprintf vsnprintf)
    target_link_options(vitals_libssl PRIVATE "-Wl,--wrap=${function}")
endforeach()
# Nothing in the module calls its exports, so --gc-sections would drop them: each one the yml lists
# is kept
file(STRINGS libssl_api.yml.in export_lines REGEX "^ +- (sceSsl|vitalsSsl)[A-Za-z0-9]+:")
foreach(line ${export_lines})
    string(REGEX REPLACE "^ +- ((sceSsl|vitalsSsl)[A-Za-z0-9]+):.*$" "\\1" function "${line}")
    target_link_options(vitals_libssl PRIVATE "-Wl,--undefined=${function}")
endforeach()
# vitals' certificate store is read through the kernel plugin's system call, from the stub its
# build generates (no process but the kernel can open ux0:data/vitals/system)
set(VITALS_KERNEL_STUB "${CMAKE_BINARY_DIR}/../vitals-boot/stubs/libvitals_kernel_stub.a")
if(NOT EXISTS "${VITALS_KERNEL_STUB}")
    message(FATAL_ERROR "${VITALS_KERNEL_STUB} is missing; build ../vitals-boot first (make does this)")
endif()
target_link_libraries(vitals_libssl PRIVATE
    ${VITALS_KERNEL_STUB}
    mbedtls
    mbedx509
    tfpsacrypto
    gcc
    SceLibKernel_stub
    SceKernelThreadMgr_stub
    SceSysmem_stub
    SceIofilemgr_stub
    SceNet_stub
    SceRtc_stub
)

configure_file(libssl_api.yml.in libssl_api.yml @ONLY)
vita_create_self(libssl.suprx vitals_libssl
    CONFIG ${CMAKE_CURRENT_BINARY_DIR}/libssl_api.yml UNSAFE)
# The stubs that import it (stubs/lib<library>_stub.a and _stub_weak.a), which vitals-http links to
# use the libssl module as Sony's libhttp does
add_custom_target(vitals_ssl_stubs ALL
    COMMAND vita-elf-export user $<TARGET_FILE:vitals_libssl> ${CMAKE_CURRENT_BINARY_DIR}/libssl_api.yml
        libssl_exports.yml
    COMMAND vita-libs-gen libssl_exports.yml stubs
    COMMAND make -C stubs
    DEPENDS vitals_libssl
)
