cmake_minimum_required(VERSION 3.16)
project(vitals_libssl C)
include("$ENV{VITASDK}/share/vita.cmake" REQUIRED)

# Console output: 0 none, 1 start-up, connections, failures and every call to an export that
# isn't written yet, 2 also Mbed TLS's own messages (make DEBUG=<level>)
set(VITALS_DEBUG 0 CACHE STRING "Debug output on the console: 0, 1 or 2")
if(NOT VITALS_DEBUG MATCHES "^[012]$")
    message(FATAL_ERROR "VITALS_DEBUG must be 0, 1 or 2")
endif()
# The bundle the vitals app installs, which servers are checked against
set(VITALS_SSL_CA_PATH "vs0:/data/external/cert/CA_LIST.cer" CACHE STRING "Trusted CA bundle (PEM)")

# TLS is Mbed TLS 3.6 (tls13-vita/crypto, shared with vitals-http and the browser provider), with
# tls13-vita's CA index and runtime
set(TLS13_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../tls13-vita)
include(../dependencies.cmake)
# The release version from ../VERSION, which the module header carries
include(../version.cmake)
vitals_download("${VITALS_MBEDTLS_URL}" "${VITALS_MBEDTLS_SHA256}" VITALS_MBEDTLS_ARCHIVE)
add_subdirectory(${TLS13_DIR}/crypto crypto)

add_executable(vitals_libssl
    src/core.c
    src/connection.c
    src/certificate.c
    src/vitals.c
    src/ssl.c
    src/internal.c
    src/platform_vita.c
    ${TLS13_DIR}/provider/platform_shims.c
    ${TLS13_DIR}/provider/ca_index.c
    ${TLS13_DIR}/provider/user_runtime.c
)
target_include_directories(vitals_libssl PRIVATE src include ${TLS13_DIR}/provider ${TLS13_DIR}/include)
target_compile_definitions(vitals_libssl PRIVATE
    VITALS_DEBUG=${VITALS_DEBUG}
    VITALS_LOG_PREFIX="vitals-ssl"
    VITALS_SSL_CA_PATH="${VITALS_SSL_CA_PATH}"
)
target_compile_options(vitals_libssl PRIVATE -std=gnu11 -Wall -Wextra -Werror -Wshadow
    -Wstrict-prototypes -ffunction-sections -fdata-sections -Os)
set_source_files_properties(${TLS13_DIR}/provider/user_runtime.c PROPERTIES COMPILE_OPTIONS "-fno-builtin")

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
target_link_libraries(vitals_libssl PRIVATE
    mbedtls
    mbedx509
    mbedcrypto
    gcc
    SceAppMgr_stub
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
