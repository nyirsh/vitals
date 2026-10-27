cmake_minimum_required(VERSION 3.16)
project(vitals_http_lib C)
include("$ENV{VITASDK}/share/vita.cmake" REQUIRED)

# Console output: 0 none, 1 start-up, connections and failures, 2 also every TLS step
# (make DEBUG=<level>)
set(VITALS_DEBUG 0 CACHE STRING "Debug output on the console: 0, 1 or 2")
if(NOT VITALS_DEBUG MATCHES "^[012]$")
    message(FATAL_ERROR "VITALS_DEBUG must be 0, 1 or 2")
endif()
# TLS's heap, apart from the pool the app gives sceHttpInit: about 40 KiB per open https
# connection, plus a certificate chain while it is checked
set(VITALS_HTTP_TLS_HEAP_KIB 128 CACHE STRING "TLS heap in KiB (one memory block per process)")
if(NOT VITALS_HTTP_TLS_HEAP_KIB MATCHES "^[0-9]+$" OR VITALS_HTTP_TLS_HEAP_KIB LESS 64
   OR VITALS_HTTP_TLS_HEAP_KIB GREATER 4096)
    message(FATAL_ERROR "VITALS_HTTP_TLS_HEAP_KIB must be 64..4096")
endif()
math(EXPR VITALS_HTTP_TLS_HEAP_BYTES "${VITALS_HTTP_TLS_HEAP_KIB} * 1024")

# What follows an app's own User-Agent unless ux0:data/vitals/useragent.txt gives another: printable
# ASCII without the characters that would break the C string or the build's quoting
set(VITALS_HTTP_USER_AGENT "libhttp/3.74 (PS Vita)" CACHE STRING "User-Agent suffix after the app's own")
string(LENGTH "${VITALS_HTTP_USER_AGENT}" VITALS_HTTP_USER_AGENT_LENGTH)
if(VITALS_HTTP_USER_AGENT_LENGTH EQUAL 0 OR VITALS_HTTP_USER_AGENT_LENGTH GREATER 127
   OR NOT VITALS_HTTP_USER_AGENT MATCHES "^[ -~]+$" OR VITALS_HTTP_USER_AGENT MATCHES "[\"\\#$;`']")
    message(FATAL_ERROR "VITALS_HTTP_USER_AGENT must be 1..127 printable ASCII characters, without \" \\ # $ ; ` '")
endif()
# The bundle the vitals app installs, which the HTTP provider trusts too
set(VITALS_HTTP_CA_PATH "vs0:/data/external/cert/CA_LIST.cer" CACHE STRING "Trusted CA bundle (PEM)")

# TLS is Mbed TLS 3.6 (tls13-vita/crypto, shared with the browser provider), with tls13-vita's CA index, certificate flags and runtime
set(TLS13_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../tls13-vita)
include(../dependencies.cmake)
# The release version from ../VERSION, which the module header carries
include(../version.cmake)
vitals_download("${VITALS_MBEDTLS_URL}" "${VITALS_MBEDTLS_SHA256}" VITALS_MBEDTLS_ARCHIVE)
add_subdirectory(${TLS13_DIR}/crypto crypto)

add_executable(vitals_libhttp
    src/core.c
    src/request.c
    src/message.c
    src/uri.c
    src/cookie.c
    src/inflate.c
    src/async.c
    src/private.c
    src/redirect.c
    src/useragent.c
    src/tls.c
    ${TLS13_DIR}/provider/platform_shims.c
    src/platform_vita.c
    ${TLS13_DIR}/provider/ca_index.c
    ${TLS13_DIR}/provider/user_runtime.c
    ${TLS13_DIR}/src/error_map.c
    ${TLS13_DIR}/src/host_map.c
    ${TLS13_DIR}/src/redirect_list.c
)
target_include_directories(vitals_libhttp PRIVATE src ${TLS13_DIR}/provider ${TLS13_DIR}/include)
target_compile_definitions(vitals_libhttp PRIVATE
    VITALS_DEBUG=${VITALS_DEBUG}
    VITALS_LOG_PREFIX="vitals-http"
    VITALS_HTTP_HEAP_BYTES=${VITALS_HTTP_TLS_HEAP_BYTES}u
    VITALS_HTTP_CA_PATH="${VITALS_HTTP_CA_PATH}"
    VH_DEFAULT_SUFFIX="${VITALS_HTTP_USER_AGENT}"
)
target_compile_options(vitals_libhttp PRIVATE -std=gnu11 -Wall -Wextra -Werror -Wshadow
    -Wstrict-prototypes -ffunction-sections -fdata-sections -Os)
set_source_files_properties(${TLS13_DIR}/provider/user_runtime.c PROPERTIES COMPILE_OPTIONS "-fno-builtin")

# No C library: the runtime's wrappers stand in for the calls this module and its libraries make
target_link_options(vitals_libhttp PRIVATE -nostdlib -Wl,--gc-sections
    -Wl,--undefined=module_start -Wl,--undefined=module_stop
    -Wl,-T,${CMAKE_CURRENT_SOURCE_DIR}/sce_gap.ld)
foreach(function malloc calloc realloc free memchr memcmp memcpy memmove memset strchr strcmp strlen
        strstr printf puts snprintf vsnprintf)
    target_link_options(vitals_libhttp PRIVATE "-Wl,--wrap=${function}")
endforeach()
# Nothing in the module calls its exports, so --gc-sections would drop them: each one the yml lists
# is kept
file(STRINGS vitals_http_api.yml.in export_lines REGEX "^ +- sceHttps?[A-Za-z0-9]+:")
foreach(line ${export_lines})
    string(REGEX REPLACE "^ +- (sceHttps?[A-Za-z0-9]+):.*$" "\\1" function "${line}")
    target_link_options(vitals_libhttp PRIVATE "-Wl,--undefined=${function}")
endforeach()
# The host redirect list is read through the kernel plugin's system call, from the stub its build
# generates
set(VITALS_KERNEL_STUB "${CMAKE_BINARY_DIR}/../vitals-plugin/stubs/libvitals_kernel_stub.a")
if(NOT EXISTS "${VITALS_KERNEL_STUB}")
    message(FATAL_ERROR "${VITALS_KERNEL_STUB} is missing; build ../vitals-plugin first (make does this)")
endif()
target_link_libraries(vitals_libhttp PRIVATE
    ${VITALS_KERNEL_STUB}
    mbedtls
    mbedx509
    mbedcrypto
    z
    gcc
    SceAppMgr_stub
    SceLibKernel_stub
    SceKernelThreadMgr_stub
    SceSysmem_stub
    SceIofilemgr_stub
    SceNet_stub
    SceRtc_stub
)

configure_file(vitals_http_api.yml.in vitals_http_api.yml @ONLY)
vita_create_self(libhttp.suprx vitals_libhttp
    CONFIG ${CMAKE_CURRENT_BINARY_DIR}/vitals_http_api.yml UNSAFE)
