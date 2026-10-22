include("${VITASDK}/share/vita.cmake" REQUIRED)
set(VITALS_HTTP_CA_PATH "vs0:/data/external/cert/CA_LIST.cer" CACHE STRING
    "Authoritative HTTP trust bundle; diagnostics use a separately staged VPK bundle")

set(VITALS_HTTP_HEAP_KIB 128 CACHE STRING
    "Provider heap in KiB (one physical memory block per injected process)")
if(NOT VITALS_HTTP_HEAP_KIB MATCHES "^[0-9]+$" OR VITALS_HTTP_HEAP_KIB LESS 64
   OR VITALS_HTTP_HEAP_KIB GREATER 4096)
    message(FATAL_ERROR "VITALS_HTTP_HEAP_KIB must be 64..4096")
endif()
math(EXPR VITALS_HTTP_HEAP_BYTES_VALUE "${VITALS_HTTP_HEAP_KIB} * 1024")

add_executable(vitals_http
    ca_file.c
    ca_index.c
    cert_hooks.c
    host_redirect.c
    provider.c
    platform_shims.c
    private_mapping.c
    transport.c
    trust_store.c
    user_runtime.c
    vita_net.c
)
if(VITALS_DEBUG GREATER_EQUAL 1)
    target_sources(vitals_http PRIVATE http_trace.c)
endif()

target_include_directories(vitals_http PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_compile_features(vitals_http PRIVATE c_std_11)
target_compile_definitions(vitals_http PRIVATE
    VITALS_DEBUG=${VITALS_DEBUG}
    VITALS_LOG_PREFIX="vitals_http"
    VITALS_HTTP_HEAP_BYTES=${VITALS_HTTP_HEAP_BYTES_VALUE}u
    VITALS_DEFAULT_CA_PATH="${VITALS_HTTP_CA_PATH}"
)
target_compile_options(vitals_http PRIVATE
    -std=gnu11
    -Wall
    -Wextra
    -Werror
    -Wshadow
    -Wstrict-prototypes
    -ffunction-sections
    -fdata-sections
    -Os
)

target_link_options(vitals_http PRIVATE
    -nostdlib
    -Wl,--gc-sections
    -Wl,--undefined=module_start
    -Wl,--undefined=module_stop
)
set(vitals_runtime_wrappers malloc calloc realloc free memchr memcmp memcpy memmove memset
    strchr strcmp strlen strstr printf puts snprintf vsnprintf)
foreach(function ${vitals_runtime_wrappers})
    target_link_options(vitals_http PRIVATE "-Wl,--wrap=${function}")
endforeach()
set_source_files_properties(user_runtime.c PROPERTIES COMPILE_OPTIONS "-fno-builtin")

# The kernel plugin's system call that reads the redirect list (host_redirect.c), from the
# stub its build generates
set(VITALS_KERNEL_STUB "${CMAKE_BINARY_DIR}/../vitals-plugin/stubs/libvitals_kernel_stub.a")
if(NOT EXISTS "${VITALS_KERNEL_STUB}")
    message(FATAL_ERROR "${VITALS_KERNEL_STUB} is missing; build ../vitals-plugin first (make does this)")
endif()
target_link_libraries(vitals_http PRIVATE
    vitals_core
    ${VITALS_KERNEL_STUB}
    mbedtls
    mbedx509
    tfpsacrypto
    gcc
    SceAppMgr_stub
    SceSysmem_stub
    SceNet_stub
    SceIofilemgr_stub
    SceRtc_stub
    SceLibKernel_stub
    SceKernelModulemgr_stub
    SceKernelThreadMgr_stub
    taihen_stub
)

# The module header carries the release version from ../../VERSION
configure_file(vitals_http.yml.in vitals_http.yml @ONLY)
vita_create_self(
    vitals_http.suprx
    vitals_http
    CONFIG ${CMAKE_CURRENT_BINARY_DIR}/vitals_http.yml
    UNSAFE
)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_custom_target(vitals_http_runtime_check ALL
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/../tools/check_http_runtime.py
        ${CMAKE_CURRENT_BINARY_DIR}/vitals_http.suprx
    DEPENDS vitals_http.suprx-self
    VERBATIM
)
