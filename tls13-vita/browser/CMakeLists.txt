include("${VITASDK}/share/vita.cmake" REQUIRED)

add_executable(vitals
    module.c
    backend.c
    config.c
    webkit_callback.c
    ../provider/ca_file.c
    ../provider/ca_index.c
    ../provider/platform_shims.c
)
# Messages printed by Mbed TLS and the other linked code are shown only at debug level 2
if(VITALS_DEBUG LESS 2)
    target_sources(vitals PRIVATE quiet_output.c)
    target_link_options(vitals PRIVATE -Wl,--wrap=printf -Wl,--wrap=puts)
endif()
target_include_directories(vitals PRIVATE . ../provider)
target_compile_features(vitals PRIVATE c_std_11)
target_compile_definitions(vitals PRIVATE VITALS_DEBUG=${VITALS_DEBUG}
    VITALS_LOG_PREFIX="vitals_browser")
target_compile_options(vitals PRIVATE -std=gnu11 -Wall -Wextra -Werror -Wshadow
    -Wstrict-prototypes -ffunction-sections -fdata-sections -O2)
target_link_options(vitals PRIVATE -nostdlib -Wl,--gc-sections
    -Wl,--undefined=module_start -Wl,--undefined=module_stop)
target_link_libraries(vitals PRIVATE vitals_core mbedtls mbedx509 mbedcrypto gcc
    SceLibc_stub SceNet_stub SceRtc_stub SceLibKernel_stub SceIofilemgr_stub
    SceKernelModulemgr_stub SceKernelThreadMgr_stub SceSysmem_stub taihen_stub)
# The module header carries the release version from ../../VERSION
configure_file(vitals.yml.in vitals.yml @ONLY)
vita_create_self(vitals.suprx vitals
    CONFIG ${CMAKE_CURRENT_BINARY_DIR}/vitals.yml UNSAFE)
