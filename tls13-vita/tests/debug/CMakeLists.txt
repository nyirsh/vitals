# Every log line compiles: the provider and browser sources are built with debug output on (levels
# 1 and 2), against stand-ins declared as in VitaSDK; a broken or mismatched log line fails the
# test build. Only compiled, never run
set(debug_sources
    ../../provider/ca_file.c ../../provider/ca_index.c ../../provider/cert_hooks.c
    ../../provider/host_redirect.c ../../provider/http_trace.c ../../provider/platform_shims.c
    ../../provider/private_mapping.c ../../provider/provider.c ../../provider/transport.c
    ../../provider/trust_store.c ../../provider/vita_net.c
    ../../browser/backend.c ../../browser/config.c ../../browser/module.c ../../browser/webkit_callback.c)
foreach(level 1 2)
    add_library(vitals_debug_${level}_build OBJECT ${debug_sources})
    target_include_directories(vitals_debug_${level}_build PRIVATE ../../provider ../../browser)
    target_link_libraries(vitals_debug_${level}_build PRIVATE vitals_core mbedtls vitals_vita_mock)
    target_compile_definitions(vitals_debug_${level}_build PRIVATE VITALS_DEBUG=${level}
        VITALS_LOG_PREFIX="vitals_test" VITALS_HTTP_HEAP_BYTES=131072u
        VITALS_DEFAULT_CA_PATH="vs0:/data/external/cert/CA_LIST.cer")
    target_compile_options(vitals_debug_${level}_build PRIVATE -Wall -Wextra -Werror)

    # The runtime has its own host stand-ins
    add_library(vitals_debug_${level}_runtime OBJECT ../../provider/user_runtime.c)
    target_include_directories(vitals_debug_${level}_runtime PRIVATE ../../provider ../runtime)
    target_compile_definitions(vitals_debug_${level}_runtime PRIVATE VITALS_DEBUG=${level}
        VITALS_RUNTIME_HOST_TEST=1 VITALS_HTTP_HEAP_BYTES=131072u)
    target_compile_options(vitals_debug_${level}_runtime PRIVATE -Wall -Wextra -Werror -fno-builtin)
endforeach()
