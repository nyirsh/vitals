# Every log line compiles: the browser module's sources are built with debug output on (levels
# 1 and 2), against stand-ins declared as in VitaSDK; a broken or mismatched log line fails the
# test build. Only compiled, never run
set(debug_sources
    ../../../vitals-ssl/src/ca_index.c ../../../vitals-ssl/src/platform_shims.c ../../../../shared/src/ca_scan.c
    ../../backend.c ../../config.c ../../module.c ../../webkit_callback.c)
foreach(level 1 2)
    add_library(vitals_debug_${level}_build OBJECT ${debug_sources})
    target_include_directories(vitals_debug_${level}_build PRIVATE ../../../vitals-ssl/src ../../../common/runtime ../.. ../../../../shared/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../vitals-ssl/include)
    target_link_libraries(vitals_debug_${level}_build PRIVATE vitals_core mbedtls vitals_vita_mock)
    target_compile_definitions(vitals_debug_${level}_build PRIVATE VITALS_DEBUG=${level}
        VITALS_LOG_NAME="vitals_test" VITALS_LOG_CONSOLE_ONLY VITALS_HTTP_HEAP_BYTES=131072u)
    target_compile_options(vitals_debug_${level}_build PRIVATE -Wall -Wextra -Werror)

    # The runtime has its own host stand-ins
    add_library(vitals_debug_${level}_runtime OBJECT ../../../common/runtime/user_runtime.c)
    target_include_directories(vitals_debug_${level}_runtime PRIVATE ../../../common/runtime ../../../common/tests/runtime)
    target_compile_definitions(vitals_debug_${level}_runtime PRIVATE VITALS_DEBUG=${level}
        VITALS_RUNTIME_HOST_TEST=1 VITALS_HTTP_HEAP_BYTES=131072u)
    target_compile_options(vitals_debug_${level}_runtime PRIVATE -Wall -Wextra -Werror -fno-builtin)
endforeach()
