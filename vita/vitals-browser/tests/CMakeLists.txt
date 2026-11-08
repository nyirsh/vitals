cmake_minimum_required(VERSION 3.16)
# Host tests of the browser provider: its output, settings, module checks and, over loopback, its
# real TLS handshakes on vitals-ssl and its memory use; then every log line compiled at debug levels
# 1 and 2 (debug/). Built for this machine with AddressSanitizer and UBSan; `make test` runs them
project(vitals_browser_tests C)

# A few tests place memory at fixed low addresses (the Vita's 32-bit pointers), which only Linux
# allows; elsewhere they are left out
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(VITALS_FIXED_ADDRESS_TESTS ON)
else()
    set(VITALS_FIXED_ADDRESS_TESTS OFF)
endif()
option(VITALS_ENABLE_SANITIZERS "Build the tests with AddressSanitizer and UBSan" ON)
if(VITALS_ENABLE_SANITIZERS)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()
enable_testing()

include(${CMAKE_CURRENT_SOURCE_DIR}/../../common/core.cmake)
# The real Mbed TLS, as vitals-ssl builds it, over the Vita stand-ins (../../common/tests)
include(${CMAKE_CURRENT_SOURCE_DIR}/../../dependencies.cmake)
vitals_download("${VITALS_MBEDTLS_URL}" "${VITALS_MBEDTLS_SHA256}" VITALS_MBEDTLS_ARCHIVE)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../vitals-ssl/crypto crypto)
find_package(Threads REQUIRED)
add_library(vitals_vita_mock STATIC ../../common/tests/vita_mock.c)
target_include_directories(vitals_vita_mock PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../common/tests/include)
target_link_libraries(vitals_vita_mock PUBLIC Threads::Threads)

add_subdirectory(debug)

add_executable(vitals_browser_quiet_output_tests test_quiet_output.c ../quiet_output.c)
target_compile_options(vitals_browser_quiet_output_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME vitals_browser_quiet_output COMMAND vitals_browser_quiet_output_tests)

# The other browser tests place memory at fixed low addresses, as the Vita's 32-bit pointers
# need, which only Linux allows
if(NOT VITALS_FIXED_ADDRESS_TESTS)
    return()
endif()

add_executable(vitals_browser_config_tests test_config.c ../config.c)
target_link_libraries(vitals_browser_config_tests PRIVATE vitals_core)
target_include_directories(vitals_browser_config_tests PRIVATE ../../common/runtime)
target_compile_options(vitals_browser_config_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME vitals_browser_config COMMAND vitals_browser_config_tests)

# The backend's TLS is vitals-ssl, built in here with its host platform; it needs VitaSDK's
# <psp2/libssl.h>, as vitals-ssl's own tests do
if(NOT DEFINED ENV{VITASDK})
    message(STATUS "VITASDK is not set: the browser backend tests are left out")
else()
set(VITALS_SSL_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../../vitals-ssl)
file(COPY $ENV{VITASDK}/arm-vita-eabi/include/psp2/libssl.h DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/sdk/psp2)
file(COPY $ENV{VITASDK}/arm-vita-eabi/include/vitasdk/build_utils.h DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/sdk/vitasdk)
add_library(vitals_ssl_host STATIC
    ${VITALS_SSL_ROOT}/src/core.c
    ${VITALS_SSL_ROOT}/src/connection.c
    ${VITALS_SSL_ROOT}/src/certificate.c
    ${VITALS_SSL_ROOT}/src/vitals.c
    ${VITALS_SSL_ROOT}/src/ssl.c
    ${VITALS_SSL_ROOT}/src/internal.c
    ${VITALS_SSL_ROOT}/tests/platform_posix.c
    ${VITALS_SSL_ROOT}/src/platform_shims.c
    ${VITALS_SSL_ROOT}/src/ca_index.c
    ../../../shared/src/ca_scan.c)
target_include_directories(vitals_ssl_host BEFORE PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/sdk)
target_include_directories(vitals_ssl_host PRIVATE ${VITALS_SSL_ROOT}/src ../../common/runtime ../../../shared/include
    PUBLIC ${VITALS_SSL_ROOT}/include)
target_compile_definitions(vitals_ssl_host PRIVATE VITALS_DEBUG=0 VITALS_LOG_PREFIX="vitals-ssl")
target_compile_options(vitals_ssl_host PRIVATE -std=gnu11 -fno-pie)
target_link_libraries(vitals_ssl_host PUBLIC vitals_core mbedtls mbedx509 tfpsacrypto vitals_vita_mock)

add_executable(vitals_browser_backend_tests test_backend.c ../backend.c ../config.c)
target_include_directories(vitals_browser_backend_tests PRIVATE .. ../../common/runtime)
target_link_libraries(vitals_browser_backend_tests PRIVATE vitals_ssl_host)
target_compile_options(vitals_browser_backend_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG -fno-pie)
target_link_options(vitals_browser_backend_tests PRIVATE -no-pie)
find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_test(NAME vitals_browser_loopback COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/run_browser_loopback.py" $<TARGET_FILE:vitals_browser_backend_tests>)
set_tests_properties(vitals_browser_loopback PROPERTIES TIMEOUT 120)

add_executable(vitals_browser_memory_tests test_backend.c memory_tracker.c ../backend.c
    ../config.c)
target_include_directories(vitals_browser_memory_tests PRIVATE .. ../../common/runtime)
target_link_libraries(vitals_browser_memory_tests PRIVATE vitals_ssl_host)
target_compile_definitions(vitals_browser_memory_tests PRIVATE
    VITALS_BROWSER_MEMORY_TEST=1)
target_compile_options(vitals_browser_memory_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG -fno-pie)
target_link_options(vitals_browser_memory_tests PRIVATE -no-pie -Wl,--wrap=malloc -Wl,--wrap=calloc
    -Wl,--wrap=realloc -Wl,--wrap=free)
add_test(NAME vitals_browser_memory COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/run_browser_loopback.py" $<TARGET_FILE:vitals_browser_memory_tests>
    --scenario memory-full-ca)
set_tests_properties(vitals_browser_memory PROPERTIES TIMEOUT 120)

add_executable(vitals_browser_lazy_ca_tests test_lazy_ca.c ../backend.c ../config.c)
target_include_directories(vitals_browser_lazy_ca_tests PRIVATE .. ../../common/runtime)
target_link_libraries(vitals_browser_lazy_ca_tests PRIVATE vitals_ssl_host)
target_compile_options(vitals_browser_lazy_ca_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG -fno-pie)
target_link_options(vitals_browser_lazy_ca_tests PRIVATE -no-pie -Wl,--wrap=vitals_ca_read)
foreach(scenario IN ITEMS init legacy failure)
    add_test(NAME vitals_browser_lazy_ca_${scenario} COMMAND vitals_browser_lazy_ca_tests ${scenario})
endforeach()
endif()

add_executable(vitals_browser_module_tests test_module.c ../module.c
    ../webkit_callback.c)
target_include_directories(vitals_browser_module_tests PRIVATE .. ../../common/runtime ../../common/tests/include)
target_link_libraries(vitals_browser_module_tests PRIVATE vitals_core)
target_compile_definitions(vitals_browser_module_tests PRIVATE VITALS_HOST_MODULE_TEST=1)
target_compile_options(vitals_browser_module_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
foreach(scenario valid bad-args bad-id bad-name bad-size bad-site-0 bad-site-1 bad-site-2 bad-site-3 bad-site-4 bad-site-5 hook-0 hook-1 hook-2 hook-3
    bad-buffer bad-arg-size bad-version bad-reserved bad-negative-id bad-address bad-text-memsz bad-data-filesz bad-data-memsz init-fail)
    add_test(NAME vitals_browser_module_${scenario} COMMAND vitals_browser_module_tests ${scenario})
endforeach()
