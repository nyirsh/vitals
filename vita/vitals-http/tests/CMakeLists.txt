cmake_minimum_required(VERSION 3.16)
project(vitals_http_tests C)

# The library, built for this machine with tests/platform_posix.c, and the real Mbed TLS over
# the Vita stand-ins (../../common/tests), tested through its API against tests/server.py
if(NOT DEFINED ENV{VITASDK})
    message(FATAL_ERROR "VITASDK must be set: the tests use its <psp2/net/http.h>")
endif()
set(ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(VITALS_COMMON_DIR ${ROOT}/../common)
set(VITALS_SSL_DIR ${ROOT}/../vitals-ssl)
include(${ROOT}/../dependencies.cmake)
vitals_download("${VITALS_MBEDTLS_URL}" "${VITALS_MBEDTLS_SHA256}" VITALS_MBEDTLS_ARCHIVE)
add_subdirectory(${VITALS_SSL_DIR}/crypto crypto)

find_package(Threads REQUIRED)
find_package(ZLIB REQUIRED)
find_package(Python3 COMPONENTS Interpreter REQUIRED)
enable_testing()

# Only the SDK's libhttp header, so its other headers don't replace the stand-ins and the system's
file(COPY $ENV{VITASDK}/arm-vita-eabi/include/psp2/net/http.h DESTINATION ${CMAKE_BINARY_DIR}/sdk/psp2/net)
file(COPY $ENV{VITASDK}/arm-vita-eabi/include/psp2/libssl.h DESTINATION ${CMAKE_BINARY_DIR}/sdk/psp2)
file(COPY $ENV{VITASDK}/arm-vita-eabi/include/vitasdk/build_utils.h DESTINATION ${CMAKE_BINARY_DIR}/sdk/vitasdk)

add_library(vitals_vita_mock STATIC ${VITALS_COMMON_DIR}/tests/vita_mock.c)
target_include_directories(vitals_vita_mock PUBLIC ${VITALS_COMMON_DIR}/tests/include)
target_link_libraries(vitals_vita_mock PUBLIC Threads::Threads)

add_executable(vitals_http_tests
    ${ROOT}/src/core.c
    ${ROOT}/src/request.c
    ${ROOT}/src/message.c
    ${ROOT}/src/uri.c
    ${ROOT}/src/cookie.c
    ${ROOT}/src/inflate.c
    ${ROOT}/src/async.c
    ${ROOT}/src/private.c
    ${ROOT}/src/redirect.c
    ${ROOT}/src/useragent.c
    ${ROOT}/src/tls.c
    ${ROOT}/src/tls_sony.c
    ${ROOT}/src/md5.c
    ssl_platform.c
    ${VITALS_SSL_DIR}/src/core.c
    ${VITALS_SSL_DIR}/src/connection.c
    ${VITALS_SSL_DIR}/src/certificate.c
    ${VITALS_SSL_DIR}/src/vitals.c
    ${VITALS_SSL_DIR}/src/platform_shims.c
    ${VITALS_SSL_DIR}/src/ca_index.c
    ${ROOT}/../../shared/src/ca_scan.c
    ${VITALS_COMMON_DIR}/src/error_map.c
    ${ROOT}/../../shared/src/host_map.c
    ${ROOT}/../../shared/src/redirect_list.c
    platform_posix.c
    test_main.c
)
target_include_directories(vitals_http_tests BEFORE PRIVATE ${CMAKE_BINARY_DIR}/sdk)
# With the debug log compiled in, so its lines run too (VH_TEST_LOG=1 shows them)
target_compile_definitions(vitals_http_tests PRIVATE VITALS_DEBUG=1 VITALS_LOG_NAME="vitals-http" VITALS_LOG_CONSOLE_ONLY)
target_include_directories(vitals_http_tests PRIVATE ${ROOT}/src ${ROOT}/include ${VITALS_SSL_DIR}/src ${VITALS_SSL_DIR}/include
    ${VITALS_COMMON_DIR}/runtime ${VITALS_COMMON_DIR}/include ${ROOT}/../../shared/include)
target_compile_options(vitals_http_tests PRIVATE -std=gnu11 -g -Wall -Wextra -Werror
    -fsanitize=address,undefined -fno-omit-frame-pointer)
target_link_options(vitals_http_tests PRIVATE -fsanitize=address,undefined)
target_link_libraries(vitals_http_tests PRIVATE mbedtls mbedx509 tfpsacrypto vitals_vita_mock ZLIB::ZLIB
    Threads::Threads)

add_test(NAME vitals_http
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.py $<TARGET_FILE:vitals_http_tests>)
set_tests_properties(vitals_http PROPERTIES TIMEOUT 180)
# The same on the path vitals-http takes when the process's libssl is Sony's (the Options' tls.off,
# src/tls_sony.c): here on vitals-ssl's own versions of the functions Sony's libssl exports
add_test(NAME vitals_http_on_sony_libssl
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.py $<TARGET_FILE:vitals_http_tests>)
set_tests_properties(vitals_http_on_sony_libssl PROPERTIES TIMEOUT 180 ENVIRONMENT VH_TEST_SONY_SSL=1)
