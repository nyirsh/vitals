cmake_minimum_required(VERSION 3.16)
project(vitals_http_tests C)

# The library, built for this machine with tests/platform_posix.c, and the real Mbed TLS over
# tls13-vita's Vita stand-ins, tested through its API against tests/server.py
if(NOT DEFINED ENV{VITASDK})
    message(FATAL_ERROR "VITASDK must be set: the tests use its <psp2/net/http.h>")
endif()
set(ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(TLS13_DIR ${ROOT}/../tls13-vita)
set(VITALS_SSL_DIR ${ROOT}/../vitals-ssl)
include(${ROOT}/../dependencies.cmake)
vitals_download("${VITALS_MBEDTLS_URL}" "${VITALS_MBEDTLS_SHA256}" VITALS_MBEDTLS_ARCHIVE)
add_subdirectory(${TLS13_DIR}/crypto crypto)

find_package(Threads REQUIRED)
find_package(ZLIB REQUIRED)
find_package(Python3 COMPONENTS Interpreter REQUIRED)
enable_testing()

# Only the SDK's libhttp header, so its other headers don't replace the stand-ins and the system's
file(COPY $ENV{VITASDK}/arm-vita-eabi/include/psp2/net/http.h DESTINATION ${CMAKE_BINARY_DIR}/sdk/psp2/net)
file(COPY $ENV{VITASDK}/arm-vita-eabi/include/psp2/libssl.h DESTINATION ${CMAKE_BINARY_DIR}/sdk/psp2)
file(COPY $ENV{VITASDK}/arm-vita-eabi/include/vitasdk/build_utils.h DESTINATION ${CMAKE_BINARY_DIR}/sdk/vitasdk)

add_library(vitals_vita_mock STATIC ${TLS13_DIR}/tests/transport/vita_mock.c)
target_include_directories(vitals_vita_mock PUBLIC ${TLS13_DIR}/tests/transport/include)
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
    ${ROOT}/src/ssl_platform.c
    ${VITALS_SSL_DIR}/src/core.c
    ${VITALS_SSL_DIR}/src/connection.c
    ${VITALS_SSL_DIR}/src/certificate.c
    ${VITALS_SSL_DIR}/src/vitals.c
    ${TLS13_DIR}/provider/platform_shims.c
    ${TLS13_DIR}/provider/ca_index.c
    ${TLS13_DIR}/src/error_map.c
    ${TLS13_DIR}/src/host_map.c
    ${TLS13_DIR}/src/redirect_list.c
    platform_posix.c
    test_main.c
)
target_include_directories(vitals_http_tests BEFORE PRIVATE ${CMAKE_BINARY_DIR}/sdk)
# With the debug log compiled in, so its lines run too (VH_TEST_LOG=1 shows them)
target_compile_definitions(vitals_http_tests PRIVATE VITALS_DEBUG=1 VITALS_LOG_PREFIX="vitals-http")
target_include_directories(vitals_http_tests PRIVATE ${ROOT}/src ${VITALS_SSL_DIR}/src ${VITALS_SSL_DIR}/include
    ${TLS13_DIR}/provider ${TLS13_DIR}/include)
target_compile_options(vitals_http_tests PRIVATE -std=gnu11 -g -Wall -Wextra -Werror
    -fsanitize=address,undefined -fno-omit-frame-pointer)
target_link_options(vitals_http_tests PRIVATE -fsanitize=address,undefined)
target_link_libraries(vitals_http_tests PRIVATE mbedtls mbedx509 mbedcrypto vitals_vita_mock ZLIB::ZLIB
    Threads::Threads)

add_test(NAME vitals_http
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.py $<TARGET_FILE:vitals_http_tests>)
set_tests_properties(vitals_http PROPERTIES TIMEOUT 180)
