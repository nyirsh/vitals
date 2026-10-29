cmake_minimum_required(VERSION 3.16)
project(vitals_ssl_tests C)

# vitals-ssl built for this machine with tests/platform_posix.c, and the real Mbed TLS over
# tls13-vita's Vita stand-ins, called as Sony's libhttp calls it against tests/server.py
if(NOT DEFINED ENV{VITASDK})
    message(FATAL_ERROR "VITASDK must be set: the tests use its <psp2/libssl.h>")
endif()
set(ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(TLS13_DIR ${ROOT}/../tls13-vita)
include(${ROOT}/../dependencies.cmake)
vitals_download("${VITALS_MBEDTLS_URL}" "${VITALS_MBEDTLS_SHA256}" VITALS_MBEDTLS_ARCHIVE)
add_subdirectory(${TLS13_DIR}/crypto crypto)

find_package(Threads REQUIRED)
find_package(Python3 COMPONENTS Interpreter REQUIRED)
enable_testing()

# Only the SDK's libssl header, so its other headers don't replace the stand-ins
file(COPY $ENV{VITASDK}/arm-vita-eabi/include/psp2/libssl.h DESTINATION ${CMAKE_BINARY_DIR}/sdk/psp2)
file(COPY $ENV{VITASDK}/arm-vita-eabi/include/vitasdk/build_utils.h DESTINATION ${CMAKE_BINARY_DIR}/sdk/vitasdk)

add_library(vitals_vita_mock STATIC ${TLS13_DIR}/tests/transport/vita_mock.c)
target_include_directories(vitals_vita_mock PUBLIC ${TLS13_DIR}/tests/transport/include)
target_link_libraries(vitals_vita_mock PUBLIC Threads::Threads)

add_executable(vitals_ssl_tests
    ${ROOT}/src/core.c
    ${ROOT}/src/connection.c
    ${ROOT}/src/ssl.c
    ${ROOT}/src/internal.c
    ${TLS13_DIR}/provider/platform_shims.c
    ${TLS13_DIR}/provider/ca_index.c
    platform_posix.c
    test_main.c
)
target_include_directories(vitals_ssl_tests BEFORE PRIVATE ${CMAKE_BINARY_DIR}/sdk)
# With the debug log compiled in, so its lines run too
target_compile_definitions(vitals_ssl_tests PRIVATE VITALS_DEBUG=1 VITALS_LOG_PREFIX="vitals-ssl")
target_include_directories(vitals_ssl_tests PRIVATE ${ROOT}/src ${TLS13_DIR}/provider ${TLS13_DIR}/include)
target_compile_options(vitals_ssl_tests PRIVATE -std=gnu11 -g -Wall -Wextra -Werror
    -fsanitize=address,undefined -fno-omit-frame-pointer)
target_link_options(vitals_ssl_tests PRIVATE -fsanitize=address,undefined)
target_link_libraries(vitals_ssl_tests PRIVATE mbedtls mbedx509 mbedcrypto vitals_vita_mock Threads::Threads)

add_test(NAME vitals_ssl
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.py $<TARGET_FILE:vitals_ssl_tests>)
set_tests_properties(vitals_ssl PROPERTIES TIMEOUT 120)
