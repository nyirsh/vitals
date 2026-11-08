cmake_minimum_required(VERSION 3.16)
project(vitals_ssl_tests C)

# vitals-ssl built for this machine with tests/platform_posix.c, and the real Mbed TLS over
# the Vita stand-ins (../../common/tests), called as Sony's libhttp calls it against
# shared/tests/server.py; then its crypto platform and its certificate index's exact trust
if(NOT DEFINED ENV{VITASDK})
    message(FATAL_ERROR "VITASDK must be set: the tests use its <psp2/libssl.h>")
endif()
set(ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(VITALS_COMMON_DIR ${ROOT}/../common)
set(SHARED_DIR ${ROOT}/../../shared)
include(${ROOT}/../dependencies.cmake)
vitals_download("${VITALS_MBEDTLS_URL}" "${VITALS_MBEDTLS_SHA256}" VITALS_MBEDTLS_ARCHIVE)
add_subdirectory(${ROOT}/crypto crypto)

find_package(Threads REQUIRED)
find_package(Python3 COMPONENTS Interpreter REQUIRED)
enable_testing()

# Only the SDK's libssl header, so its other headers don't replace the stand-ins
file(COPY $ENV{VITASDK}/arm-vita-eabi/include/psp2/libssl.h DESTINATION ${CMAKE_BINARY_DIR}/sdk/psp2)
file(COPY $ENV{VITASDK}/arm-vita-eabi/include/vitasdk/build_utils.h DESTINATION ${CMAKE_BINARY_DIR}/sdk/vitasdk)

add_library(vitals_vita_mock STATIC ${VITALS_COMMON_DIR}/tests/vita_mock.c)
target_include_directories(vitals_vita_mock PUBLIC ${VITALS_COMMON_DIR}/tests/include)
target_link_libraries(vitals_vita_mock PUBLIC Threads::Threads)

add_executable(vitals_ssl_tests
    ${ROOT}/src/core.c
    ${ROOT}/src/connection.c
    ${ROOT}/src/certificate.c
    ${ROOT}/src/vitals.c
    ${ROOT}/src/ssl.c
    ${ROOT}/src/internal.c
    ${ROOT}/src/platform_shims.c
    ${ROOT}/src/ca_index.c
    ${SHARED_DIR}/src/ca_scan.c
    platform_posix.c
    test_main.c
)
target_include_directories(vitals_ssl_tests BEFORE PRIVATE ${CMAKE_BINARY_DIR}/sdk)
# With the debug log compiled in, so its lines run too
target_compile_definitions(vitals_ssl_tests PRIVATE VITALS_DEBUG=1 VITALS_LOG_PREFIX="vitals-ssl")
target_include_directories(vitals_ssl_tests PRIVATE ${ROOT}/src ${ROOT}/include ${VITALS_COMMON_DIR}/runtime
    ${VITALS_COMMON_DIR}/include ${SHARED_DIR}/include)
target_compile_options(vitals_ssl_tests PRIVATE -std=gnu11 -g -Wall -Wextra -Werror
    -fsanitize=address,undefined -fno-omit-frame-pointer)
target_link_options(vitals_ssl_tests PRIVATE -fsanitize=address,undefined)
target_link_libraries(vitals_ssl_tests PRIVATE mbedtls mbedx509 tfpsacrypto vitals_vita_mock Threads::Threads)

add_test(NAME vitals_ssl
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.py $<TARGET_FILE:vitals_ssl_tests>)
set_tests_properties(vitals_ssl PROPERTIES TIMEOUT 120)

# The crypto platform (src/platform_shims.c) on the stand-ins: entropy, time and locking
add_executable(vitals_crypto_platform_tests test_crypto_platform.c ${ROOT}/src/platform_shims.c)
target_include_directories(vitals_crypto_platform_tests PRIVATE ${ROOT}/src ${VITALS_COMMON_DIR}/runtime)
target_link_libraries(vitals_crypto_platform_tests PRIVATE mbedtls vitals_vita_mock)
target_compile_options(vitals_crypto_platform_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME vitals_crypto_platform COMMAND vitals_crypto_platform_tests)
set_tests_properties(vitals_crypto_platform PROPERTIES TIMEOUT 20)

# The certificate index's exact trust of self-signed certificates, against a local server
add_executable(vitals_exact_trust_tests test_exact_trust.c ${ROOT}/src/ca_index.c ${ROOT}/src/platform_shims.c
    ${SHARED_DIR}/src/ca_scan.c)
target_include_directories(vitals_exact_trust_tests PRIVATE ${ROOT}/src ${VITALS_COMMON_DIR}/runtime
    ${VITALS_COMMON_DIR}/include ${SHARED_DIR}/include)
target_link_libraries(vitals_exact_trust_tests PRIVATE mbedtls vitals_vita_mock)
target_compile_options(vitals_exact_trust_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME vitals_exact_trust
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/run_exact_trust.py $<TARGET_FILE:vitals_exact_trust_tests>)
set_tests_properties(vitals_exact_trust PROPERTIES TIMEOUT 120)
