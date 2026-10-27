# Mbed TLS 3.6, for vitals-http and the browser provider; VITALS_MBEDTLS_ARCHIVE comes from the
# including CMakeLists.txt (see ../../dependencies.cmake)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(GEN_FILES OFF CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)
set(MBEDTLS_USER_CONFIG_FILE "${CMAKE_CURRENT_LIST_DIR}/mbedtls_user_config.h" CACHE FILEPATH "" FORCE)

include(FetchContent)
include_directories(BEFORE "${CMAKE_CURRENT_LIST_DIR}")
if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
endif()
# Patched to offer, in a ClientHello, suites it doesn't implement (offer-unknown-ciphersuites.patch)
FetchContent_Declare(vitals_mbedtls
    URL "${VITALS_MBEDTLS_ARCHIVE}"
    URL_HASH SHA256=${VITALS_MBEDTLS_SHA256}
    PATCH_COMMAND ${CMAKE_COMMAND} -DPATCH_FILE=${CMAKE_CURRENT_LIST_DIR}/offer-unknown-ciphersuites.patch
        -P ${CMAKE_CURRENT_LIST_DIR}/apply_patch.cmake
)
FetchContent_MakeAvailable(vitals_mbedtls)
# The Vita headers declare inet_pton without a linked implementation; Mbed TLS has its own parser
target_compile_definitions(mbedx509 PRIVATE MBEDTLS_TEST_SW_INET_PTON)
foreach(target mbedtls mbedx509 mbedcrypto)
    target_include_directories(${target} PUBLIC "${CMAKE_CURRENT_LIST_DIR}")
    target_compile_options(${target} PRIVATE -ffunction-sections -fdata-sections -Os)
endforeach()
