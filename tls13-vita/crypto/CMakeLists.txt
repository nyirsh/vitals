# VITALS_MBEDTLS_ARCHIVE comes from tls13-vita/CMakeLists.txt (see dependencies.cmake)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(GEN_FILES OFF CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)
set(MBEDTLS_USER_CONFIG_FILE "${CMAKE_CURRENT_LIST_DIR}/mbedtls_user_config.h" CACHE FILEPATH "" FORCE)
set(TF_PSA_CRYPTO_USER_CONFIG_FILE "${CMAKE_CURRENT_LIST_DIR}/psa_user_config.h" CACHE FILEPATH "" FORCE)

include(FetchContent)
include_directories(BEFORE "${CMAKE_CURRENT_LIST_DIR}")
if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
endif()
FetchContent_Declare(vitals_mbedtls
    URL "${VITALS_MBEDTLS_ARCHIVE}"
    URL_HASH SHA256=${VITALS_MBEDTLS_SHA256}
)
FetchContent_MakeAvailable(vitals_mbedtls)
# The Vita headers declare inet_pton without a compatible linked implementation
# Upstream also uses this selector on platforms requiring its internal IP parser
target_compile_definitions(mbedx509 PRIVATE MBEDTLS_TEST_SW_INET_PTON)
foreach(target mbedtls mbedx509 tfpsacrypto)
    target_include_directories(${target} PUBLIC "${CMAKE_CURRENT_LIST_DIR}")
    target_compile_options(${target} PRIVATE -ffunction-sections -fdata-sections -Os)
endforeach()
