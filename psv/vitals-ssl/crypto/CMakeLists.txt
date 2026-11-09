# Mbed TLS 4.2 and TF-PSA-Crypto, for vitals-ssl; VITALS_MBEDTLS_ARCHIVE comes from the including
# CMakeLists.txt (see ../../dependencies.cmake)
# The patches, their applier and the TLS options are both consoles' (../../../shared/mbedtls); the
# crypto options and mutexes, here, are this console's
set(VITALS_SHARED_MBEDTLS "${CMAKE_CURRENT_LIST_DIR}/../../../shared/mbedtls")
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(GEN_FILES OFF CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)
set(MBEDTLS_USER_CONFIG_FILE "${VITALS_SHARED_MBEDTLS}/mbedtls_user_config.h" CACHE FILEPATH "" FORCE)
# This folder's crypto options, or the including build's VITALS_PSA_USER_CONFIG (the host tests')
if(NOT VITALS_PSA_USER_CONFIG)
    set(VITALS_PSA_USER_CONFIG "${CMAKE_CURRENT_LIST_DIR}/psa_user_config.h")
endif()
set(TF_PSA_CRYPTO_USER_CONFIG_FILE "${VITALS_PSA_USER_CONFIG}" CACHE FILEPATH "" FORCE)

include(FetchContent)
include_directories(BEFORE "${CMAKE_CURRENT_LIST_DIR}")
if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
endif()
# Patched back to TLS 1.2's RSA key exchange, client side (rsa-client.patch, from devnoname120's
# tls_fixer), to offer, in a ClientHello, suites it doesn't implement
# (offer-unknown-ciphersuites.patch), and to let a client pick its certificate from a server's
# certificate request (certificate-request-callback.patch); and so that a PKCS#8 RSA key has its
# public half, as its certificate check needs (pkcs8-rsa-public-key.patch)
FetchContent_Declare(vitals_mbedtls
    URL "${VITALS_MBEDTLS_ARCHIVE}"
    URL_HASH SHA256=${VITALS_MBEDTLS_SHA256}
    PATCH_COMMAND ${CMAKE_COMMAND} -DPATCH_FILE=${VITALS_SHARED_MBEDTLS}/rsa-client.patch
        -DPATCH_MARKER=ssl_write_encrypted_pms
        -DPATCH_SOURCE=library/ssl_tls12_client.c
        -P ${VITALS_SHARED_MBEDTLS}/apply_patch.cmake
    COMMAND ${CMAKE_COMMAND} -DPATCH_FILE=${VITALS_SHARED_MBEDTLS}/offer-unknown-ciphersuites.patch
        -DPATCH_MARKER=mbedtls_ssl_conf_offer_unknown_ciphersuites
        -P ${VITALS_SHARED_MBEDTLS}/apply_patch.cmake
    COMMAND ${CMAKE_COMMAND} -DPATCH_FILE=${VITALS_SHARED_MBEDTLS}/certificate-request-callback.patch
        -DPATCH_MARKER=mbedtls_ssl_conf_cert_request_cb
        -P ${VITALS_SHARED_MBEDTLS}/apply_patch.cmake
    COMMAND ${CMAKE_COMMAND} -DPATCH_FILE=${VITALS_SHARED_MBEDTLS}/pkcs8-rsa-public-key.patch
        "-DPATCH_MARKER=vitals: the public half too"
        -DPATCH_SOURCE=tf-psa-crypto/extras/pkparse.c
        -P ${VITALS_SHARED_MBEDTLS}/apply_patch.cmake
)
FetchContent_MakeAvailable(vitals_mbedtls)
# The Vita headers declare inet_pton without a linked implementation; Mbed TLS has its own parser
target_compile_definitions(mbedx509 PRIVATE MBEDTLS_TEST_SW_INET_PTON)
foreach(target mbedtls mbedx509 tfpsacrypto)
    target_include_directories(${target} PUBLIC "${CMAKE_CURRENT_LIST_DIR}")
    target_compile_options(${target} PRIVATE -ffunction-sections -fdata-sections -Os)
endforeach()
