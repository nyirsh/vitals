# curl for the app's downloads (the Mozilla CA bundle, the new-release check), on Mbed TLS 4.2 as
# vitals' libssl builds it (../../vitals-ssl/crypto, with the app's crypto options, ../crypto): the
# app's own TLS, so the downloads work whatever the console's TLS is. As the Vita's
# vitals-app/curl, which is on OpenSSL; the pin is both consoles' (../../../shared/curl/curl.cmake)
vitals_download("${VITALS_CURL_URL}" "${VITALS_CURL_SHA256}" VITALS_CURL_ARCHIVE)

set(BUILD_CURL_EXE OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(BUILD_LIBCURL_DOCS OFF CACHE BOOL "" FORCE)
set(BUILD_MISC_DOCS OFF CACHE BOOL "" FORCE)
set(ENABLE_CURL_MANUAL OFF CACHE BOOL "" FORCE)
set(CURL_ENABLE_EXPORT_TARGET OFF CACHE BOOL "" FORCE)
set(HTTP_ONLY ON CACHE BOOL "" FORCE)
set(ENABLE_IPV6 OFF CACHE BOOL "" FORCE)
set(ENABLE_UNIX_SOCKETS OFF CACHE BOOL "" FORCE)
set(ENABLE_THREADED_RESOLVER OFF CACHE BOOL "" FORCE)
set(CURL_DISABLE_SOCKETPAIR ON CACHE BOOL "" FORCE)
set(CURL_USE_PKGCONFIG OFF CACHE BOOL "" FORCE)
set(CURL_USE_LIBPSL OFF CACHE BOOL "" FORCE)
set(CURL_USE_LIBSSH2 OFF CACHE BOOL "" FORCE)
set(CURL_ZLIB OFF CACHE STRING "" FORCE)
set(CURL_BROTLI OFF CACHE STRING "" FORCE)
set(CURL_ZSTD OFF CACHE STRING "" FORCE)
set(USE_NGHTTP2 OFF CACHE BOOL "" FORCE)
set(USE_LIBIDN2 OFF CACHE BOOL "" FORCE)
set(CURL_USE_OPENSSL OFF CACHE BOOL "" FORCE)
set(CURL_USE_MBEDTLS ON CACHE BOOL "" FORCE)
set(CURL_CA_BUNDLE "none" CACHE STRING "No default/system CA file" FORCE)
set(CURL_CA_PATH "none" CACHE STRING "No default/system CA directory" FORCE)
set(CURL_CA_FALLBACK OFF CACHE BOOL "" FORCE)
# The PS3's sockets (the SDK's BSD family, librt) have no fcntl: they're made non-blocking with
# setsockopt's SO_NBIO, which curl knows as SO_NONBLOCK (below), and there's no close-on-exec to set
# (curl's fcntl(F_SETFD, FD_CLOEXEC) on a new socket fails with ENOSYS, failing the connection)
set(HAVE_FCNTL 0 CACHE INTERNAL "" FORCE)
set(HAVE_FCNTL_O_NONBLOCK 0 CACHE INTERNAL "" FORCE)
set(HAVE_SETSOCKOPT_SO_NONBLOCK 1 CACHE INTERNAL "" FORCE)
# Nor basename, which the check finds in a header without a definition: curl has its own
set(HAVE_BASENAME 0 CACHE INTERNAL "" FORCE)
# curl's extra warnings fire on Mbed TLS's own headers
set(PICKY_COMPILER OFF CACHE BOOL "" FORCE)
# Mbed TLS is the targets ../../vitals-ssl/crypto made, not an installed copy: their names stand for
# the libraries, and they bring their include folders and options along
include(FetchContent)
FetchContent_GetProperties(vitals_mbedtls)
set(MBEDTLS_INCLUDE_DIR "${vitals_mbedtls_SOURCE_DIR}/include" CACHE PATH "" FORCE)
set(MBEDTLS_LIBRARY mbedtls CACHE STRING "" FORCE)
set(MBEDX509_LIBRARY mbedx509 CACHE STRING "" FORCE)
set(MBEDCRYPTO_LIBRARY tfpsacrypto CACHE STRING "" FORCE)

include(FetchContent)
if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
endif()
FetchContent_Declare(vitals_curl URL "${VITALS_CURL_ARCHIVE}"
    URL_HASH SHA256=${VITALS_CURL_SHA256})
FetchContent_MakeAvailable(vitals_curl)
target_compile_definitions(libcurl_static PRIVATE SO_NONBLOCK=SO_NBIO)
