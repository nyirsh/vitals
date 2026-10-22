# Pinned third-party sources, downloaded into build/deps on first use
# To update one, change its version and SHA-256 together; the SHA-256 is that of the release
# archive named below (for example `sha256sum mbedtls-4.2.0.tar.bz2`)

# Mbed TLS (bundles TF-PSA-Crypto), used by the TLS providers
set(VITALS_MBEDTLS_VERSION "4.2.0")
set(VITALS_MBEDTLS_SHA256 "2bed9d713b4668f76553b097e72b8aa30bc8f112a940d7ae228d524bbde6ffea")
set(VITALS_MBEDTLS_URL
    "https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-${VITALS_MBEDTLS_VERSION}/mbedtls-${VITALS_MBEDTLS_VERSION}.tar.bz2")

# curl, used by the installer to download the latest Mozilla CA bundle
set(VITALS_CURL_VERSION "8.17.0")
set(VITALS_CURL_SHA256 "e8e74cdeefe5fb78b3ae6e90cd542babf788fa9480029cfcee6fd9ced42b7910")
set(VITALS_CURL_URL "https://curl.se/download/curl-${VITALS_CURL_VERSION}.tar.gz")

set(VITALS_DEPS_DIR "${CMAKE_CURRENT_LIST_DIR}/build/deps")

# Downloads <url> into build/deps (skipped when the cached copy already matches <sha256>)
# and stores the local path in <out_var>
# A failed or mismatching download stops the build
function(vitals_download url sha256 out_var)
    get_filename_component(name "${url}" NAME)
    set(path "${VITALS_DEPS_DIR}/${name}")
    file(DOWNLOAD "${url}" "${path}" EXPECTED_HASH SHA256=${sha256} STATUS status)
    list(GET status 0 code)
    if(NOT code EQUAL 0)
        file(REMOVE "${path}")
        message(FATAL_ERROR "Download of ${url} failed: ${status}")
    endif()
    set(${out_var} "${path}" PARENT_SCOPE)
endfunction()
