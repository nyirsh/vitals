# Pinned third-party sources, downloaded into build/deps on first use (as the Vita's dependencies.cmake)
# To update one, change its version and SHA-256 together; the SHA-256 is that of the release
# archive named below (for example `sha256sum mbedtls-4.2.0.tar.bz2`)

# Mbed TLS 4.2 (with TF-PSA-Crypto), the TLS of vitals' libssl: pinned for both consoles in
# ../shared/mbedtls/mbedtls.cmake
include("${CMAKE_CURRENT_LIST_DIR}/../shared/mbedtls/mbedtls.cmake")

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
