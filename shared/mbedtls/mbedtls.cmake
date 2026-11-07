# Mbed TLS 4.2 (with TF-PSA-Crypto), the TLS of both consoles' libssl, pinned once for both (each
# console's dependencies.cmake includes this). To update it, change the version and SHA-256 together;
# the SHA-256 is that of the release archive below (for example `sha256sum mbedtls-4.2.0.tar.bz2`).
# It's patched back to the client side of TLS 1.2's RSA key exchange, which 4.0 removed and the
# consoles' own TLS offers, as some of Sony's servers (PSN sign-in, the store) still expect
# (rsa-client.patch, next to this file)
set(VITALS_MBEDTLS_VERSION "4.2.0")
set(VITALS_MBEDTLS_SHA256 "2bed9d713b4668f76553b097e72b8aa30bc8f112a940d7ae228d524bbde6ffea")
set(VITALS_MBEDTLS_URL
    "https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-${VITALS_MBEDTLS_VERSION}/mbedtls-${VITALS_MBEDTLS_VERSION}.tar.bz2")
