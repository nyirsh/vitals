# Third-party notices

These notices cover the third-party software and data in vitals. The app's VPK includes this file and the [licenses](licenses/) folder. The exact versions and SHA-256 hashes of Mbed TLS and curl are pinned in [dependencies.cmake](dependencies.cmake).

## Mbed TLS

`libssl.suprx` (vitals-ssl) statically links `libmbedtls.a`, `libmbedx509.a` and `libtfpsacrypto.a`, built from the official Mbed TLS 4.2 source release (currently 4.2.0, which bundles TF-PSA-Crypto), downloaded from the `Mbed-TLS/mbedtls` GitHub releases. vitals modifies it with four patches in [tls13-vita/crypto](tls13-vita/crypto/):

- [rsa-client.patch](tls13-vita/crypto/rsa-client.patch) puts back the client side of TLS 1.2's RSA key exchange and its four AES-CBC suites, which Mbed TLS removed in 4.0 and some of Sony's servers still use. It comes from devnoname120's [tls_fixer](https://github.com/devnoname120/vita_tls_fixer) (v0.2.2, `tls13/crypto/patches/rsa-client-4.2.patch`), trimmed
- [offer-unknown-ciphersuites.patch](tls13-vita/crypto/offer-unknown-ciphersuites.patch) lets a ClientHello list cipher suites Mbed TLS doesn't implement
- [certificate-request-callback.patch](tls13-vita/crypto/certificate-request-callback.patch) lets a client pick its certificate from a server's certificate request
- [pkcs8-rsa-public-key.patch](tls13-vita/crypto/pkcs8-rsa-public-key.patch) gives an RSA private key read from PKCS#8 its public half, as the other key formats have, so it can be matched to its certificate

Each change is marked in the code. vitals also adds configuration headers and a Vita platform adapter. This distribution selects the Apache License 2.0 offered by both projects; the license texts are `licenses/Mbed-TLS-LICENSE.txt` and `licenses/TF-PSA-Crypto-LICENSE.txt`.

The Mbed TLS source release also bundles optional third-party code (Project Everest/HACL\* Curve25519, p256-m and the mldsa-native ML-DSA implementation). vitals' configuration does not enable any of it, so none of that code is in the modules.

Mbed TLS is an independent work; no endorsement by its authors is implied.

## curl

The app statically links libcurl (currently 8.17.0), built from the unmodified official release archive from `curl.se` under the curl license (`licenses/curl-LICENSE.txt`). Source: <https://github.com/curl/curl/releases>. The Vita build disables unused protocols, default CA discovery and the console UI.

## OpenSSL, zlib and Zstandard

`libhttp.suprx` (vitals-http) statically links zlib from VitaSDK, for gzip bodies. libcurl uses OpenSSL, zlib and Zstandard from VitaSDK (OpenSSL 1.1.1t, zlib 1.3.2 and Zstandard 1.5.7 in the validated build). Their license texts are `licenses/OpenSSL-LICENSE.txt`, `licenses/zlib-LICENSE.txt` and `licenses/zstd-LICENSE.txt`; Zstandard's BSD option is selected. This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit (<https://www.openssl.org/>). This product includes cryptographic software written by Eric Young (eay@cryptsoft.com).

## Mozilla certificate data

`mozilla-certs.pem` is the curl project's PEM conversion of Mozilla's CA data (Mozilla NSS `certdata.txt`), under the Mozilla Public License 2.0 (`licenses/Mozilla-MPL-2.0.txt`). Its upstream header is kept unchanged. Source: <https://curl.se/ca/cacert.pem>. The snapshot's date, URL and SHA-256 are recorded in `certificate-sources.json`.

## Sony material

The Sony certificate bundle (`sony-certs.pem`) and the Sony system module shipped in `vitals-app/assets/` (`compat.suprx`) are Sony material, and so is `vitals-app/assets/lssl.suprx`, Sony's libssl, kept in the repository as the reference vitals-ssl was written from and no longer shipped. They are not covered by any of the licenses above. When merging certificates, the app keeps the selected certificates and removes duplicates; it does not import the console's existing trust store.
