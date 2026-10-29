# Third-party notices

These notices cover the third-party software and data in vitals. The app's VPK includes this file and the [licenses](licenses/) folder. The exact versions and SHA-256 hashes of Mbed TLS and curl are pinned in [dependencies.cmake](dependencies.cmake).

## Mbed TLS

`libhttp.suprx` (vitals-http), `libssl.suprx` (vitals-ssl) and `vitals.suprx` (the browser provider) statically link `libmbedtls.a`, `libmbedx509.a` and `libmbedcrypto.a`, built from the official Mbed TLS 3.6 LTS source release (currently 3.6.7), downloaded from the `Mbed-TLS/mbedtls` GitHub releases. vitals modifies three of its files with [tls13-vita/crypto/offer-unknown-ciphersuites.patch](tls13-vita/crypto/offer-unknown-ciphersuites.patch), so that a ClientHello can list cipher suites Mbed TLS doesn't implement, and five with [tls13-vita/crypto/certificate-request-callback.patch](tls13-vita/crypto/certificate-request-callback.patch), so that a client can pick its certificate from a server's certificate request (each change is marked in the code), and adds configuration headers and a Vita platform adapter. This distribution selects the Apache License 2.0 offered by the project; the license text is `licenses/Mbed-TLS-LICENSE.txt`.

The Mbed TLS source release also bundles optional third-party code (Project Everest/HACL\* Curve25519 and p256-m). vitals' configuration does not enable any of it, so none of that code is in the modules.

Mbed TLS is an independent work; no endorsement by its authors is implied.

## curl

The app statically links libcurl (currently 8.17.0), built from the unmodified official release archive from `curl.se` under the curl license (`licenses/curl-LICENSE.txt`). Source: <https://github.com/curl/curl/releases>. The Vita build disables unused protocols, default CA discovery and the console UI.

## OpenSSL, zlib and Zstandard

`libhttp.suprx` (vitals-http) statically links zlib from VitaSDK, for gzip bodies. libcurl uses OpenSSL, zlib and Zstandard from VitaSDK (OpenSSL 1.1.1t, zlib 1.3.2 and Zstandard 1.5.7 in the validated build). Their license texts are `licenses/OpenSSL-LICENSE.txt`, `licenses/zlib-LICENSE.txt` and `licenses/zstd-LICENSE.txt`; Zstandard's BSD option is selected. This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit (<https://www.openssl.org/>). This product includes cryptographic software written by Eric Young (eay@cryptsoft.com).

## Mozilla certificate data

`mozilla-certs.pem` is the curl project's PEM conversion of Mozilla's CA data (Mozilla NSS `certdata.txt`), under the Mozilla Public License 2.0 (`licenses/Mozilla-MPL-2.0.txt`). Its upstream header is kept unchanged. Source: <https://curl.se/ca/cacert.pem>. The snapshot's date, URL and SHA-256 are recorded in `certificate-sources.json`.

## Sony material

The Sony certificate bundle (`sony-certs.pem`) and the Sony system module shipped in `vitals-app/assets/` (`compat.suprx`) are Sony material, and so is `vitals-app/assets/lssl.suprx`, Sony's libssl, kept in the repository as the reference vitals-ssl was written from and no longer shipped. They are not covered by any of the licenses above. When merging certificates, the app keeps the selected certificates and removes duplicates; it does not import the console's existing trust store.
