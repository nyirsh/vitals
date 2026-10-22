# Third-party notices

These notices cover the third-party software and data in vitals. The app's VPK includes this file and the [licenses](licenses/) folder. The exact versions and SHA-256 hashes of Mbed TLS and curl are pinned in [dependencies.cmake](dependencies.cmake).

## Mbed TLS and TF-PSA-Crypto

`vitals_http.suprx` and `vitals.suprx` statically link `libmbedtls.a`, `libmbedx509.a` and `libtfpsacrypto.a`. They are built from the official Mbed TLS source release (currently 4.2.0, which bundles TF-PSA-Crypto 1.2.0), downloaded from the `Mbed-TLS/mbedtls` GitHub releases. The sources are not modified; vitals only adds configuration headers and a Vita platform adapter. This distribution selects the Apache License 2.0 offered by those projects; the license texts are `licenses/Mbed-TLS-LICENSE.txt` and `licenses/TF-PSA-Crypto-LICENSE.txt`.

The Mbed TLS source release also bundles optional third-party code (Project Everest/HACL\* Curve25519, p256-m and mldsa-native). vitals' configuration does not enable any of it, so none of that code is in the modules.

Mbed TLS and TF-PSA-Crypto are independent works; no endorsement by their authors is implied.

## curl

The app statically links libcurl (currently 8.17.0), built from the unmodified official release archive from `curl.se` under the curl license (`licenses/curl-LICENSE.txt`). Source: <https://github.com/curl/curl/releases>. The Vita build disables unused protocols, default CA discovery and the console UI.

## OpenSSL, zlib and Zstandard

libcurl uses OpenSSL, zlib and Zstandard from VitaSDK (OpenSSL 1.1.1t, zlib 1.3.2 and Zstandard 1.5.7 in the validated build). Their license texts are `licenses/OpenSSL-LICENSE.txt`, `licenses/zlib-LICENSE.txt` and `licenses/zstd-LICENSE.txt`; Zstandard's BSD option is selected. This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit (<https://www.openssl.org/>). This product includes cryptographic software written by Eric Young (eay@cryptsoft.com).

## Mozilla certificate data

`mozilla-certs.pem` is the curl project's PEM conversion of Mozilla's CA data (Mozilla NSS `certdata.txt`), under the Mozilla Public License 2.0 (`licenses/Mozilla-MPL-2.0.txt`). Its upstream header is kept unchanged. Source: <https://curl.se/ca/cacert.pem>. The snapshot's date, URL and SHA-256 are recorded in `certificate-sources.json`.

## Sony material

The Sony certificate bundle (`sony-certs.pem`) and the Sony system modules shipped in `vitals-app/assets/` (`compat.suprx`, `lhttp.suprx`, `lssl.suprx`) are Sony material. They are not covered by any of the licenses above. When merging certificates, the app keeps the selected certificates and removes duplicates; it does not import the console's existing trust store.
