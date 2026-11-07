# Third-party notices

These notices cover the third-party software and data in vitals, for the PS Vita and the PlayStation 3. Both apps' packages include this file and the [licenses](licenses/) folder. The exact versions and SHA-256 hashes of what's downloaded at build time are pinned in [shared/mbedtls/mbedtls.cmake](shared/mbedtls/mbedtls.cmake) for Mbed TLS and in [shared/curl/curl.cmake](shared/curl/curl.cmake) for curl.

## Both consoles

### Mbed TLS

vitals' libssl (`libssl.suprx` on the Vita, from `vita/vitals-ssl`; `libssl.sprx` on the PS3, from `ps3/vitals-ssl`), and the PS3's app (`ps3/vitals-app`, as libcurl's TLS), statically link `libmbedtls.a`, `libmbedx509.a` and `libtfpsacrypto.a`, built from the official Mbed TLS 4.2 source release (currently 4.2.0, which bundles TF-PSA-Crypto), downloaded from the `Mbed-TLS/mbedtls` GitHub releases. vitals modifies it with four patches, in [shared/mbedtls](shared/mbedtls/), which both consoles' builds apply:

- [rsa-client.patch](shared/mbedtls/rsa-client.patch) puts back the client side of TLS 1.2's RSA key exchange and its four AES-CBC suites, which Mbed TLS removed in 4.0 and some of Sony's servers still use. It comes from devnoname120's [tls_fixer](https://github.com/devnoname120/vita_tls_fixer) (v0.2.2, `tls13/crypto/patches/rsa-client-4.2.patch`), trimmed
- [offer-unknown-ciphersuites.patch](shared/mbedtls/offer-unknown-ciphersuites.patch) lets a ClientHello list cipher suites Mbed TLS doesn't implement
- [certificate-request-callback.patch](shared/mbedtls/certificate-request-callback.patch) lets a client pick its certificate from a server's certificate request
- [pkcs8-rsa-public-key.patch](shared/mbedtls/pkcs8-rsa-public-key.patch) gives an RSA private key read from PKCS#8 its public half, as the other key formats have, so it can be matched to its certificate

Each change is marked in the code. vitals also adds configuration headers and a platform adapter for each console (the PS3's in [ps3/vitals-ssl/src/platform](ps3/vitals-ssl/src/platform/)). This distribution selects the Apache License 2.0 offered by both projects; the license texts are `licenses/Mbed-TLS-LICENSE.txt` and `licenses/TF-PSA-Crypto-LICENSE.txt`.

The Mbed TLS source release also bundles optional third-party code (Project Everest/HACL\* Curve25519, p256-m and the mldsa-native ML-DSA implementation). vitals' configuration does not enable any of it, so none of that code is in the modules.

Mbed TLS is an independent work; no endorsement by its authors is implied.

### Mozilla certificate data

`mozilla-certs.pem` (in each app's `vitals-app/assets/`; the PS3 installs it as `cacert.pem`) is the curl project's PEM conversion of Mozilla's CA data (Mozilla NSS `certdata.txt`), under the Mozilla Public License 2.0 (`licenses/Mozilla-MPL-2.0.txt`). Its upstream header is kept unchanged. Source: <https://curl.se/ca/cacert.pem>. The snapshot's date, URL and SHA-256 are recorded in each app's `certificate-sources.json`.

## PS Vita

### curl

Both apps statically link libcurl (currently 8.17.0), built from the unmodified official release archive from `curl.se` under the curl license (`licenses/curl-LICENSE.txt`). Source: <https://github.com/curl/curl/releases>. The builds disable unused protocols and default CA discovery; the Vita's uses OpenSSL (below) and disables the console UI, the PS3's uses Mbed TLS (above).

### OpenSSL, zlib and Zstandard

`libhttp.suprx` (vita/vitals-http) statically links zlib from VitaSDK, for gzip bodies. libcurl uses OpenSSL, zlib and Zstandard from VitaSDK (OpenSSL 1.1.1t, zlib 1.3.2 and Zstandard 1.5.7 in the validated build). Their license texts are `licenses/OpenSSL-LICENSE.txt`, `licenses/zlib-LICENSE.txt` and `licenses/zstd-LICENSE.txt`; Zstandard's BSD option is selected. This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit (<https://www.openssl.org/>). This product includes cryptographic software written by Eric Young (eay@cryptsoft.com).

### Sony material

The Sony certificate bundle (`sony-certs.pem`) and the Sony system module shipped in `vita/vitals-app/assets/` (`compat.suprx`) are Sony material, and so is `vita/vitals-app/assets/lssl.suprx`, Sony's libssl, kept in the repository as the reference vitals-ssl was written from and no longer shipped. They are not covered by any of the licenses above. When merging certificates, the app keeps the selected certificates and removes duplicates; it does not import the console's existing trust store.

## PlayStation 3

### PS3DK

The modules are built with PS3DK (RPCS3's PS3 SDK), which [vitals-ps3-sdk](https://github.com/nyirsh/vitals-ps3-sdk) fetches and builds into the `nyirsh/vitals-ps3-sdk` image, with vitals' patch to its prx-gen; none of it is in the repository or the modules beyond what follows. [ps3/cmake/vitals-prx.ld](ps3/cmake/vitals-prx.ld) is derived from PS3DK's `lv2-prx.ld`, under PS3DK's MIT license (`licenses/PS3DK-LICENSE.txt`).

### Function names

The names in `ps3/tools/names/` come from RPCS3's module tables (GPL-2.0); they are the names of Sony's API, not RPCS3's code, and only the repository's tools use them.

### Sony material

No Sony module or certificate is in the repository or the PS3 app; the tools read the decrypted modules from outside it, and the PS3's own certificates stay on the console.
