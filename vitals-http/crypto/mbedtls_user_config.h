#ifndef VH_MBEDTLS_USER_CONFIG_H
#define VH_MBEDTLS_USER_CONFIG_H

/* Mbed TLS 3.6 for vitals-http: a TLS 1.2 and 1.3 client on the Vita's own primitives
 * (tls_platform.c), verifying against CAs loaded on demand (tls13-vita's ca_index.c) */

#include <stdint.h>

#define MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK

#define MBEDTLS_THREADING_C
#define MBEDTLS_THREADING_ALT
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_ENTROPY_HARDWARE_ALT
#define MBEDTLS_PLATFORM_MS_TIME_ALT
#define MBEDTLS_PLATFORM_GMTIME_R_ALT
#define MBEDTLS_PLATFORM_TIME_TYPE_MACRO int64_t
#define MBEDTLS_PLATFORM_TIME_MACRO vh_mbedtls_time

/* To fit the 128 KiB heap: a connection's outgoing records are 4 KiB at most (incoming ones
 * stay at 16 KiB, as a server may send them that size) */
#define MBEDTLS_SSL_OUT_CONTENT_LEN 4096

/* No files, sockets, clocks or servers of its own */
#undef MBEDTLS_FS_IO
#undef MBEDTLS_NET_C
#undef MBEDTLS_TIMING_C
#undef MBEDTLS_PSA_ITS_FILE_C
#undef MBEDTLS_PSA_CRYPTO_STORAGE_C
#undef MBEDTLS_SELF_TEST
#undef MBEDTLS_DEBUG_C
#undef MBEDTLS_SSL_SRV_C
#undef MBEDTLS_SSL_CACHE_C
#undef MBEDTLS_SSL_COOKIE_C
#undef MBEDTLS_SSL_TICKET_C
#undef MBEDTLS_SSL_PROTO_DTLS
#undef MBEDTLS_SSL_DTLS_ANTI_REPLAY
#undef MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE
#undef MBEDTLS_SSL_DTLS_CONNECTION_ID
#undef MBEDTLS_SSL_DTLS_HELLO_VERIFY
#undef MBEDTLS_SSL_DTLS_SRTP
#undef MBEDTLS_SSL_CONTEXT_SERIALIZATION
#undef MBEDTLS_SSL_RENEGOTIATION
#undef MBEDTLS_PKCS7_C
#undef MBEDTLS_X509_CREATE_C
#undef MBEDTLS_X509_CRT_WRITE_C
#undef MBEDTLS_X509_CSR_WRITE_C
#undef MBEDTLS_X509_CSR_PARSE_C
#undef MBEDTLS_X509_CRL_PARSE_C

#ifdef __cplusplus
extern "C" {
#endif
int64_t vh_mbedtls_time(int64_t *output);
#ifdef __cplusplus
}
#endif

#endif
