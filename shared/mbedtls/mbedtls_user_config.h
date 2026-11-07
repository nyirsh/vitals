#ifndef VITALS_MBEDTLS_USER_CONFIG_H
#define VITALS_MBEDTLS_USER_CONFIG_H

/* Mbed TLS 4.2's TLS and X.509 options, for vitals-ssl: a TLS 1.2 and 1.3 client verifying against
 * CAs loaded on demand (../provider/ca_index.c); the crypto options are in psa_user_config.h */

#define MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK

/* TLS 1.2's RSA key exchange, client side, which rsa-client.patch puts back */
#define MBEDTLS_KEY_EXCHANGE_RSA_ENABLED

/* To keep each connection small in the app's libssl pool: its outgoing records are 4 KiB at most
 * (incoming ones stay at 16 KiB, as a server may send them that size) */
#define MBEDTLS_SSL_OUT_CONTENT_LEN 4096

/* No sockets, clocks or servers of its own (the RSA key exchange patch is client-only) */
#undef MBEDTLS_NET_C
#undef MBEDTLS_TIMING_C
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

#endif
