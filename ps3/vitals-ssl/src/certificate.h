#ifndef VITALS_SSL_CERTIFICATE_H
#define VITALS_SSL_CERTIFICATE_H

#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>

#include <stddef.h>
#include <stdint.h>

/* SSL-C's certificate objects over Mbed TLS (certificate.c): certificates, their names and keys,
 * all opaque to their callers. A certificate either owns its Mbed TLS certificate (one parsed for
 * the caller) or borrows one (the server's chain, while libhttp's verify callback runs) */

#define VS_CERT_MAGIC 0x54435356u
#define VS_NAME_MAGIC 0x4E435356u
#define VS_KEY_MAGIC 0x4B435356u

typedef struct VsName {
	uint32_t magic;
	/* The certificate's own: its first entry, and the name's DER (tag and all) */
	const mbedtls_x509_name *head;
	mbedtls_x509_buf raw;
} VsName;

typedef struct VsKey {
	uint32_t magic;
	/* A certificate's public key, which the certificate frees: EVP_PKEY_free leaves it */
	int owned_by_cert;
	mbedtls_pk_context pk;
} VsKey;

typedef struct VsCert {
	uint32_t magic;
	mbedtls_x509_crt *crt;
	int owned;
	mbedtls_x509_crt own;
	/* What the getters give, made on first use and kept as long as the certificate */
	VsName subject, issuer;
	VsKey *public_key;
	char not_before[16], not_after[16];
} VsCert;

int vs_is_cert(const void *cert);
/* A certificate the caller doesn't free: the server's, for the verify callback */
void vs_cert_borrow(VsCert *cert, mbedtls_x509_crt *crt);
void vs_cert_return(VsCert *cert);
/* A certificate parsed from PEM or DER, which SSLCERT_free frees; NULL when it isn't one */
VsCert *vs_cert_parse(const unsigned char *data, size_t length);
/* A private key parsed from PEM or DER, which EVP_PKEY_free frees; NULL when it isn't one */
void *vs_key_parse(const unsigned char *data, size_t length);
int vs_is_key(const void *key);
/* The Mbed TLS certificate and key of an object, or NULL */
const mbedtls_x509_crt *vs_cert_crt(const void *cert);
mbedtls_pk_context *vs_key_pk(void *key);
/* SSLCERT_NAME_hash's: OpenSSL 0.9.8's X509_NAME_hash, the MD5 of the name's DER read as a
 * little-endian number, which Sony's CA table is keyed by */
uint32_t vs_name_hash_raw(const unsigned char *der, size_t length);

#endif
