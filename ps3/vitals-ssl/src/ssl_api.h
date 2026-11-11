#ifndef VITALS_SSL_API_H
#define VITALS_SSL_API_H

#include <stddef.h>
#include <stdint.h>

/* The cellSsl exports written so far, as their callers see them (OpenSSL 0.9.8's API, every
 * object opaque): connection.c's; core.h has the library's. The host tests call them through this */

/* Client methods */
const void *TLSv1_client_method(void);
const void *SSLv3_client_method(void);
const void *cellSsl_C5F77319(void);

/* Contexts */
void *SSL_CTX_new(const void *method);
void SSL_CTX_free(void *context);
long SSL_CTX_set_options(void *context, long options);
long SSL_CTX_ctrl(void *context, int command, long value, void *pointer);
void SSL_CTX_set_verify_mode(void *context, int mode);
void SSL_CTX_set_app_verify_cb(void *context,
                               int (*callback)(void *ssl, void *certificates[], int count, void *argument, int *reason),
                               void *argument);
int SSL_CTX_use_certificate(void *context, void *cert);
int SSL_CTX_use_PrivateKey(void *context, void *key);
void SSL_CTX_set_info_cb(void *context, void (*callback)(const void *ssl, int where, int value));

/* Socket BIOs */
void *BIO_new_socket(int fd, int close_flag);
int BIO_free(void *bio);
long BIO_ctrl(void *bio, int command, long value, void *pointer);
void BIO_set_cb_arg(void *bio, void *argument);
void *BIO_get_cb_arg(void *bio);
int BIO_get_retry_reason(void *bio);
void *BIO_ptr_ctrl(void *bio, int command, long value);
int BIO_printf(void *bio, const char *format, ...);

/* Memory BIOs */
void *BIO_new_mem(void);
void *_cellSslPemReadPrivateKey(void *bio);
void *_cellSslPemReadX509(void *bio);
int BIO_dump(void *bio, const char *data, int length);
const void *cellSsl_F422A5AB(void);
const char *SSL_alert_type_string_long(int value);
const char *SSL_alert_desc_string_long(int value);

/* Connections */
void *SSL_new(void *context);
void SSL_free(void *ssl);
int SSL_clear(void *ssl);
int SSL_set_ssl_method(void *ssl, const void *method);
int SSL_set_session(void *ssl, const void *session);
void SSL_SESSION_free(void *session);
void SSL_set_bio(void *ssl, void *read_bio, void *write_bio);
void *SSL_get_rbio(const void *ssl);
void SSL_set_connect_state(void *ssl);
int SSL_do_handshake(void *ssl);
int SSL_read(void *ssl, void *buffer, int size);
int SSL_peek(void *ssl, void *buffer, int size);
int SSL_write(void *ssl, const void *buffer, int size);
int SSL_shutdown(void *ssl);
int SSL_get_error(const void *ssl, int returned);
int SSL_version(const void *ssl);
const char *SSL_get_version(const void *ssl);
int SSL_state(const void *ssl);
const char *SSL_state_string_long(const void *ssl);
int SSL_want(const void *ssl);

/* Ciphers */
const void *SSL_get_current_cipher(const void *ssl);
const char *SSL_CIPHER_get_name(const void *cipher);
int SSL_CIPHER_get_bits(const void *cipher, int *algorithm_bits);
const char *SSL_CIPHER_get_version(const void *cipher);
unsigned long SSL_CIPHER_get_id(const void *cipher);
char *SSL_CIPHER_description(const void *cipher, char *buffer, int size);
int _cellSslConvertCipherId(unsigned long id, int *out);
int _cellSslConvertSslVersion(int version, int *out);

/* Certificates (certificate.c) */
void SSLCERT_free(void *cert);
void *SSLCERT_get_subject_name(void *cert);
void *SSLCERT_get_issuer_name(void *cert);
int SSLCERT_NAME_get_entry_count(const void *name);
void *SSLCERT_NAME_get_entry(const void *name, int index);
int SSLCERT_NAME_ENTRY_get_info(const void *entry, int *oid_tag, const unsigned char **oid, int *oid_length,
                                int *value_type, const unsigned char **value, int *value_length);
int SSLCERT_NAME_cmp(const void *a, const void *b);
unsigned long SSLCERT_NAME_hash(const void *name);
const char *SSLCERT_OID_to_string(const unsigned char *oid, int length, int short_name);
int SSLCERT_get_notBefore(void *cert, int *type, const unsigned char **data, int *length);
int SSLCERT_get_notAfter(void *cert, int *type, const unsigned char **data, int *length);
int SSLCERT_get_extension(void *cert, const char *oid, int *critical, const unsigned char **value, int *length);
int SSLCERT_get_basic_constraints_int(void *cert, int *critical, int *path_length, int *is_ca);
void *SSLCERT_get_pubkey(void *cert);
int SSLCERT_verify(void *cert, void *key);
int SSLCERT_check_private_key(void *cert, void *key);
void EVP_PKEY_free(void *key);
void *cellSsl_9447404F(const unsigned char *start, const unsigned char *end, int *used);
int cellSsl_2E8CC56D(void *cert);
int cellSsl_C132E990(void *cert);
int cellSsl_597BE64A(int nid, const void *data, uint32_t length, const unsigned char *signature,
                     uint32_t signature_length, void *key);
void *SSLCERT_from_binary(void **out, const unsigned char **data, long length);
char *SSLCERT_NAME_oneline(const void *name, char *buffer, int size);
int BER_read_item(void *item, const unsigned char *data, unsigned int length);
void *R_time_new(void);
void *R_time(void *time);
void R_time_free(void *time);
int R_time_cmp(const void *a, const void *b);
int R_time_import(const unsigned char *data, int length, int format, void *time);
int R_time_export(const void *time, int format, unsigned char *buffer, int size);

/* The public certificate functions and memory (public.c) */
int cellSslCertGetSerialNumber(void *cert, const unsigned char **data, size_t *length);
int cellSslCertGetPublicKey(void *cert, const unsigned char **data, size_t *length);
int cellSslCertGetRsaPublicKeyModulus(void *cert, const unsigned char **data, size_t *length);
int cellSslCertGetRsaPublicKeyExponent(void *cert, const unsigned char **data, size_t *length);
int cellSslCertGetNotBefore(void *cert, uint64_t *tick);
int cellSslCertGetNotAfter(void *cert, uint64_t *tick);
int cellSslCertGetSubjectName(void *cert, void **name);
int cellSslCertGetIssuerName(void *cert, void **name);
int cellSslCertGetNameEntryCount(const void *name, uint32_t *count);
int cellSslCertGetNameEntryInfo(const void *name, uint32_t index, const char **oid_name, const unsigned char **value,
                                size_t *value_length, int short_names);
int cellSslCertGetMd5Fingerprint(void *cert, unsigned char *buffer, uint32_t *length);
int cellSslGetMemoryInfo(uint32_t *free_size, uint32_t *arena, uint32_t *mallinfo);

#endif
