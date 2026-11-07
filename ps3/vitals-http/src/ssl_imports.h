#ifndef VITALS_HTTP_SSL_IMPORTS_H
#define VITALS_HTTP_SSL_IMPORTS_H

/* The libssl functions vitals' libhttp calls, imported by NID as Sony's libhttp imports Sony's
 * (cellssl_imports.yml, tools/gen_ssl_imports.py): with vitals installed, vitals' libssl answers.
 * Their prototypes are vitals-ssl's (vitals-ssl/src/ssl_api.h) */

#include <stddef.h>
#include <stdint.h>

const void *TLSv1_client_method(void);
void *SSL_CTX_new(const void *method);
void SSL_CTX_free(void *context);
void SSL_CTX_set_verify_mode(void *context, int mode);
void SSL_CTX_set_app_verify_cb(void *context,
                               int (*callback)(void *ssl, void *certificates[], int count, void *argument, int *reason),
                               void *argument);
void *BIO_new_socket(int fd, int close_flag);
long BIO_ctrl(void *bio, int command, long value, void *pointer);
void BIO_set_cb_arg(void *bio, void *argument);
void *BIO_get_cb_arg(void *bio);
void *SSL_new(void *context);
void SSL_free(void *ssl);
void SSL_set_bio(void *ssl, void *read_bio, void *write_bio);
void *SSL_get_rbio(const void *ssl);
void SSL_set_connect_state(void *ssl);
int SSL_do_handshake(void *ssl);
int SSL_read(void *ssl, void *buffer, int size);
int SSL_write(void *ssl, const void *buffer, int size);
int SSL_shutdown(void *ssl);
int SSL_get_error(const void *ssl, int returned);
int SSL_version(const void *ssl);
const void *SSL_get_current_cipher(const void *ssl);
const char *SSL_CIPHER_get_name(const void *cipher);
int SSL_CIPHER_get_bits(const void *cipher, int *algorithm_bits);
const char *SSL_CIPHER_get_version(const void *cipher);
unsigned long SSL_CIPHER_get_id(const void *cipher);
char *SSL_CIPHER_description(const void *cipher, char *buffer, int size);
int _cellSslConvertCipherId(unsigned long id, int *out);
int _cellSslConvertSslVersion(int version, int *out);
void ERR_clear_error(void);
int _cellSslIsInitd(void);

void SSLCERT_free(void *cert);
void *SSLCERT_get_subject_name(void *cert);
void *SSLCERT_get_issuer_name(void *cert);
int SSLCERT_NAME_get_entry_count(const void *name);
void *SSLCERT_NAME_get_entry(const void *name, int index);
int SSLCERT_NAME_ENTRY_get_info(const void *entry, int *oid_tag, const unsigned char **oid, int *oid_length,
                                int *value_type, const unsigned char **value, int *value_length);
int SSLCERT_NAME_cmp(const void *a, const void *b);
int SSLCERT_get_notBefore(void *cert, int *type, const unsigned char **data, int *length);
int SSLCERT_get_notAfter(void *cert, int *type, const unsigned char **data, int *length);
int SSLCERT_get_extension(void *cert, const char *oid, int *critical, const unsigned char **value, int *length);
void *SSLCERT_get_pubkey(void *cert);
int SSLCERT_verify(void *cert, void *key);
void *R_time_new(void);
void *R_time(void *time);
void R_time_free(void *time);
int R_time_cmp(const void *a, const void *b);
int R_time_import(const unsigned char *data, int length, int format, void *time);

void *cellSsl_9447404F(const unsigned char *start, const unsigned char *end, int *used);
int cellSsl_205B060C(const void *name, uint64_t *mask, int *flag);
int cellSsl_68D3409E(const void *name, char *buffer, size_t size, size_t *required, uint64_t mask);
int cellSsl_CC6A0CB5(uint64_t *mask);
int cellSsl_2E8CC56D(void *cert);

#endif
