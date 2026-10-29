#ifndef VITALS_SSL_VS_H
#define VITALS_SSL_VS_H

#include "ssl.h"

#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#include <stddef.h>
#include <stdint.h>

/* SSL-C's objects as Sony's libhttp uses them: a library made by sceSslInit, client methods,
 * contexts (SSL_CTX), connections (SSL) and socket BIOs, all opaque to their callers */

#define VS_ERROR_BEFORE_INIT ((int)0x80435001)
#define VS_ERROR_ALREADY_INITED ((int)0x80435020)
#define VS_ERROR_OUT_OF_MEMORY ((int)0x80435022)
#define VS_ERROR_INTERNAL ((int)0x80435026)
#define VS_ERROR_INVALID_VALUE ((int)0x804351FE)
#define VS_ERROR_UNKNOWN_REASON ((int)0x804352FF)
/* SceNet's EAGAIN, which a receive that timed out returns */
#define VS_NET_ERROR_EAGAIN ((int)0x80410123)
#define VS_NET_ERROR_EINTR ((int)0x80410104)

/* The objects' first word, which tells them apart */
#define VS_CONTEXT_MAGIC 0x43535356u
#define VS_BIO_MAGIC 0x42535356u

/* SSL_get_error's kinds, as OpenSSL numbers them */
#define VS_KIND_NONE 0
#define VS_KIND_SSL 1
#define VS_KIND_WANT_READ 2
#define VS_KIND_WANT_WRITE 3
#define VS_KIND_SYSCALL 5
#define VS_KIND_ZERO_RETURN 6

/* SSL_CTX_ctrl's session cache mode commands */
#define VS_CTRL_SET_SESS_CACHE_MODE 44
#define VS_CTRL_GET_SESS_CACHE_MODE 45

/* BIO_ctrl's commands: OpenSSL's, and Sony's host name (100 sets it, 123 reads it) */
#define VS_BIO_CTRL_GET_CLOSE 8
#define VS_BIO_CTRL_SET_CLOSE 9
#define VS_BIO_CTRL_SET_HOST 100
#define VS_BIO_C_SET_FD 104
#define VS_BIO_C_GET_FD 105
#define VS_BIO_CTRL_GET_HOST 123

/* SSL_set_info_callback's where bits, as OpenSSL numbers them */
#define VS_CB_READ 0x04
#define VS_CB_WRITE 0x08
#define VS_CB_ALERT 0x4000

/* How the last operation on a connection failed, which SSL_get_error reports */
typedef enum VsFailure {
    VS_FAILED_NOTHING,
    VS_FAILED_RECEIVE, /* the socket's receive returned an error */
    VS_FAILED_SEND,    /* the socket's send returned an error */
    VS_FAILED_SEND_ZERO,
    VS_FAILED_EOF,     /* the server closed the socket */
    VS_FAILED_CLOSED,  /* the server's close_notify */
    VS_FAILED_TLS,     /* the TLS itself: a bad message, an alert, a refused certificate */
} VsFailure;

typedef struct VsMethod {
    uint32_t magic;
    int kind;
} VsMethod;

/* libhttp's certificate check (0x81014592): the server's chain, its certificate first; 1 accepts,
 * and reason is what the connection's verify result becomes */
typedef int (*VsVerifyCallback)(void *ssl, void *certificates[], int count, void *argument, int *reason);
typedef int (*VsClientCertCallback)(void *ssl, void **certificate, void **key);
typedef void (*VsInfoCallback)(const void *ssl, int where, int value);

typedef struct VsContext {
    uint32_t magic;
    const VsMethod *method;
    unsigned int references;
    uint32_t options;
    long cache_mode;
    int verify_mode;
    VsVerifyCallback verify_callback;
    void *verify_argument;
    VsClientCertCallback client_cert_callback;
    /* vitals' additions (vitals.c) */
    int profile;
    int deferred_verify;
    struct VsStore *store;
    mbedtls_x509_crt *own_certificate;
    mbedtls_pk_context *own_key;
} VsContext;

typedef struct VsBio {
    uint32_t magic;
    int fd;
    int close_on_free;
    int has_fd;
    /* Sony's: the host name libhttp gives (100), which the ClientHello's SNI comes from; the
     * caller's pointer, as Sony keeps it */
    const char *host;
    /* vitals' callback BIO (vitalsSslBioNew): the caller's transport in place of a socket */
    int (*send)(void *, const unsigned char *, size_t);
    int (*receive)(void *, unsigned char *, size_t);
    void *transport;
} VsBio;

typedef struct VsSsl {
    uint32_t magic;
    VsContext *context;
    VsBio *rbio, *wbio;
    uint32_t options;
    VsInfoCallback info_callback;
    void *message_callback, *message_argument;
    int connecting;
    int ready;          /* mbedtls_ssl_setup done */
    int handshake_done;
    int close_notify;   /* the server's close_notify arrived */
    int close_sent;
    VsFailure failure;
    int socket_result;  /* what the socket returned when failure is RECEIVE or SEND */
    int tls_result;     /* Mbed TLS's error when failure is TLS */
    mbedtls_ssl_context tls;
    mbedtls_ssl_config config;
    mbedtls_x509_crt_profile profile;
    /* A host that is an IPv4 address: no SNI, as Sony's, and the certificate is checked for it
     * here, as Mbed TLS would send it */
    int check_address;
    unsigned char address[4];
    /* What the verify callback gave as its reason (SSL_get_verify_result), set by B0E4CB2F too */
    int verify_result;
    /* The CA names of the server's certificate request, while the client certificate callback
     * runs (A4EA9DE0, 243DE290) */
    void **ca_names;
    int ca_name_count;
    /* The client certificate and key the callback gave, kept until the connection is freed */
    void *client_cert, *client_key;
    /* The server asked for a certificate */
    int certificate_requested;
} VsSsl;

/* A certificate: the server's, which the connection keeps (borrowed), or one 29AAC768 parsed */
typedef struct VsCert {
    uint32_t magic;
    mbedtls_x509_crt *crt;
    int owned;
    mbedtls_x509_crt own;
} VsCert;

/* core.c, under the lock: whether sceSslInit ran, and what failed last for the error translator */
int vs_initialized(void);
int vs_is_library(const void *library);
void vs_note_out_of_memory(void);
int vs_take_out_of_memory(void);
/* The random numbers and trusted roots every connection uses (once sceSslInit made them) */
int vs_tls_random(void *context, unsigned char *output, size_t size);
int vs_find_trusted_issuers(void *context, const mbedtls_x509_crt *child, mbedtls_x509_crt **candidates);
int vs_trust_exact_self_signed(void *context, mbedtls_x509_crt *certificate, int depth, uint32_t *flags);
/* Sets up the library, with a pool of size bytes or (0) the caller's allocator: 0 or an SCE error */
int vs_library_init(unsigned int pool_size);

/* vitals.c: vitals' additions to contexts */
void vs_context_free_additions(VsContext *context);
/* The bundle's roots, then the context's store's certificates; context is the connection */
int vs_find_issuers_with_store(void *context, const mbedtls_x509_crt *child, mbedtls_x509_crt **candidates);
/* Applies the context's profile to a connection's configuration */
int vs_apply_profile(VsSsl *ssl);
/* The CA bundle's index, built on first use; NULL without a bundle */
const struct VitalsCaIndex *vs_ca_index(void);

/* certificate.c: certificate objects over Mbed TLS, for libhttp's verify callback and SceSsl's
 * getters */
const void *vs_cert_library(void);
int vs_is_ssl(const void *ssl);
const mbedtls_x509_crt *vs_certificate(const void *cert);
void vs_cert_borrow(VsCert *cert, mbedtls_x509_crt *crt);
void vs_cert_return(VsCert *cert);
int64_t vs_certificate_time(const mbedtls_x509_crt *crt, int not_after);
/* A name object: a copy of the Name raw holds (tag and all), freed with vs_name_free */
void *vs_name_new(const mbedtls_x509_buf *raw);
void vs_name_free(void *name);
int vs_name_count(const void *name);
const mbedtls_x509_name *vs_name_entry(const void *name, int index);
/* Forgets which roots the CA store gave this thread, before a verify callback runs */
void vs_certificate_lookups_reset(void);
mbedtls_pk_context *vs_key(void *key);

/* The platform: platform_vita.c on the console, tests/platform_posix.c on a host */
/* The pool sceSslInit's size gives, which every allocation comes from; a negative SCE error when
 * it can't be made */
int vs_platform_heap_create(unsigned int size);
void vs_platform_heap_destroy(void);
void vs_platform_heap_stats(unsigned int *capacity, unsigned int *peak, unsigned int *used);
void vs_lock(void);
void vs_unlock(void);
/* SceNet's errno is cleared before each socket call, as Sony's socket BIO does */
void vs_platform_clear_net_errno(void);
int vs_platform_socket_close(int fd);
/* 1 when host is an IPv4 address, with its 4 bytes */
int vs_platform_parse_ipv4(const char *host, unsigned char address[4]);
/* Runs function on a thread with a stack large enough for a handshake (TLS 1.3 with elliptic
 * curves), waiting for it; on the caller's thread when one can't be made */
void vs_platform_run_on_large_stack(void (*function)(void *), void *argument);
int vs_platform_ca_path(char *path, size_t size);
unsigned int vs_platform_thread_id(void);

/* The SceSslInternal exports written so far (core.c, connection.c, certificate.c), with the
 * arguments Sony's libhttp passes */
int sceSslInternalIsInitalized(void);
int sceSslInternalGetLibrary(void **library);
int sceSslInternalErrorCode(int kind, int reason);
const void *sceSslInternalClientMethod(void);
const void *sceSslInternalClientMethod2(void);
void *sceSslInternalCtxNew(const void *library, const void *method);
void sceSslInternalCtxFree(void *context);
int sceSslInternalCtxSeedRandom(void *context, const void *data, unsigned int size);
uint32_t sceSslInternalCtxSetOptions(void *context, uint32_t options);
long sceSslInternalCtxCtrl(void *context, int command, long value, void *pointer);
void sceSslInternalCtxSetClientCertCallback(void *context, VsClientCertCallback callback);
void sceSslInternalCtxSetVerify(void *context, int mode);
void sceSslInternalCtxSetCertVerifyCallback(void *context, VsVerifyCallback callback, void *argument);
void *sceSslInternalBioNewSocket(int fd, int close_flag);
long sceSslInternalBioCtrl(void *bio, int command, long value, void *pointer);
void *sceSslInternalNew(void *context);
void sceSslInternalFree(void *ssl);
uint32_t sceSslInternalSetOptions(void *ssl, uint32_t options);
void sceSslInternalSetBio(void *ssl, void *read_bio, void *write_bio);
void sceSslInternalSetInfoCallback(void *ssl, VsInfoCallback callback);
void sceSslInternalSetCallback(void *ssl, void *callback, void *argument);
void sceSslInternalSetConnectState(void *ssl);
int sceSslInternalConnect(void *ssl);
int sceSslInternalRead(void *ssl, void *buffer, int size);
int sceSslInternalWrite(void *ssl, const void *buffer, int size);
int sceSslInternalShutdown(void *ssl);
int sceSslInternalGetError(void *ssl, int returned);
int sceSslInternalGetItem(void *ssl, int item, const void **out);
void sceSslInternalSetVerifyResult(void *ssl, int result);
int sceSslInternalCertSubject(void *cert, int format, void **name);
int sceSslInternalCertIssuer(void *cert, int format, void **name);
int sceSslInternalNameFree(void *name);
int sceSslInternalNameEqual(const void *a, const void *b);
int sceSslInternalNameInfo(void *name, int item, void *out);
int sceSslInternalEntryInfo(void *entry, int item, void *out);
int sceSslInternalEntryFree(void *entry);
int sceSslInternalOidSet(void *oid, int mode, const unsigned char *data, unsigned int length);
int sceSslInternalOidText(const void *oid, int format, unsigned int size, char *text);
int sceSslInternalExtensionNew(const void *library, int type, void **out);
int sceSslInternalExtensionFree(void *extension);
int sceSslInternalExtensionInfo(void *extension, int item, void *out);
int sceSslInternalCertPublicKey(void *cert, int format, void **key);
int sceSslInternalKeyFree(void *key);
int sceSslInternalCertVerifySignature(void *cert, void *key, int *valid);
int sceSslInternalCertFromBinary(const void *library, int flags, int format, unsigned int length,
                                 const unsigned char *data, unsigned int *consumed, void **out);
int sceSslInternalCertFree(void *cert);
int sceSslInternalCertInfo(void *cert, int item, void *out);
int sceSslInternalCertToBinary(void *cert, int format, unsigned int size, unsigned char *buffer,
                               unsigned int *length);
int sceSslInternalTimeProvider(const void *library, int type, void **out);
int sceSslInternalTimeProviderFree(void *provider);
int sceSslInternalTimeNew(const void *provider, void **out);
int sceSslInternalTimeFree(void *time);
int sceSslInternalTimeNow(void *now);
int sceSslInternalTimeExport(const void *now, int format, void *value, unsigned int size);
int sceSslInternalTimeImport(void *time, int format, const void *value, unsigned int size);
int sceSslInternalCertNotAfter(void *cert, void *time);
int sceSslInternalCertNotBefore(void *cert, void *time);
int sceSslInternalTimeCompare(const void *a, const void *b, int *order);
int sceSslInternalTimeText(const void *time, int format, char *text, unsigned int *length, unsigned int size);
int sceSslInternalGetCertificateAuthorityByName(const void *name, char ***entries, char *buffer,
                                                unsigned int size, unsigned int *total, int flag);
int sceSslInternalGetCertificateAuthority(unsigned int group, unsigned int mask, char ***entries, char *buffer,
                                          unsigned int size, unsigned int *total);
int sceSslInternalCaRevoked(unsigned int group, unsigned int mask, const void **entries, unsigned int *count);
int sceSslInternalGetCaNameCount(void *ssl);
int sceSslInternalGetCaName(void *ssl, int index, void **name);
void *sceSslInternalBufferNew(void);
int sceSslInternalBufferWrite(void *buffer, const void *data, int length);
int sceSslInternalBufferFree(void *buffer);
int sceSslInternalKeyFromBuffer(void *buffer, const void *library, void **key, int format, int flags);
int sceSslInternalKeyMatches(void *cert, void *key);

#endif
