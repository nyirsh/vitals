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

typedef int (*VsVerifyCallback)(void *store, void *argument);
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
} VsContext;

typedef struct VsBio {
    uint32_t magic;
    int fd;
    int close_on_free;
    int has_fd;
    /* Sony's: the host name libhttp gives (100), which the ClientHello's SNI comes from; the
     * caller's pointer, as Sony keeps it */
    const char *host;
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
} VsSsl;

/* core.c, under the lock: whether sceSslInit ran, and what failed last for the error translator */
int vs_initialized(void);
int vs_is_library(const void *library);
void vs_note_out_of_memory(void);
int vs_take_out_of_memory(void);
/* The random numbers and trusted roots every connection uses (once sceSslInit made them) */
int vs_tls_random(void *context, unsigned char *output, size_t size);
int vs_find_trusted_issuers(void *context, const mbedtls_x509_crt *child, mbedtls_x509_crt **candidates);
int vs_trust_exact_self_signed(void *context, mbedtls_x509_crt *certificate, int depth, uint32_t *flags);

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

/* The SceSslInternal exports written so far (core.c, connection.c), with the arguments Sony's
 * libhttp passes */
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

#endif
