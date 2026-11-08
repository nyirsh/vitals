#ifndef VITALS_HTTP_TLS_SONY_H
#define VITALS_HTTP_TLS_SONY_H

#include <stddef.h>
#include <stdint.h>

/* vitals-http's TLS when the process's libssl is Sony's (the Options' tls.off): as Sony's libhttp
 * does it, on the functions Sony's libssl exports (tls_sony.c). tls.c decides which */

/* A CA certificate the app loaded (sceHttpsLoadCert, sceHttpsAddCA...), PEM or DER as given */
typedef struct VhSonyCa {
    struct VhSonyCa *next;
    size_t size;
    unsigned char data[];
} VhSonyCa;

/* What the check trusts besides libssl's own roots */
typedef struct {
    const VhSonyCa *cas;
} VhSonyTrust;

/* The client certificate and key the app loaded, copied for one handshake (the callee frees them) */
typedef struct {
    unsigned char *certificate;
    size_t certificate_size;
    unsigned char *key;
    size_t key_size;
} VhSonyIdentity;
/* 1 with the copies, 0 when there's none */
typedef int (*VhSonyClientSource)(void *argument, VhSonyIdentity *identity);

/* The server's chain checked against what the app loaded and libssl's roots, the host name too
 * when it isn't NULL: vitals' VITALS_CERT_* flags of what's wrong (error_map.h). ssl is the
 * connection, which the check gets its Cert-C context from */
uint32_t vh_sony_check_chain(void *ssl, void *certificates[], int count, const char *host, const VhSonyTrust *trust);

typedef struct {
    int socket;
    const char *host;
    uint32_t https_options;
    /* The chain check, with the trust it holds while it runs (vh_sony_check_chain under the lock) */
    uint32_t (*check)(void *argument, void *ssl, void *certificates[], int count, const char *host);
    void *argument;
    /* The app's sceHttpsSetSslCallback */
    int (*ssl_callback)(unsigned int bits, void *const certificates[], int count, void *argument);
    void *ssl_argument;
    /* Where the client certificate comes from, NULL for none */
    VhSonyClientSource client_source;
    void *client_argument;
} VhSonyConnection;

typedef struct VhSonyTls VhSonyTls;
/* A connection over the socket, set up as Sony's libhttp sets it up; connection stays the caller's
 * until it's closed. 0, or -1 */
int vh_sony_tls_start(VhSonyTls **tls, const VhSonyConnection *connection);
/* The handshake: libssl's result (1 when connected), with the certificate problems the options
 * count and whether the check (or the app's callback) refused them */
int vh_sony_tls_connect(VhSonyTls *tls, uint32_t *flags, int *refused);
/* The connection, for libssl's read and write */
void *vh_sony_tls_ssl(VhSonyTls *tls);
void vh_sony_tls_close(VhSonyTls *tls);

#endif
