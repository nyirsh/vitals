#ifndef VITALS_SSL_PUBLIC_H
#define VITALS_SSL_PUBLIC_H

/* vitals-ssl for its own callers (vitals-http): the Sony functions they use, as Sony's libhttp
 * calls them, and vitals' additions, the VitalsSsl library. Every object is opaque, so a caller
 * needs neither vitals-ssl's nor Mbed TLS's headers */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SSL_get_error's kinds */
#define VITALS_SSL_KIND_NONE 0
#define VITALS_SSL_KIND_SSL 1

/* SceSslInternal, as Sony's libhttp calls them */
int sceSslInternalGetLibrary(void **library);
const void *sceSslInternalClientMethod(void);
void *sceSslInternalCtxNew(const void *library, const void *method);
void sceSslInternalCtxFree(void *context);
void sceSslInternalCtxSetVerify(void *context, int mode);
/* The check that decides on a server's chain in place of the bundle's, as libhttp's: (ssl, the
 * certificates as the server sent them, how many, argument, &reason) → 1 accepts */
typedef int (*VitalsSslVerifyCallback)(void *ssl, void *certificates[], int count, void *argument, int *reason);
void sceSslInternalCtxSetCertVerifyCallback(void *context, VitalsSslVerifyCallback callback, void *argument);
void *sceSslInternalBioNewSocket(int fd, int close_flag);
long sceSslInternalBioCtrl(void *bio, int command, long value, void *pointer);
void *sceSslInternalNew(void *context);
void sceSslInternalFree(void *ssl);
void sceSslInternalSetBio(void *ssl, void *read_bio, void *write_bio);
void sceSslInternalSetConnectState(void *ssl);
int sceSslInternalConnect(void *ssl);
int sceSslInternalRead(void *ssl, void *buffer, int size);
int sceSslInternalWrite(void *ssl, const void *buffer, int size);
int sceSslInternalShutdown(void *ssl);
int sceSslInternalGetError(void *ssl, int returned);

/* BIO_ctrl's command that gives the host name (SNI, and the name checked) */
#define VITALS_SSL_BIO_SET_HOST 100

/* ---- VitalsSsl ---- */

/* Sets up the library without a pool of its own: everything comes from the caller's allocator
 * (vitals-http's heap). Once per process, in place of sceSslInit; 0, or an SCE error */
int vitalsSslInitShared(void);

/* A BIO over the caller's own transport: send and receive return the bytes moved (receive 0 when
 * the server closed) or a negative error, which connect, read and write then return as it is */
typedef int (*VitalsSslSend)(void *context, const unsigned char *data, size_t size);
typedef int (*VitalsSslReceive)(void *context, unsigned char *data, size_t size);
void *vitalsSslBioNew(VitalsSslSend send, VitalsSslReceive receive, void *context);

/* The ClientHello a context's connections send */
#define VITALS_SSL_PROFILE_MODERN 0
/* As the console's own: TLS 1.2, its suites (3DES and RC4 only offered), its signature
 * algorithms, no extended master secret, encrypt-then-MAC or tickets. The CDN in front of PSN
 * sign-in refuses others */
#define VITALS_SSL_PROFILE_CONSOLE 1
int vitalsSslCtxSetProfile(void *context, int profile);

/* With the verify mode on, a certificate the checks refuse doesn't fail the handshake: the caller
 * reads what was found (vitalsSslGetCertificateFlags) and decides */
int vitalsSslCtxSetDeferredVerify(void *context, int deferred);

/* CA certificates trusted besides the bundle (an app's sceHttpsLoadCert ones): a store, which
 * contexts given it keep until they are freed */
void *vitalsSslStoreNew(void);
/* Adds the certificates of data (PEM or DER, size bytes, any NUL after them left out): 0, or the
 * parser's error (negative) */
int vitalsSslStoreAdd(void *store, const void *data, size_t size);
void vitalsSslStoreRelease(void *store);
int vitalsSslCtxSetStore(void *context, void *store);

/* A client certificate and key (PEM or DER) sent to any server that asks for one: 0, or the
 * parser's error (negative) */
int vitalsSslCtxSetIdentity(void *context, const void *certificate, size_t certificate_size,
                            const void *key, size_t key_size);
/* Whether such data parses, without keeping it: 0 or the parser's error */
int vitalsSslCheckCertificate(const void *data, size_t size);
int vitalsSslCheckKey(const void *data, size_t size);

/* Checks a chain a verify callback was given (the server's certificate first) against the bundle and
 * the store's certificates (NULL for none), with exact trust of self-signed ones, and the host name
 * when there is one: tls13-vita's VITALS_CERT_* flags, 0 when nothing is wrong */
unsigned int vitalsSslCheckChain(void *const certificates[], int count, const char *host, void *store);

/* What the server's certificate check found, as tls13-vita's VITALS_CERT_* flags: 0 when nothing
 * (or it wasn't checked) */
unsigned int vitalsSslGetCertificateFlags(void *ssl);
/* Mbed TLS's own verification result, for logs: 0xFFFFFFFF when it didn't run */
unsigned int vitalsSslGetVerifyResult(void *ssl);
/* Mbed TLS's error of the connection's last TLS failure, 0 when none, and whether it was memory */
int vitalsSslGetTlsError(void *ssl);
int vitalsSslTlsErrorIsMemory(int error);
/* For logs: the negotiated version and suite, and whether the server asked for a certificate */
const char *vitalsSslGetVersion(void *ssl);
const char *vitalsSslGetCiphersuite(void *ssl);
int vitalsSslCertificateRequested(void *ssl);

#ifdef __cplusplus
}
#endif

#endif
