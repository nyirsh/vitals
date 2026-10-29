#include "vs.h"

#include "diagnostics.h"

#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/platform_util.h>
#include <psp2/net/net.h>

#include <stdlib.h>
#include <string.h>

/* SSL-C's connection API as Sony's libhttp calls it, which is OpenSSL's: SSL_CTX, SSL and a
 * socket BIO, with TLS 1.2 and 1.3 from Mbed TLS. What each call returns follows Sony's:
 * - connect, read and write return what the socket returned when it failed (a negative SceNet
 *   error, which is how libhttp sees a timeout), 0 when the server closed the connection, -1 when
 *   the TLS failed
 * - SSL_get_error then says which it was, as OpenSSL's kinds
 * While a context's verify mode is on the server's certificate is checked: by the verify callback
 * the context was given, which is how libhttp checks it (certificate.c has the objects it uses),
 * or else by Mbed TLS against the CA bundle and the host name */

#define METHOD_MAGIC 0x4D535356u
#define CONTEXT_MAGIC 0x43535356u
#define SSL_MAGIC 0x53535356u
#define BIO_MAGIC 0x42535356u

/* Two client methods, as Sony's: libhttp uses the first for its connections and the second for
 * another; here both are TLS 1.2 to 1.3 */
static const VsMethod g_client_method = {METHOD_MAGIC, 1};
static const VsMethod g_client_method_2 = {METHOD_MAGIC, 2};

static int is_context(const VsContext *context)
{
    return context != NULL && context->magic == CONTEXT_MAGIC;
}

static int is_ssl(const VsSsl *ssl)
{
    return ssl != NULL && ssl->magic == SSL_MAGIC;
}

int vs_is_ssl(const void *ssl)
{
    return is_ssl(ssl);
}

static int is_bio(const VsBio *bio)
{
    return bio != NULL && bio->magic == BIO_MAGIC;
}

/* NID 0xA374CD7B, Sony 0x81013ED7 */
const void *sceSslInternalClientMethod(void)
{
    return &g_client_method;
}

/* NID 0xAC1DBE40, Sony 0x8100F3E7 */
const void *sceSslInternalClientMethod2(void)
{
    return &g_client_method_2;
}

/* ---- contexts ---- */

/* NID 0xE746465E, Sony 0x8101A645: SSL_CTX_new, with the library object; NULL when it fails */
void *sceSslInternalCtxNew(const void *library, const void *method)
{
    const VsMethod *chosen = method;
    if (!vs_initialized() || !vs_is_library(library) || chosen == NULL || chosen->magic != METHOD_MAGIC)
        return NULL;
    VsContext *context = calloc(1, sizeof(*context));
    if (context == NULL) {
        vs_note_out_of_memory();
        return NULL;
    }
    context->magic = CONTEXT_MAGIC;
    context->method = chosen;
    context->references = 1;
    return context;
}

static void context_release(VsContext *context)
{
    vs_lock();
    unsigned int left = --context->references;
    vs_unlock();
    if (left == 0) {
        context->magic = 0;
        free(context);
    }
}

/* NID 0xEF9EBAC7, Sony 0x810192EF: SSL_CTX_free; the connections made from it keep it until
 * they are freed */
void sceSslInternalCtxFree(void *handle)
{
    VsContext *context = handle;
    if (is_context(context))
        context_release(context);
}

/* NID 0x67FB1CD3, Sony 0x8101648B: more bytes for Sony's random generator (libhttp gives 8 bytes
 * of the process time). Accepted and not needed: Mbed TLS's is seeded from the kernel's random
 * numbers. 0, or Sony's reason 32 without any */
int sceSslInternalCtxSeedRandom(void *handle, const void *data, unsigned int size)
{
    (void)handle;
    if (data == NULL || size == 0)
        return 32;
    return 0;
}

/* NID 0xFBEB1FD7, Sony 0x81019C21: SSL_CTX_set_options, which only adds bits; kept, as this TLS
 * has none of SSL-C's options */
uint32_t sceSslInternalCtxSetOptions(void *handle, uint32_t options)
{
    VsContext *context = handle;
    if (!is_context(context))
        return 0;
    context->options |= options;
    return context->options;
}

/* NID 0xCC7F4211, Sony 0x81019BC9: SSL_CTX_ctrl. The session cache mode is kept (there is no
 * session cache); other commands do nothing */
long sceSslInternalCtxCtrl(void *handle, int command, long value, void *pointer)
{
    VsContext *context = handle;
    (void)pointer;
    if (!is_context(context))
        return 0;
    if (command == VS_CTRL_SET_SESS_CACHE_MODE) {
        long old = context->cache_mode;
        context->cache_mode = value;
        return old;
    }
    if (command == VS_CTRL_GET_SESS_CACHE_MODE)
        return context->cache_mode;
    VITALS_LOG("ctx ctrl %d ignored", command);
    return 0;
}

/* NID 0x9E38815D, Sony 0x81016469: SSL_CTX_set_client_cert_cb, called when the server asks for a
 * certificate as (ssl, &certificate, &key) → 1 with them */
void sceSslInternalCtxSetClientCertCallback(void *handle, VsClientCertCallback callback)
{
    VsContext *context = handle;
    if (is_context(context))
        context->client_cert_callback = callback;
}

/* NID 0x260F5A85, Sony 0x81016587: SSL_CTX_set_verify's mode (1 checks the server) */
void sceSslInternalCtxSetVerify(void *handle, int mode)
{
    VsContext *context = handle;
    if (is_context(context))
        context->verify_mode = mode;
}

/* NID 0xAF50B945, Sony 0x81016581: SSL_CTX_set_cert_verify_callback, called in place of the
 * check against the CA bundle as (ssl, certificates, count, argument, &reason) */
void sceSslInternalCtxSetCertVerifyCallback(void *handle, VsVerifyCallback callback, void *argument)
{
    VsContext *context = handle;
    if (is_context(context)) {
        context->verify_callback = callback;
        context->verify_argument = argument;
    }
}

/* ---- socket BIOs ---- */

/* NID 0xFFE2ED51, Sony 0x81000DFB: BIO_new_socket; close_flag 1 closes the socket with it */
void *sceSslInternalBioNewSocket(int fd, int close_flag)
{
    VsBio *bio = calloc(1, sizeof(*bio));
    if (bio == NULL) {
        vs_note_out_of_memory();
        return NULL;
    }
    bio->magic = BIO_MAGIC;
    bio->fd = fd;
    bio->has_fd = 1;
    bio->close_on_free = close_flag & 1;
    return bio;
}

static void bio_free(VsBio *bio)
{
    if (!is_bio(bio))
        return;
    if (bio->has_fd && bio->close_on_free)
        (void)vs_platform_socket_close(bio->fd);
    bio->magic = 0;
    free(bio);
}

/* NID 0x16D7C7CA, Sony 0x81000A21: BIO_ctrl; -2 for a BIO that has none, as OpenSSL's */
long sceSslInternalBioCtrl(void *handle, int command, long value, void *pointer)
{
    VsBio *bio = handle;
    if (bio == NULL)
        return 0;
    if (!is_bio(bio))
        return -2;
    switch (command) {
    case VS_BIO_CTRL_SET_HOST:
        if (!bio->has_fd)
            return -1;
        bio->host = pointer;
        VITALS_LOG("bio %p host %p %.64s", (void *)bio, pointer, pointer != NULL ? (const char *)pointer : "-");
        return 1;
    case VS_BIO_CTRL_GET_HOST:
        if (pointer == NULL || !bio->has_fd)
            return -1;
        *(const char **)pointer = bio->host;
        return 1;
    case VS_BIO_C_SET_FD:
        if (pointer == NULL)
            return -1;
        bio->fd = *(const int *)pointer;
        bio->has_fd = 1;
        bio->close_on_free = (int)(value & 1);
        return 1;
    case VS_BIO_C_GET_FD:
        if (!bio->has_fd)
            return -1;
        if (pointer != NULL)
            *(int *)pointer = bio->fd;
        return bio->fd;
    case VS_BIO_CTRL_GET_CLOSE:
        return bio->close_on_free;
    case VS_BIO_CTRL_SET_CLOSE:
        bio->close_on_free = (int)(value & 1);
        return 1;
    default:
        VITALS_LOG("bio %p ctrl %d %ld %p ignored", (void *)bio, command, value, pointer);
        return 0;
    }
}

/* ---- connections ---- */

/* NID 0xD28834E6, Sony 0x81019741: SSL_new; NULL when it fails */
void *sceSslInternalNew(void *handle)
{
    VsContext *context = handle;
    if (!is_context(context))
        return NULL;
    VsSsl *ssl = calloc(1, sizeof(*ssl));
    if (ssl == NULL) {
        vs_note_out_of_memory();
        return NULL;
    }
    ssl->magic = SSL_MAGIC;
    vs_lock();
    ++context->references;
    vs_unlock();
    ssl->context = context;
    mbedtls_ssl_init(&ssl->tls);
    mbedtls_ssl_config_init(&ssl->config);
    return ssl;
}

/* SSL_set_bio's and SSL_free's: a BIO used both ways is freed once */
static void free_bios(VsSsl *ssl)
{
    if (ssl->rbio != NULL && ssl->rbio != ssl->wbio)
        bio_free(ssl->rbio);
    bio_free(ssl->wbio);
    ssl->rbio = ssl->wbio = NULL;
}

/* NID 0x19B2BB58, Sony 0x81019397: SSL_free, with its BIOs, as OpenSSL's */
void sceSslInternalFree(void *handle)
{
    VsSsl *ssl = handle;
    if (!is_ssl(ssl))
        return;
    mbedtls_ssl_free(&ssl->tls);
    mbedtls_ssl_config_free(&ssl->config);
    if (ssl->client_cert != NULL)
        (void)sceSslInternalCertFree(ssl->client_cert);
    if (ssl->client_key != NULL)
        (void)sceSslInternalKeyFree(ssl->client_key);
    free_bios(ssl);
    context_release(ssl->context);
    mbedtls_platform_zeroize(ssl, sizeof(*ssl));
    free(ssl);
}

/* NID 0x0DB6C206, Sony 0x81019BB1: SSL_set_options, which only adds bits */
uint32_t sceSslInternalSetOptions(void *handle, uint32_t options)
{
    VsSsl *ssl = handle;
    if (!is_ssl(ssl))
        return 0;
    ssl->options |= options;
    return ssl->options;
}

/* NID 0x4A1557A7, Sony 0x81019A15: SSL_set_bio; the BIOs it replaces are freed */
void sceSslInternalSetBio(void *handle, void *read_bio, void *write_bio)
{
    VsSsl *ssl = handle;
    if (!is_ssl(ssl))
        return;
    if (ssl->rbio != read_bio || ssl->wbio != write_bio) {
        if (ssl->rbio != read_bio && ssl->rbio != write_bio && ssl->rbio != ssl->wbio)
            bio_free(ssl->rbio);
        if (ssl->wbio != read_bio && ssl->wbio != write_bio)
            bio_free(ssl->wbio);
    }
    ssl->rbio = read_bio;
    ssl->wbio = write_bio;
}

/* NID 0xF2C9B744, Sony 0x8101B08B: SSL_set_info_callback; called for alerts */
void sceSslInternalSetInfoCallback(void *handle, VsInfoCallback callback)
{
    VsSsl *ssl = handle;
    if (is_ssl(ssl))
        ssl->info_callback = callback;
}

/* NID 0xF71DB06F, Sony 0x8101B097: a callback and its argument, kept (Sony's libhttp gives one
 * that does nothing) */
void sceSslInternalSetCallback(void *handle, void *callback, void *argument)
{
    VsSsl *ssl = handle;
    if (is_ssl(ssl)) {
        ssl->message_callback = callback;
        ssl->message_argument = argument;
    }
}

/* NID 0xCEE46B33, Sony 0x8101AE2D: SSL_set_connect_state */
void sceSslInternalSetConnectState(void *handle)
{
    VsSsl *ssl = handle;
    if (is_ssl(ssl))
        ssl->connecting = 1;
}

/* The socket BIO's send and receive, as Sony's: SceNet's errno cleared first, and what the socket
 * returned kept for the caller when it failed */
static int tls_send(void *context, const unsigned char *data, size_t size)
{
    VsSsl *ssl = context;
    if (!is_bio(ssl->wbio) || !ssl->wbio->has_fd)
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    vs_platform_clear_net_errno();
    int result = sceNetSend(ssl->wbio->fd, data, (unsigned int)size, 0);
    if (result > 0)
        return result;
    if (result == 0) {
        ssl->failure = VS_FAILED_SEND_ZERO;
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    ssl->failure = VS_FAILED_SEND;
    ssl->socket_result = result;
    return result == (int)VS_NET_ERROR_EAGAIN ? MBEDTLS_ERR_SSL_WANT_WRITE : MBEDTLS_ERR_NET_SEND_FAILED;
}

static int tls_recv(void *context, unsigned char *data, size_t size)
{
    VsSsl *ssl = context;
    if (!is_bio(ssl->rbio) || !ssl->rbio->has_fd)
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    vs_platform_clear_net_errno();
    int result = sceNetRecv(ssl->rbio->fd, data, (unsigned int)size, 0);
    if (result >= 0)
        return result;
    ssl->failure = VS_FAILED_RECEIVE;
    ssl->socket_result = result;
    return result == (int)VS_NET_ERROR_EAGAIN ? MBEDTLS_ERR_SSL_WANT_READ : MBEDTLS_ERR_NET_RECV_FAILED;
}

/* Whether the server's certificate names the address (an IP address entry in subjectAltName) */
static int names_address(const mbedtls_x509_crt *certificate, const unsigned char address[4])
{
    for (const mbedtls_x509_sequence *entry = &certificate->subject_alt_names; entry != NULL && entry->buf.p != NULL;
         entry = entry->next) {
        mbedtls_x509_subject_alternative_name name;
        if (mbedtls_x509_parse_subject_alt_name(&entry->buf, &name) != 0)
            continue;
        int same = name.type == MBEDTLS_X509_SAN_IP_ADDRESS && name.san.unstructured_name.len == 4 &&
                   memcmp(name.san.unstructured_name.p, address, 4) == 0;
        mbedtls_x509_free_subject_alt_name(&name);
        if (same)
            return 1;
    }
    return 0;
}

static int verify_certificate(void *context, mbedtls_x509_crt *certificate, int depth, uint32_t *flags)
{
    VsSsl *ssl = context;
    (void)vs_trust_exact_self_signed(NULL, certificate, depth, flags);
    if (depth == 0 && ssl->check_address && !names_address(certificate, ssl->address))
        *flags |= MBEDTLS_X509_BADCERT_CN_MISMATCH;
    return 0;
}

/* No roots for Mbed TLS when the verify callback decides: it looks them up itself */
static int no_issuers(void *context, const mbedtls_x509_crt *child, mbedtls_x509_crt **candidates)
{
    (void)context, (void)child;
    *candidates = NULL;
    return 0;
}

/* Mbed TLS's flags for the callback's reason, which pick the alert (Sony's map is in the README) */
static uint32_t refused_flags(int reason)
{
    switch (reason) {
    case 3:
        return MBEDTLS_X509_BADCERT_FUTURE;
    case 4:
        return MBEDTLS_X509_BADCERT_EXPIRED;
    case 8:
        return MBEDTLS_X509_BADCERT_REVOKED;
    default:
        return MBEDTLS_X509_BADCERT_OTHER;
    }
}

#define MAX_CHAIN 16

/* With a verify callback: Mbed TLS's own findings are dropped, and once it has the server's chain
 * (depth 0 is called last) the callback decides, as Sony's calls it, with the certificates as the
 * server sent them */
static int verify_with_callback(void *context, mbedtls_x509_crt *certificate, int depth, uint32_t *flags)
{
    VsSsl *ssl = context;
    *flags = 0;
    if (depth > 0)
        return 0;
    VsCert *certs = calloc(MAX_CHAIN, sizeof(*certs));
    void *handles[MAX_CHAIN];
    if (certs == NULL) {
        vs_note_out_of_memory();
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    }
    int count = 0;
    for (mbedtls_x509_crt *crt = certificate; crt != NULL && crt->raw.p != NULL && count < MAX_CHAIN; crt = crt->next) {
        vs_cert_borrow(&certs[count], crt);
        handles[count] = &certs[count];
        ++count;
    }
    vs_certificate_lookups_reset();
    ssl->verify_result = 0;
    /* libhttp's argument: the flags, then the host name its check compares */
    const char *const *argument = ssl->context->verify_argument;
    VITALS_LOG("ssl %p verify flags=%08X host %p %.64s", (void *)ssl,
               argument != NULL ? (unsigned int)(uintptr_t)argument[0] : 0u,
               argument != NULL ? (const void *)argument[1] : NULL,
               argument != NULL && argument[1] != NULL ? argument[1] : "-");
    (void)argument;
    int accepted = ssl->context->verify_callback(ssl, handles, count, ssl->context->verify_argument,
                                                 &ssl->verify_result);
    vs_certificate_lookups_reset();
    for (int i = 0; i < count; ++i)
        vs_cert_return(&certs[i]);
    free(certs);
    VITALS_LOG("ssl %p verify callback %d reason=%d chain=%d", (void *)ssl, accepted, ssl->verify_result, count);
    if (!accepted)
        *flags = refused_flags(ssl->verify_result);
    return 0;
}

/* The server asked for a certificate: the context's client certificate callback picks one, as
 * Sony's calls it, from the CA names the server gave (each a 2-byte length, then a DER Name);
 * libhttp's gives the certificate sceHttpsLoadCert loaded when one of them is its issuer. Without
 * one Mbed TLS sends none */
static int certificate_request(void *context, mbedtls_ssl_context *tls, const unsigned char *names, size_t length)
{
    VsSsl *ssl = context;
    VsClientCertCallback callback = ssl->context->client_cert_callback;
    if (callback == NULL)
        return 0;
    int count = 0;
    for (size_t at = 0; at + 2 <= length;) {
        size_t size = ((size_t)names[at] << 8) | names[at + 1];
        if (size > length - at - 2)
            break;
        at += 2 + size;
        ++count;
    }
    void **parsed = count > 0 ? calloc((size_t)count, sizeof(*parsed)) : NULL;
    if (count > 0 && parsed == NULL) {
        vs_note_out_of_memory();
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }
    int kept = 0;
    for (size_t at = 0; kept < count && at + 2 <= length;) {
        size_t size = ((size_t)names[at] << 8) | names[at + 1];
        mbedtls_x509_buf raw = {MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE, size, (unsigned char *)names + at + 2};
        void *name = vs_name_new(&raw);
        if (name != NULL)
            parsed[kept++] = name;
        at += 2 + size;
    }
    ssl->ca_names = parsed;
    ssl->ca_name_count = kept;
    void *cert = NULL, *key = NULL;
    int chosen = callback(ssl, &cert, &key);
    ssl->ca_names = NULL;
    ssl->ca_name_count = 0;
    for (int i = 0; i < kept; ++i)
        vs_name_free(parsed[i]);
    free(parsed);
    const mbedtls_x509_crt *crt = vs_certificate(cert);
    mbedtls_pk_context *pk = vs_key(key);
    VITALS_LOG("ssl %p certificate request names=%d chosen=%d", (void *)ssl, kept, chosen);
    if (chosen != 1 || crt == NULL || pk == NULL) {
        if (cert != NULL)
            (void)sceSslInternalCertFree(cert);
        if (key != NULL)
            (void)sceSslInternalKeyFree(key);
        return 0;
    }
    /* The connection keeps them for the handshake, which uses them until it ends */
    if (ssl->client_cert != NULL)
        (void)sceSslInternalCertFree(ssl->client_cert);
    if (ssl->client_key != NULL)
        (void)sceSslInternalKeyFree(ssl->client_key);
    ssl->client_cert = cert;
    ssl->client_key = key;
    return mbedtls_ssl_set_hs_own_cert(tls, (mbedtls_x509_crt *)crt, pk);
}

/* Mbed TLS for one connection, on its first connect: TLS 1.2 to 1.3, the host name the read BIO
 * carries as SNI and for the certificate check; an IPv4 address isn't sent, as Sony's */
static int setup(VsSsl *ssl)
{
    if (ssl->ready)
        return 0;
    int result = mbedtls_ssl_config_defaults(&ssl->config, MBEDTLS_SSL_IS_CLIENT,
                                             MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (result != 0)
        return result;
    /* As vitals-http: SHA-1 signatures stay allowed for Sony's own servers */
    ssl->profile = mbedtls_x509_crt_profile_default;
    ssl->profile.allowed_mds |= MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA1);
    mbedtls_ssl_conf_cert_profile(&ssl->config, &ssl->profile);
    mbedtls_ssl_conf_rng(&ssl->config, vs_tls_random, NULL);
    mbedtls_ssl_conf_min_tls_version(&ssl->config, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&ssl->config, MBEDTLS_SSL_VERSION_TLS1_3);
    int verify = ssl->context->verify_mode & 1;
    mbedtls_ssl_conf_authmode(&ssl->config, verify ? MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_NONE);
    if (verify && ssl->context->verify_callback != NULL) {
        mbedtls_ssl_conf_ca_cb(&ssl->config, no_issuers, NULL);
        mbedtls_ssl_conf_verify(&ssl->config, verify_with_callback, ssl);
    } else if (verify) {
        mbedtls_ssl_conf_ca_cb(&ssl->config, vs_find_trusted_issuers, NULL);
        mbedtls_ssl_conf_verify(&ssl->config, verify_certificate, ssl);
    }
    if (ssl->context->client_cert_callback != NULL)
        mbedtls_ssl_conf_cert_request_cb(&ssl->config, certificate_request, ssl);
    result = mbedtls_ssl_setup(&ssl->tls, &ssl->config);
    if (result != 0)
        return result;
    const char *host = is_bio(ssl->rbio) ? ssl->rbio->host : NULL;
    /* The firmware's libhttp gives none with BIO_ctrl (the one read for this gives its check's
     * host name, command 100): its verify callback's argument has it, the flags then the name */
    if (host == NULL && ssl->context->verify_callback != NULL && ssl->context->verify_argument != NULL) {
        host = ((const char *const *)ssl->context->verify_argument)[1];
        VITALS_LOG("ssl %p host from the verify argument", (void *)ssl);
    }
    if (host != NULL && (strlen(host) >= 256 || host[0] == '\0'))
        host = NULL;
    ssl->check_address = host != NULL && vs_platform_parse_ipv4(host, ssl->address);
    /* NULL: no SNI, and no name for Mbed TLS to check */
    result = mbedtls_ssl_set_hostname(&ssl->tls, ssl->check_address ? NULL : host);
    if (result != 0)
        return result;
    mbedtls_ssl_set_bio(&ssl->tls, ssl, tls_send, tls_recv, NULL);
    ssl->ready = 1;
    VITALS_LOG("ssl %p host=%s verify=%d", (void *)ssl, host != NULL ? host : "-", verify);
    return 0;
}

static int out_of_memory(int result)
{
    return result == MBEDTLS_ERR_SSL_ALLOC_FAILED || result == MBEDTLS_ERR_X509_ALLOC_FAILED ||
           result == MBEDTLS_ERR_MPI_ALLOC_FAILED || result == MBEDTLS_ERR_PK_ALLOC_FAILED;
}

/* The caller's return for an Mbed TLS failure, with failure set for SSL_get_error */
static int failed(VsSsl *ssl, int result)
{
    if ((ssl->failure == VS_FAILED_RECEIVE || ssl->failure == VS_FAILED_SEND) &&
        (result == MBEDTLS_ERR_NET_RECV_FAILED || result == MBEDTLS_ERR_NET_SEND_FAILED ||
         result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE))
        return ssl->socket_result;
    if (ssl->failure == VS_FAILED_SEND_ZERO && result == MBEDTLS_ERR_SSL_WANT_WRITE)
        return 0;
    if (result == MBEDTLS_ERR_SSL_CONN_EOF) {
        ssl->failure = VS_FAILED_EOF;
        return 0;
    }
    if (result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        ssl->failure = VS_FAILED_CLOSED;
        ssl->close_notify = 1;
        return 0;
    }
    ssl->failure = VS_FAILED_TLS;
    ssl->tls_result = result;
    if (out_of_memory(result))
        vs_note_out_of_memory();
    /* An alert from the server, for the info callback (libhttp logs its number) */
    if (result == MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE && ssl->info_callback != NULL)
        ssl->info_callback(ssl, VS_CB_ALERT | VS_CB_READ,
                           (2 << 8) | (int)ssl->tls.MBEDTLS_PRIVATE(in_msg)[1]);
    return -1;
}

typedef struct Handshake {
    VsSsl *ssl;
    int result;
} Handshake;

static void handshake(void *argument)
{
    Handshake *run = argument;
    run->result = mbedtls_ssl_handshake(&run->ssl->tls);
}

static int connect_now(VsSsl *ssl)
{
    ssl->failure = VS_FAILED_NOTHING;
    if (!vs_initialized()) {
        ssl->failure = VS_FAILED_TLS;
        return -1;
    }
    int result = setup(ssl);
    if (result != 0)
        return failed(ssl, result);
    Handshake run = {ssl, 0};
    vs_platform_run_on_large_stack(handshake, &run);
    if (run.result != 0) {
        int returned = failed(ssl, run.result);
        if (ssl->failure == VS_FAILED_TLS)
            VITALS_LOG("ssl %p handshake failed %d flags=%08X", (void *)ssl, run.result,
                       (unsigned int)mbedtls_ssl_get_verify_result(&ssl->tls));
        return returned;
    }
    ssl->handshake_done = 1;
    VITALS_LOG("ssl %p connected %s %s", (void *)ssl, mbedtls_ssl_get_version(&ssl->tls),
               mbedtls_ssl_get_ciphersuite(&ssl->tls));
    return 1;
}

/* NID 0xE5EDD91B, Sony 0x8101ADCF: SSL_connect; 1 once connected */
int sceSslInternalConnect(void *handle)
{
    VsSsl *ssl = handle;
    if (!is_ssl(ssl))
        return -1;
    ssl->connecting = 1;
    return ssl->handshake_done ? 1 : connect_now(ssl);
}

/* NID 0x4F781BB6, Sony 0x81019B11: SSL_read; connects first if it hasn't */
int sceSslInternalRead(void *handle, void *buffer, int size)
{
    VsSsl *ssl = handle;
    if (!is_ssl(ssl) || buffer == NULL || size < 0)
        return -1;
    if (!ssl->handshake_done) {
        int connected = connect_now(ssl);
        if (connected <= 0)
            return connected;
    }
    if (size == 0)
        return 0;
    for (;;) {
        ssl->failure = VS_FAILED_NOTHING;
        int result = mbedtls_ssl_read(&ssl->tls, buffer, (size_t)size);
        if (result > 0)
            return result;
        if (result == 0)
            result = MBEDTLS_ERR_SSL_CONN_EOF;
        /* TLS 1.3's session tickets, read on the way to the data */
        if (result == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET)
            continue;
        return failed(ssl, result);
    }
}

/* NID 0xF39A49C6, Sony 0x81019B4B: SSL_write; all of the data, or the failure */
int sceSslInternalWrite(void *handle, const void *buffer, int size)
{
    VsSsl *ssl = handle;
    if (!is_ssl(ssl) || buffer == NULL || size < 0)
        return -1;
    if (!ssl->handshake_done) {
        int connected = connect_now(ssl);
        if (connected <= 0)
            return connected;
    }
    int written = 0;
    while (written < size) {
        ssl->failure = VS_FAILED_NOTHING;
        int result = mbedtls_ssl_write(&ssl->tls, (const unsigned char *)buffer + written,
                                       (size_t)(size - written));
        if (result <= 0)
            return written > 0 ? written : failed(ssl, result == 0 ? MBEDTLS_ERR_SSL_WANT_WRITE : result);
        written += result;
    }
    return written;
}

/* NID 0xEC9FAF42, Sony 0x81019B81: SSL_shutdown; sends close_notify once, and is 1 when the
 * server's has arrived too */
int sceSslInternalShutdown(void *handle)
{
    VsSsl *ssl = handle;
    if (!is_ssl(ssl))
        return -1;
    if (ssl->handshake_done && !ssl->close_sent) {
        ssl->close_sent = 1;
        (void)mbedtls_ssl_close_notify(&ssl->tls);
    }
    return ssl->close_notify ? 1 : 0;
}

/* NID 0x2F0FC3CD, Sony 0x8101ACC1: SSL_get_error, as Sony's: a TLS failure is 1; after a failed
 * receive 2 (any error, as Sony's socket BIO asks for a retry on each), after a send that sent
 * nothing 3; 0 returned after the server's close_notify is 6; anything else 5, a system error,
 * whose SceNet errno the caller reads */
int sceSslInternalGetError(void *handle, int returned)
{
    VsSsl *ssl = handle;
    if (returned > 0)
        return VS_KIND_NONE;
    if (!is_ssl(ssl))
        return VS_KIND_SSL;
    switch (ssl->failure) {
    case VS_FAILED_TLS:
        return VS_KIND_SSL;
    case VS_FAILED_RECEIVE:
        return returned < 0 ? VS_KIND_WANT_READ : VS_KIND_SYSCALL;
    case VS_FAILED_SEND_ZERO:
        return VS_KIND_WANT_WRITE;
    case VS_FAILED_CLOSED:
        return returned == 0 ? VS_KIND_ZERO_RETURN : VS_KIND_SYSCALL;
    default:
        return VS_KIND_SYSCALL;
    }
}

/* NID 0x24C6257F, Sony 0x81019995: an item of the connection by number: 1, 5 and 6 the Cert-C
 * objects certificate.c's functions take (one here), 2, 3, 4 and 7 nothing */
int sceSslInternalGetItem(void *handle, int item, const void **out)
{
    if (!is_ssl(handle) || out == NULL)
        return 10017;
    switch (item) {
    case 1:
    case 5:
    case 6:
        *out = vs_cert_library();
        return 0;
    case 2:
    case 3:
    case 4:
    case 7:
        *out = NULL;
        return 0;
    default:
        return 10011;
    }
}

/* NID 0xB0E4CB2F, Sony 0x8101AF8F: SSL_set_verify_result */
void sceSslInternalSetVerifyResult(void *handle, int result)
{
    VsSsl *ssl = handle;
    if (is_ssl(ssl))
        ssl->verify_result = result;
}

/* NID 0xA4EA9DE0, Sony 0x810163C5: how many CA names the server's certificate request gave, while
 * the client certificate callback runs; 0 otherwise */
int sceSslInternalGetCaNameCount(void *handle)
{
    VsSsl *ssl = handle;
    return is_ssl(ssl) ? ssl->ca_name_count : 0;
}

/* NID 0x243DE290, Sony 0x810163F7: one of them, as a name object the connection keeps */
int sceSslInternalGetCaName(void *handle, int index, void **name)
{
    VsSsl *ssl = handle;
    if (!is_ssl(ssl) || name == NULL)
        return 10017;
    if (index < 0 || index >= ssl->ca_name_count)
        return 10008;
    *name = ssl->ca_names[index];
    return 0;
}
