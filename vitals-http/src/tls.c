#include "vh.h"

#include "diagnostics.h"
#include "user_runtime.h"
#include "vitals/error_map.h"
#include "vitals_ssl.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* TLS 1.2 and 1.3 through vitals-ssl, built in: its connections over this library's transport,
 * the CA bundle's index and the app's own CA certificates, its exact trust of self-signed
 * certificates, and tls13-vita's mapping of certificate problems to libhttp's detail bits. Its
 * memory is the tls13-vita runtime's heap (user_runtime.c), not the app's pool.
 *
 * Sony's own connections (the ones with the private HTTPS option 0x40, as the shell's PSN
 * sign-in) get the console's own ClientHello (vitals-ssl's console profile), as a capture of a
 * working sign-in shows it. The CDN in front of PSN sign-in refuses handshakes that don't look
 * like a console's */

/* An app's size can't be larger than the TLS functions take at once */
#define VH_TLS_CHUNK 0x40000000u

struct VhTls
{
    void *ssl;
    VhTransport *transport;
    /* The transport's last error, which vitals-ssl only sees as a failed send or receive */
    int io_error;
    /* A client certificate and key were given to the connection */
    int has_own;
    /* The server's handshake records, for the debug log */
    VhRecordScan scan;
    char host[VH_HOST_MAX];
};

/* Set up on the first https connection, with the lock held: 1 once ready, negative when it failed */
static int g_state;
/* sceHttpsLoadCert's CA certificates, under the lock; each connection keeps the store it began with */
static void *g_store;
/* Its client certificate and key, as the app gave them (NUL-terminated); each connection parses
 * its own copy, so an unload during a handshake frees nothing it uses */
static unsigned char *g_client_certificate, *g_client_key;
static size_t g_client_certificate_size, g_client_key_size;

/* The heap, then vitals-ssl (Mbed TLS's platform and PSA, its random generator; it indexes the CA
 * bundle on the first check). With the lock held */
static int tls_ready(void)
{
    if (g_state != 0)
        return g_state;
    g_state = vh_platform_tls_init() == 0 && vitalsSslInitShared() == 0 ? 1 : -1;
    VITALS_LOG("tls ready rc=%d", g_state);
    return g_state;
}

/* The transport's bytes, or its error as it is, which connect, read and write give back */
static int bio_send(void *context, const unsigned char *data, size_t size)
{
    VhTls *tls = context;
    int sent = vh_transport_raw_send(tls->transport, data, size);
    if (sent < 0)
        tls->io_error = sent;
    return sent;
}

static int bio_recv(void *context, unsigned char *data, size_t size)
{
    VhTls *tls = context;
    int received = vh_transport_raw_recv(tls->transport, data, size);
    if (received < 0) {
        tls->io_error = received;
        return received;
    }
    vh_record_scan(&tls->scan, data, (size_t)received);
    return received;
}

/* Handshake messages, across records: their 4-byte headers are read, their bodies skipped */
static void scan_handshake(VhRecordScan *scan, const unsigned char *data, size_t size)
{
    for (size_t at = 0; at < size;) {
        if (scan->message_left != 0) {
            size_t skip = size - at < scan->message_left ? size - at : scan->message_left;
            at += skip;
            scan->message_left -= (unsigned int)skip;
            continue;
        }
        scan->message[scan->message_have++] = data[at++];
        if (scan->message_have == 4) {
            /* 13: CertificateRequest */
            if (scan->message[0] == 13)
                scan->certificate_request = 1;
            scan->message_left = (unsigned int)scan->message[1] << 16 | (unsigned int)scan->message[2] << 8 | scan->message[3];
            scan->message_have = 0;
        }
    }
}

void vh_record_scan(VhRecordScan *scan, const unsigned char *data, size_t size)
{
    for (size_t at = 0; at < size && !scan->done;) {
        if (scan->record_left == 0) {
            scan->header[scan->header_have++] = data[at++];
            if (scan->header_have == 5) {
                scan->header_have = 0;
                scan->record_type = scan->header[0];
                scan->record_left = (unsigned int)scan->header[3] << 8 | scan->header[4];
                /* 20: ChangeCipherSpec */
                if (scan->record_type == 20)
                    scan->done = 1;
            }
            continue;
        }
        size_t take = size - at < scan->record_left ? size - at : scan->record_left;
        /* 22: handshake */
        if (scan->record_type == 22)
            scan_handshake(scan, data + at, take);
        at += take;
        scan->record_left -= (unsigned int)take;
    }
}

/* An error of the TLS layer as the app sees it: the transport's own when it had one */
static int tls_error(VhTls *tls)
{
    if (vh_transport_aborted(tls->transport))
        return (int)SCE_HTTP_ERROR_ABORTED;
    return tls->io_error != 0 ? tls->io_error : (int)SCE_HTTP_ERROR_SSL;
}

/* An outcome stored as the connection's SSL error, through tls13-vita's mapping */
static int store_outcome(VitalsOutcome outcome, uint32_t detail, int *ssl_error, unsigned int *ssl_detail)
{
    VitalsMappedError mapped = vitals_map_outcome(outcome, detail);
    *ssl_error = mapped.ssl_error;
    *ssl_detail = mapped.detail;
    return mapped.hook_result;
}

void vh_tls_close(VhTls *tls)
{
    if (tls == NULL)
        return;
    sceSslInternalFree(tls->ssl);
    memset(tls, 0, sizeof(*tls));
    free(tls);
}

/* The client certificate and key sceHttpsLoadCert gave, for servers that ask for one; 0 when there
 * are none, or the parser's error */
static int own_identity(VhTls *tls, void *context)
{
    int result = 0;
    vh_lock();
    if (g_client_certificate != NULL && g_client_key != NULL) {
        tls->has_own = 1;
        result = vitalsSslCtxSetIdentity(context, g_client_certificate, g_client_certificate_size, g_client_key,
                                         g_client_key_size);
    }
    vh_unlock();
    if (tls->has_own)
        VITALS_LOG("client certificate host=%s rc=%08X", tls->host, (unsigned int)result);
    return result;
}

/* A connection of vitals-ssl over the transport, verified, but decided after the handshake from the
 * HTTPS options and the app's callback: 0, or the parser's or SSL's error (-1 for memory) */
static int setup(VhTls *tls, int console)
{
    void *library = NULL;
    if (sceSslInternalGetLibrary(&library) != 0)
        return -1;
    void *context = sceSslInternalCtxNew(library, sceSslInternalClientMethod());
    if (context == NULL)
        return -1;
    sceSslInternalCtxSetVerify(context, 1);
    int result = vitalsSslCtxSetDeferredVerify(context, 1);
    if (result == 0)
        result = vitalsSslCtxSetProfile(context, console ? VITALS_SSL_PROFILE_CONSOLE : VITALS_SSL_PROFILE_MODERN);
    if (result == 0) {
        vh_lock();
        result = vitalsSslCtxSetStore(context, g_store);
        vh_unlock();
    }
    if (result == 0)
        result = own_identity(tls, context);
    if (result == 0) {
        tls->ssl = sceSslInternalNew(context);
        if (tls->ssl == NULL)
            result = -1;
    }
    /* The connection keeps the context */
    sceSslInternalCtxFree(context);
    if (result != 0)
        return result;
    void *bio = vitalsSslBioNew(bio_send, bio_recv, tls);
    if (bio == NULL)
        return -1;
    (void)sceSslInternalBioCtrl(bio, VITALS_SSL_BIO_SET_HOST, 0, tls->host);
    sceSslInternalSetBio(tls->ssl, bio, bio);
    sceSslInternalSetConnectState(tls->ssl);
    return 0;
}

#if VITALS_DEBUG >= 1
/* For the debug log: in TLS 1.3 the request is encrypted, so only vitals-ssl sees it */
static const char *client_certificate_asked(VhTls *tls)
{
    if (tls->scan.certificate_request || vitalsSslCertificateRequested(tls->ssl))
        return "yes";
    if (strcmp(vitalsSslGetVersion(tls->ssl), "TLSv1.2") == 0 && tls->scan.done)
        return "no";
    return "unknown";
}
#endif

int vh_tls_start(VhTls **out, VhTransport *transport, const VhOpen *open, int *ssl_error, unsigned int *ssl_detail)
{
    *out = NULL;
    *ssl_error = 0;
    *ssl_detail = 0;
    vh_lock();
    int ready = tls_ready();
    vh_unlock();
    VhTls *tls = ready > 0 ? calloc(1, sizeof(*tls)) : NULL;
    if (tls == NULL)
        return store_outcome(ready > 0 ? VITALS_OUTCOME_NO_MEMORY : VITALS_OUTCOME_INTERNAL, 0, ssl_error, ssl_detail);
    tls->transport = transport;
    /* An IPv6 address loses its brackets */
    size_t length = strlen(open->host);
    if (length >= 2 && open->host[0] == '[' && open->host[length - 1] == ']') {
        memcpy(tls->host, open->host + 1, length - 2);
        tls->host[length - 2] = '\0';
    } else
        memcpy(tls->host, open->host, length + 1);

    int console = (open->https_options & VITALS_SCE_HTTPS_OPTION_PRIVATE_CHAIN) != 0;
    int result = setup(tls, console);
    if (result != 0) {
        VITALS_LOG("tls setup failed host=%s tls=%08X", tls->host, (unsigned int)result);
        vh_tls_close(tls);
        return store_outcome(result == -1 || vitalsSslTlsErrorIsMemory(result) ? VITALS_OUTCOME_NO_MEMORY
                                                                               : VITALS_OUTCOME_INTERNAL,
                             (uint32_t)result, ssl_error, ssl_detail);
    }
    VITALS_VERBOSE("handshake start %s profile=%s", tls->host, console ? "console" : "modern");
    int connected = sceSslInternalConnect(tls->ssl);
    /* For the log */
    uint32_t verify = vitalsSslGetVerifyResult(tls->ssl);
    (void)verify;
    if (connected != 1) {
        int error = vitalsSslGetTlsError(tls->ssl);
        uint32_t found = vitalsSslGetCertificateFlags(tls->ssl);
        VITALS_LOG("handshake failed host=%s client_cert_asked=%s", tls->host, client_certificate_asked(tls));
        VITALS_LOG("handshake failed host=%s tls=%08X io=%08X verify=%08X", tls->host, (unsigned int)error,
                   (unsigned int)tls->io_error, (unsigned int)verify);
        if (found != 0)
            result = store_outcome(VITALS_OUTCOME_CERTIFICATE, vitals_filter_certificate_flags(found, open->https_options),
                                   ssl_error, ssl_detail);
        else if (vitalsSslTlsErrorIsMemory(error))
            result = store_outcome(VITALS_OUTCOME_NO_MEMORY, (uint32_t)error, ssl_error, ssl_detail);
        else
            result = store_outcome(tls->io_error != 0 ? VITALS_OUTCOME_IO : VITALS_OUTCOME_HANDSHAKE, (uint32_t)error,
                                   ssl_error, ssl_detail);
        if (tls->io_error != 0 || vh_transport_aborted(transport))
            result = tls_error(tls);
        vh_tls_close(tls);
        vitals_user_runtime_report("handshake failed", 1);
        return result;
    }

    /* Only the checks the options ask for; the app's callback can accept the rest */
    uint32_t flags = vitals_filter_certificate_flags(vitalsSslGetCertificateFlags(tls->ssl), open->https_options);
    uint32_t detail = vitals_map_certificate_detail(flags);
    if (detail != 0) {
        /* As with the HTTP provider, the callback gets the problems and no certificates */
        void *const no_certificates[1] = {NULL};
        int accepted = open->ssl_callback != NULL &&
                       open->ssl_callback(detail, no_certificates, 0, open->ssl_argument) >= 0;
        VITALS_LOG("certificate host=%s verify=%08X detail=%02X accepted=%d", tls->host, (unsigned int)verify,
                   (unsigned int)detail, accepted);
        if (!accepted) {
            vh_tls_close(tls);
            return store_outcome(VITALS_OUTCOME_CERTIFICATE, flags, ssl_error, ssl_detail);
        }
    }
    VITALS_LOG("handshake ok host=%s %s %s profile=%s options=%03X callback=%d client_cert_asked=%s sent=%d",
               tls->host, vitalsSslGetVersion(tls->ssl), vitalsSslGetCiphersuite(tls->ssl),
               console ? "console" : "modern", (unsigned int)open->https_options, open->ssl_callback != NULL,
               client_certificate_asked(tls), tls->has_own);
    /* The heap's peak, when it has grown */
    vitals_user_runtime_report("handshake", 0);
    *out = tls;
    return 0;
}

int vh_tls_send(VhTls *tls, const void *data, size_t size)
{
    const unsigned char *at = data;
    while (size > 0) {
        int chunk = (int)(size > VH_TLS_CHUNK ? VH_TLS_CHUNK : size);
        int sent = sceSslInternalWrite(tls->ssl, at, chunk);
        if (sent <= 0)
            return tls_error(tls);
        at += sent;
        size -= (size_t)sent;
    }
    return 0;
}

int vh_tls_recv(VhTls *tls, void *data, size_t size)
{
    tls->io_error = 0;
    /* TLS 1.3's session tickets are read through on the way to the data */
    int received = sceSslInternalRead(tls->ssl, data, (int)(size > VH_TLS_CHUNK ? VH_TLS_CHUNK : size));
    if (received > 0)
        return received;
    /* close_notify, or a server that closes without it, both end the response */
    if (received == 0)
        return 0;
    VITALS_VERBOSE("tls read host=%s rc=%08X io=%08X", tls->host, (unsigned int)received, (unsigned int)tls->io_error);
    return tls_error(tls);
}

/* ---- sceHttpsLoadCert ---- */

/* Wipes a secret before it is freed: through a volatile pointer, which the compiler can't drop */
static void wipe(void *data, size_t size)
{
    volatile unsigned char *at = data;
    while (size-- > 0)
        *at++ = 0;
}

/* A copy of the app's data, NUL-terminated; NULL when there is none or memory ran out */
static unsigned char *copy_data(const SceHttpsData *data, size_t *size)
{
    if (data == NULL || data->ptr == NULL || data->size == 0)
        return NULL;
    unsigned char *copy = malloc((size_t)data->size + 1u);
    if (copy != NULL) {
        memcpy(copy, data->ptr, data->size);
        copy[data->size] = '\0';
        *size = data->size;
    }
    return copy;
}

static void free_client(void)
{
    if (g_client_key != NULL)
        wipe(g_client_key, g_client_key_size);
    free(g_client_certificate);
    free(g_client_key);
    g_client_certificate = g_client_key = NULL;
    g_client_certificate_size = g_client_key_size = 0;
}

static void release_store(void)
{
    vitalsSslStoreRelease(g_store);
    g_store = NULL;
}

/* As Sony's: it replaces everything loaded before. The CA certificates must all parse; the client
 * certificate and key are checked here too, and refused when they don't, with the reason logged */
int vh_tls_load_certs(int count, const SceHttpsData **list, const SceHttpsData *cert, const SceHttpsData *key)
{
    if (tls_ready() < 0)
        return (int)SCE_HTTP_ERROR_SSL;
    void *store = count > 0 ? vitalsSslStoreNew() : NULL;
    if (count > 0 && store == NULL)
        return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
    for (int i = 0; i < count; ++i) {
        int parsed = list[i] != NULL && list[i]->ptr != NULL && list[i]->size != 0
                         ? vitalsSslStoreAdd(store, list[i]->ptr, list[i]->size)
                         : -1;
        if (parsed != 0) {
            VITALS_LOG("load cert: CA %d of %d unreadable rc=%08X", i + 1, count, (unsigned int)parsed);
            vitalsSslStoreRelease(store);
            return (int)SCE_HTTP_ERROR_INVALID_VALUE;
        }
    }

    size_t certificate_size = 0, key_size = 0;
    unsigned char *certificate = copy_data(cert, &certificate_size);
    unsigned char *private_key = copy_data(key, &key_size);
    int result = 0;
    if ((cert != NULL && certificate == NULL) || (key != NULL && private_key == NULL))
        result = (int)SCE_HTTP_ERROR_INVALID_VALUE;
    else if (certificate != NULL || private_key != NULL) {
        /* Parsed once now, so a bad one is told at once rather than at every handshake */
        int certificate_rc = certificate != NULL ? vitalsSslCheckCertificate(certificate, certificate_size) : -1;
        int key_rc = private_key != NULL ? vitalsSslCheckKey(private_key, key_size) : -1;
        VITALS_LOG("load cert: client certificate %u bytes rc=%08X, key %u bytes rc=%08X",
                   (unsigned int)certificate_size, (unsigned int)certificate_rc, (unsigned int)key_size,
                   (unsigned int)key_rc);
        if (certificate_rc != 0 || key_rc != 0)
            result = (int)SCE_HTTP_ERROR_INVALID_VALUE;
    }
    if (result < 0) {
        if (private_key != NULL)
            wipe(private_key, key_size);
        free(certificate);
        free(private_key);
        vitalsSslStoreRelease(store);
        return result;
    }
    release_store();
    g_store = store;
    free_client();
    g_client_certificate = certificate;
    g_client_certificate_size = certificate_size;
    g_client_key = private_key;
    g_client_key_size = key_size;
    VITALS_LOG("loaded %d CA certificates, client certificate %s", count,
               certificate != NULL && private_key != NULL ? "yes" : "no");
    return 0;
}

void vh_tls_unload_certs(void)
{
    release_store();
    free_client();
}

/* A copy of size bytes, NUL-terminated for PEM; NULL when there are none or memory ran out */
static unsigned char *copy_bytes(const void *data, unsigned int size)
{
    const SceHttpsData given = {(char *)(uintptr_t)data, size};
    size_t copied = 0;
    return copy_data(&given, &copied);
}

/* Sony's keeps whatever it is given and fails at its use; one that doesn't parse can't be used
 * here either, so it is left out, with the reason logged */
int vh_tls_add_ca(const void *data, unsigned int size)
{
    if (tls_ready() < 0)
        return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
    if (data == NULL || size == 0)
        return 0;
    if (g_store == NULL && (g_store = vitalsSslStoreNew()) == NULL)
        return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
    int parsed = vitalsSslStoreAdd(g_store, data, size);
    if (vitalsSslTlsErrorIsMemory(parsed))
        return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
    if (parsed != 0)
        VITALS_LOG("private CA certificate of %u bytes unreadable rc=%08X: not trusted", size, (unsigned int)parsed);
    return 0;
}

void vh_tls_clear_cas(void)
{
    release_store();
}

/* Each replaces the one before, and nothing (no data, or none of it) leaves none; the pair is used
 * once both are there, as sceHttpsLoadCert's */
static int set_client_part(unsigned char **slot, size_t *slot_size, const void *data, unsigned int size, int secret)
{
    if (tls_ready() < 0)
        return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
    unsigned char *copy = NULL;
    if (data != NULL && size != 0 && (copy = copy_bytes(data, size)) == NULL)
        return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
    if (secret && *slot != NULL)
        wipe(*slot, *slot_size);
    free(*slot);
    *slot = copy;
    *slot_size = copy != NULL ? size : 0;
    return 0;
}

int vh_tls_set_client_certificate(const void *data, unsigned int size)
{
    return set_client_part(&g_client_certificate, &g_client_certificate_size, data, size, 0);
}

int vh_tls_set_client_key(const void *data, unsigned int size)
{
    return set_client_part(&g_client_key, &g_client_key_size, data, size, 1);
}

void vh_tls_clear_client(void)
{
    free_client();
}
