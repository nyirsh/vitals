#include "vh.h"

#include "diagnostics.h"
#include "user_runtime.h"
#include "vitals/error_map.h"
#include "vitals_ssl.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* TLS 1.2 and 1.3 through vitals-ssl, the libssl module, as Sony's libhttp goes through Sony's: its
 * connections over this library's transport, the CA bundle's index and the app's own CA
 * certificates, its exact trust of self-signed certificates, and tls13-vita's mapping of
 * certificate problems to libhttp's detail bits. Its memory is the pool the app gave sceSslInit;
 * without one, as with Sony's, there is no https. (The host tests build vitals-ssl in.)
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
/* sceHttpsLoadCert's CA certificates, as the app gave them, under the lock. As Sony's, loading them
 * keeps them and nothing more: libssl, which may not be in the process, reads them when an https
 * connection starts, into the store, which is made again when they change (g_store_made). Each
 * connection keeps the store it began with */
typedef struct VhCa
{
    struct VhCa *next;
    size_t size;
    unsigned char data[];
} VhCa;
static VhCa *g_cas;
static unsigned int g_cas_changed;
static void *g_store;
static unsigned int g_store_made;
/* Its client certificate and key, as the app gave them (NUL-terminated); each connection parses
 * its own copy, so an unload during a handshake frees nothing it uses */
static unsigned char *g_client_certificate, *g_client_key;
static size_t g_client_certificate_size, g_client_key_size;

/* The heap for what this library keeps; with the lock held */
static int tls_ready(void)
{
    if (g_state != 0)
        return g_state;
    g_state = vh_platform_tls_init() == 0 ? 1 : -1;
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

/* The store of the loaded CA certificates, made again when they changed; NULL when there are none
 * or memory ran out. With the lock held and libssl set up */
static void *current_store(void)
{
    if (g_store_made == g_cas_changed)
        return g_store;
    if (g_store != NULL)
        vitalsSslStoreRelease(g_store);
    g_store = NULL;
    g_store_made = g_cas_changed;
    if (g_cas == NULL || (g_store = vitalsSslStoreNew()) == NULL)
        return g_store;
    for (const VhCa *ca = g_cas; ca != NULL; ca = ca->next) {
        int parsed = vitalsSslStoreAdd(g_store, ca->data, ca->size);
        if (parsed != 0)
            VITALS_LOG("loaded CA certificate of %u bytes unreadable rc=%08X: not trusted", (unsigned int)ca->size,
                       (unsigned int)parsed);
    }
    return g_store;
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
    /* One that doesn't parse is left out, as no client certificate */
    if (result != 0 && !vitalsSslTlsErrorIsMemory(result)) {
        tls->has_own = 0;
        result = 0;
    }
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
        result = vitalsSslCtxSetStore(context, current_store());
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
    /* As Sony's: libssl must be the app's, set up with sceSslInit. Only https calls it: in a process
     * without it, the import points at the libssl another process loaded (the module is shared) */
    int ssl_state = sceSslInternalIsInitalized();
    if (ssl_state != 0) {
        VITALS_LOG("tls host=%s: libssl not initialized rc=%08X", open->host, (unsigned int)ssl_state);
        return store_outcome(VITALS_OUTCOME_INTERNAL, (uint32_t)ssl_state, ssl_error, ssl_detail);
    }
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

/* ---- libhttp's certificate check, on a libssl context another module made ---- */

/* The argument libhttp's check takes (sceHttpPrivateSslContextAddCertCheck's), in Sony's layout:
 * on the Vita flags at 0, the host name at 4, where the SCE result and the SCE_HTTPS_ERROR_SSL_*
 * bits go at 8 and 12, the app's callback and its argument at 16 and 20, and a lock its caller
 * gives at 40 and 44 */
typedef struct VhCertCheck
{
    uint32_t flags;
    const char *host;
    int *result;
    unsigned int *bits;
    int (*callback)(unsigned int bits, void *const certificates[], int count, void *argument);
    void *argument;
    void *reserved[4];
    int (*lock)(void *argument);
    int (*unlock)(void *argument);
} VhCertCheck;

/* Sony's flags when the caller gives none: server verify, CN check, known CA, and its CA lookup */
#define VH_CERT_CHECK_DEFAULT 0x65u
/* The caller's lock is taken around the check */
#define VH_CERT_CHECK_LOCKED 0x40000000u
/* The SCE result of a refused certificate */
#define VH_CERT_CHECK_REFUSED ((int)0x80435806)
/* The reason a refusal gives libssl, which picks the alert (handshake_failure) */
#define VH_CERT_CHECK_REASON 10

/* As Sony's libhttp's (0x81014592), called by libssl for the server's chain: the checks the flags
 * ask for, on the bundle and the certificates the app loaded, then the app's callback, which
 * decides when there is one (it accepts what was found unless it returns a negative), as with this
 * library's own connections */
static int cert_check(void *ssl, void *certificates[], int count, void *argument, int *reason)
{
    VhCertCheck *check = argument;
    uint32_t options = check != NULL && check->flags != 0 ? check->flags : VH_CERT_CHECK_DEFAULT;
    int locked = check != NULL && (check->flags & VH_CERT_CHECK_LOCKED) != 0 && check->lock != NULL &&
                 check->unlock != NULL;
    (void)ssl;
    if (locked)
        (void)check->lock(check->argument);
    uint32_t found = 0;
    if ((options & VITALS_SCE_HTTPS_OPTION_SERVER_VERIFY) != 0) {
        /* The store stays while it is read */
        vh_lock();
        found = vitalsSslCheckChain(certificates, count,
                                    (options & VITALS_SCE_HTTPS_OPTION_CN_CHECK) != 0 && check != NULL ? check->host
                                                                                                       : NULL,
                                    current_store());
        vh_unlock();
    }
    unsigned int bits = vitals_map_certificate_detail(vitals_filter_certificate_flags(found, options));
    if (locked)
        (void)check->unlock(check->argument);
    int accepted = bits == 0;
    if (check != NULL && check->callback != NULL)
        accepted = check->callback(bits, certificates, count, check->argument) >= 0;
    if (check != NULL && check->result != NULL)
        *check->result = accepted ? 0 : VH_CERT_CHECK_REFUSED;
    if (check != NULL && check->bits != NULL)
        *check->bits = bits;
    *reason = accepted ? 0 : VH_CERT_CHECK_REASON;
    VITALS_LOG("cert check host=%s options=%08X found=%02X bits=%02X callback=%d accepted=%d",
               check != NULL && check->host != NULL ? check->host : "-", (unsigned int)options, (unsigned int)found, bits,
               check != NULL && check->callback != NULL, accepted);
    return accepted;
}

/* As Sony's: the verify mode on, and the check above in place of the bundle's; always 0. The context is
 * the libssl module's, another copy of vitals-ssl, of the same version (the two are installed
 * together), so its context is the same structure as this copy's */
int vh_tls_add_cert_check(void *context, void *argument)
{
    vh_lock();
    int ready = tls_ready();
    vh_unlock();
    /* Sony's succeeds whatever happens; without TLS here the check still reads the bundle */
    if (ready < 0)
        VITALS_LOG("cert check installed without tls");
    sceSslInternalCtxSetVerify(context, 1);
    sceSslInternalCtxSetCertVerifyCallback(context, cert_check, argument);
    return 0;
}

/* ---- sceHttpsLoadCert ---- */

/* Wipes a secret before it is freed: through a volatile pointer, which the compiler can't drop */
static void wipe(void *data, size_t size)
{
    volatile unsigned char *at = data;
    while (size-- > 0)
        *at++ = 0;
}

/* A copy of size bytes, NUL-terminated for PEM; NULL when there are none or memory ran out */
static unsigned char *copy_bytes(const void *data, size_t size)
{
    if (data == NULL || size == 0)
        return NULL;
    unsigned char *copy = malloc(size + 1u);
    if (copy != NULL) {
        memcpy(copy, data, size);
        copy[size] = '\0';
    }
    return copy;
}

static VhCa *ca_new(const void *data, size_t size)
{
    VhCa *ca = malloc(sizeof(*ca) + size + 1u);
    if (ca != NULL) {
        ca->next = NULL;
        ca->size = size;
        memcpy(ca->data, data, size);
        ca->data[size] = '\0';
    }
    return ca;
}

static void cas_free(VhCa *ca)
{
    while (ca != NULL) {
        VhCa *next = ca->next;
        free(ca);
        ca = next;
    }
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

/* A store was only made with libssl in the process (by an https connection), so it is released only
 * then */
static void release_cas(void)
{
    cas_free(g_cas);
    g_cas = NULL;
    if (g_store != NULL)
        vitalsSslStoreRelease(g_store);
    g_store = NULL;
    g_store_made = ++g_cas_changed;
}

/* As Sony's: it replaces everything loaded before, and keeps what it is given, which is read when an
 * https connection starts: a CA certificate that doesn't parse then isn't trusted, and a client
 * certificate or key that doesn't isn't sent */
int vh_tls_load_certs(int count, const SceHttpsData **list, const SceHttpsData *cert, const SceHttpsData *key)
{
    if (tls_ready() < 0)
        return (int)SCE_HTTP_ERROR_SSL;
    for (int i = 0; i < count; ++i)
        if (list[i] == NULL || list[i]->ptr == NULL || list[i]->size == 0)
            return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    if ((cert != NULL && (cert->ptr == NULL || cert->size == 0)) || (key != NULL && (key->ptr == NULL || key->size == 0)))
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;

    VhCa *cas = NULL, **last = &cas;
    for (int i = 0; i < count; ++i) {
        if ((*last = ca_new(list[i]->ptr, list[i]->size)) == NULL)
            break;
        last = &(*last)->next;
    }
    unsigned char *certificate = cert != NULL ? copy_bytes(cert->ptr, cert->size) : NULL;
    unsigned char *private_key = key != NULL ? copy_bytes(key->ptr, key->size) : NULL;
    if (*last != NULL || (count > 0 && cas == NULL) || (cert != NULL && certificate == NULL) ||
        (key != NULL && private_key == NULL)) {
        cas_free(cas);
        free(certificate);
        if (private_key != NULL)
            wipe(private_key, key->size);
        free(private_key);
        return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
    }
    release_cas();
    g_cas = cas;
    ++g_cas_changed;
    free_client();
    g_client_certificate = certificate;
    g_client_certificate_size = certificate != NULL ? cert->size : 0;
    g_client_key = private_key;
    g_client_key_size = private_key != NULL ? key->size : 0;
    VITALS_LOG("loaded %d CA certificates, client certificate %s", count,
               certificate != NULL && private_key != NULL ? "yes" : "no");
    return 0;
}

void vh_tls_unload_certs(void)
{
    release_cas();
    free_client();
}

/* As Sony's: kept, and read when an https connection starts */
int vh_tls_add_ca(const void *data, unsigned int size)
{
    if (tls_ready() < 0)
        return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
    if (data == NULL || size == 0)
        return 0;
    VhCa *ca = ca_new(data, size);
    if (ca == NULL)
        return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
    VhCa **last = &g_cas;
    while (*last != NULL)
        last = &(*last)->next;
    *last = ca;
    ++g_cas_changed;
    return 0;
}

void vh_tls_clear_cas(void)
{
    release_cas();
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
