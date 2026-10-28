#include "vh.h"

#include "ca_index.h"
#include "crypto_platform.h"
#include "diagnostics.h"
#include "user_runtime.h"
#include "vitals/error_map.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* TLS 1.2 and 1.3 with Mbed TLS 3.6 and tls13-vita's CA bundle index, its exact trust of
 * self-signed certificates, and its mapping of certificate problems to libhttp's detail bits.
 * Mbed TLS's memory is the tls13-vita runtime's heap (user_runtime.c), not the app's pool.
 *
 * Sony's own connections (the ones with the private HTTPS option 0x40, as the shell's PSN
 * sign-in) get the console's own ClientHello, as a capture of a working sign-in shows it: TLS 1.2,
 * no session ID, the suites below, null compression, and only server_name and
 * signature_algorithms. The CDN in front of PSN sign-in refuses handshakes that don't look like a
 * console's */

/* The console's suites in its order. 3DES and RC4 are only offered (the patched Mbed TLS lists
 * suites it doesn't have); every server seen picks AES128-SHA256. Mbed TLS adds the renegotiation
 * SCSV after them, as the console does */
static const int g_console_suites[] = {
    MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA256,
    MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA,
    MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA,
    0x000A, /* TLS_RSA_WITH_3DES_EDE_CBC_SHA */
    0x0005, /* TLS_RSA_WITH_RC4_128_SHA */
    0x0004, /* TLS_RSA_WITH_RC4_128_MD5 */
    0,
};

/* Its signature algorithms, in its order: RSA PKCS#1 with SHA-256, SHA-512, SHA-384, SHA-1 */
static const uint16_t g_console_signatures[] = {
    MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA256,
    MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA512,
    MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA384,
    MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA1,
    MBEDTLS_TLS1_3_SIG_NONE,
};

/* How many post-handshake records (TLS 1.3 session tickets) a read goes through */
#define VH_TICKET_BUDGET 16u

struct VhTls
{
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config config;
    mbedtls_x509_crt_profile profile;
    VhTransport *transport;
    /* The transport's last error, which Mbed TLS only sees as a failed send or receive */
    int io_error;
    /* The client certificate and key it presents, its own parsed copies */
    mbedtls_x509_crt own_certificate;
    mbedtls_pk_context own_key;
    int has_own;
    /* The server's handshake records, for the debug log */
    VhRecordScan scan;
    char host[VH_HOST_MAX];
};

/* Set up on the first https connection, with the lock held: 1 once ready, negative when it failed */
static int g_state;
static VitalsCaIndex g_ca_index;
static int g_ca_index_ready;
/* sceHttpsLoadCert's CA certificates, under the lock; handshakes copy the ones they need */
static mbedtls_x509_crt *g_loaded;
/* Its client certificate and key, as the app gave them (NUL-terminated); each connection parses
 * its own copy, so an unload during a handshake frees nothing it uses */
static unsigned char *g_client_certificate, *g_client_key;
static size_t g_client_certificate_size, g_client_key_size;
/* The random numbers of every handshake */
static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_random;

/* Mbed TLS's platform and PSA, then the index of the CA bundle; a missing bundle leaves only the
 * app's certificates trusted. With the lock held */
static int tls_ready(void)
{
    char path[VITALS_CA_INDEX_PATH_SIZE];
    if (g_state != 0)
        return g_state;
    if (vh_platform_tls_init() != 0 || vitals_crypto_platform_init() != 0 || psa_crypto_init() != PSA_SUCCESS) {
        g_state = -1;
        return g_state;
    }
    mbedtls_entropy_init(&g_entropy);
    mbedtls_ctr_drbg_init(&g_random);
    if (mbedtls_ctr_drbg_seed(&g_random, mbedtls_entropy_func, &g_entropy, (const unsigned char *)"vitals-http", 11) != 0) {
        mbedtls_ctr_drbg_free(&g_random);
        mbedtls_entropy_free(&g_entropy);
        g_state = -1;
        return g_state;
    }
    if (vh_platform_ca_path(path, sizeof(path)) == 0)
        g_ca_index_ready = vitals_ca_index_build(&g_ca_index, path) == 0;
    VITALS_LOG("tls ready roots=%u", g_ca_index_ready ? (unsigned int)g_ca_index.count : 0u);
    g_state = 1;
    return g_state;
}

static void free_chain(mbedtls_x509_crt *chain)
{
    if (chain != NULL) {
        mbedtls_x509_crt_free(chain);
        mbedtls_free(chain);
    }
}

/* Adds the loaded CA certificates that issued child to *candidates, as copies Mbed TLS frees */
static int loaded_ca_find(const mbedtls_x509_crt *child, mbedtls_x509_crt **candidates)
{
    int result = 0;
    vh_lock();
    for (const mbedtls_x509_crt *ca = g_loaded; ca != NULL && ca->raw.p != NULL; ca = ca->next) {
        if (ca->subject_raw.len != child->issuer_raw.len ||
            memcmp(ca->subject_raw.p, child->issuer_raw.p, ca->subject_raw.len) != 0)
            continue;
        if (*candidates == NULL) {
            *candidates = mbedtls_calloc(1, sizeof(**candidates));
            if (*candidates == NULL) {
                result = MBEDTLS_ERR_X509_ALLOC_FAILED;
                break;
            }
            mbedtls_x509_crt_init(*candidates);
        }
        (void)mbedtls_x509_crt_parse_der(*candidates, ca->raw.p, ca->raw.len);
    }
    vh_unlock();
    if (*candidates != NULL && (*candidates)->raw.p == NULL) {
        free_chain(*candidates);
        *candidates = NULL;
    }
    return result;
}

/* The bundle's roots, then the app's CA certificates */
static int find_trusted_issuers(void *context, const mbedtls_x509_crt *child, mbedtls_x509_crt **candidates)
{
    (void)context;
    *candidates = NULL;
    int result = g_ca_index_ready ? vitals_ca_index_find(&g_ca_index, child, candidates) : 0;
    if (result != 0)
        return result;
    return loaded_ca_find(child, candidates);
}

/* A self-signed server certificate that is itself trusted counts as trusted; its other checks
 * (host name, dates) still apply */
static int trust_exact_self_signed(void *context, mbedtls_x509_crt *certificate, int depth, uint32_t *flags)
{
    if (depth == 0 && (*flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED) != 0 &&
        vitals_ca_trusts_exact(find_trusted_issuers, context, certificate))
        *flags &= ~(uint32_t)MBEDTLS_X509_BADCERT_NOT_TRUSTED;
    return 0;
}

/* Mbed TLS's verification flags as tls13-vita's certificate flags (VITALS_CERT_*) */
static uint32_t certificate_flags(uint32_t flags)
{
    const uint32_t invalid = MBEDTLS_X509_BADCERT_REVOKED | MBEDTLS_X509_BADCRL_EXPIRED |
                             MBEDTLS_X509_BADCERT_MISSING | MBEDTLS_X509_BADCERT_SKIP_VERIFY |
                             MBEDTLS_X509_BADCERT_OTHER | MBEDTLS_X509_BADCRL_FUTURE |
                             MBEDTLS_X509_BADCERT_KEY_USAGE | MBEDTLS_X509_BADCERT_EXT_KEY_USAGE |
                             MBEDTLS_X509_BADCERT_NS_CERT_TYPE | MBEDTLS_X509_BADCERT_BAD_MD |
                             MBEDTLS_X509_BADCERT_BAD_PK | MBEDTLS_X509_BADCERT_BAD_KEY |
                             MBEDTLS_X509_BADCRL_BAD_MD | MBEDTLS_X509_BADCRL_BAD_PK | MBEDTLS_X509_BADCRL_BAD_KEY;
    uint32_t mapped = 0;
    if (flags & invalid)
        mapped |= VITALS_CERT_INVALID;
    if (flags & MBEDTLS_X509_BADCERT_CN_MISMATCH)
        mapped |= VITALS_CERT_HOSTNAME;
    if (flags & MBEDTLS_X509_BADCERT_EXPIRED)
        mapped |= VITALS_CERT_EXPIRED;
    if (flags & MBEDTLS_X509_BADCERT_FUTURE)
        mapped |= VITALS_CERT_FUTURE;
    if (flags & (MBEDTLS_X509_BADCERT_NOT_TRUSTED | MBEDTLS_X509_BADCRL_NOT_TRUSTED))
        mapped |= VITALS_CERT_UNKNOWN_CA;
    if (flags != 0 && mapped == 0)
        mapped = VITALS_CERT_INTERNAL;
    return mapped;
}

static int bio_send(void *context, const unsigned char *data, size_t size)
{
    VhTls *tls = context;
    int sent = vh_transport_raw_send(tls->transport, data, size);
    if (sent < 0) {
        tls->io_error = sent;
        return sent == (int)SCE_HTTP_ERROR_TIMEOUT ? MBEDTLS_ERR_SSL_TIMEOUT : MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return sent;
}

static int bio_recv(void *context, unsigned char *data, size_t size)
{
    VhTls *tls = context;
    int received = vh_transport_raw_recv(tls->transport, data, size);
    if (received < 0) {
        tls->io_error = received;
        return received == (int)SCE_HTTP_ERROR_TIMEOUT ? MBEDTLS_ERR_SSL_TIMEOUT : MBEDTLS_ERR_NET_RECV_FAILED;
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
    mbedtls_ssl_free(&tls->ssl);
    mbedtls_ssl_config_free(&tls->config);
    if (tls->has_own) {
        mbedtls_x509_crt_free(&tls->own_certificate);
        mbedtls_pk_free(&tls->own_key);
    }
    mbedtls_platform_zeroize(tls, sizeof(*tls));
    free(tls);
}

static int parse_certificate_data(mbedtls_x509_crt *chain, const unsigned char *data, size_t size);
static int parse_key_data(mbedtls_pk_context *key, const unsigned char *data, size_t size);

/* The client certificate and key sceHttpsLoadCert gave, for servers that ask for one */
static int own_identity(VhTls *tls)
{
    int result = 0;
    vh_lock();
    if (g_client_certificate != NULL && g_client_key != NULL) {
        mbedtls_x509_crt_init(&tls->own_certificate);
        mbedtls_pk_init(&tls->own_key);
        tls->has_own = 1;
        result = parse_certificate_data(&tls->own_certificate, g_client_certificate, g_client_certificate_size);
        if (result == 0)
            result = parse_key_data(&tls->own_key, g_client_key, g_client_key_size);
    }
    vh_unlock();
    if (tls->has_own && result == 0)
        result = mbedtls_ssl_conf_own_cert(&tls->config, &tls->own_certificate, &tls->own_key);
    if (tls->has_own)
        VITALS_LOG("client certificate host=%s rc=%08X", tls->host, (unsigned int)result);
    return result;
}

static int setup(VhTls *tls, int console)
{
    mbedtls_ssl_init(&tls->ssl);
    mbedtls_ssl_config_init(&tls->config);
    int result = mbedtls_ssl_config_defaults(&tls->config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                             MBEDTLS_SSL_PRESET_DEFAULT);
    if (result != 0)
        return result;
    /* As the HTTP provider: SHA-1 signatures stay allowed for Sony's own servers */
    tls->profile = mbedtls_x509_crt_profile_default;
    tls->profile.allowed_mds |= MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA1);
    mbedtls_ssl_conf_cert_profile(&tls->config, &tls->profile);
    mbedtls_ssl_conf_rng(&tls->config, mbedtls_ctr_drbg_random, &g_random);
    mbedtls_ssl_conf_min_tls_version(&tls->config, MBEDTLS_SSL_VERSION_TLS1_2);
    if (console) {
        mbedtls_ssl_conf_max_tls_version(&tls->config, MBEDTLS_SSL_VERSION_TLS1_2);
        mbedtls_ssl_conf_ciphersuites(&tls->config, g_console_suites);
        mbedtls_ssl_conf_offer_unknown_ciphersuites(&tls->config, 1);
        mbedtls_ssl_conf_sig_algs(&tls->config, g_console_signatures);
        mbedtls_ssl_conf_extended_master_secret(&tls->config, MBEDTLS_SSL_EXTENDED_MS_DISABLED);
        mbedtls_ssl_conf_encrypt_then_mac(&tls->config, MBEDTLS_SSL_ETM_DISABLED);
        mbedtls_ssl_conf_session_tickets(&tls->config, MBEDTLS_SSL_SESSION_TICKETS_DISABLED);
    } else
        mbedtls_ssl_conf_max_tls_version(&tls->config, MBEDTLS_SSL_VERSION_TLS1_3);
    /* Verified, but decided after the handshake, from the HTTPS options and the app's callback */
    mbedtls_ssl_conf_authmode(&tls->config, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_cb(&tls->config, find_trusted_issuers, NULL);
    mbedtls_ssl_conf_verify(&tls->config, trust_exact_self_signed, NULL);
    result = own_identity(tls);
    if (result != 0)
        return result;
    result = mbedtls_ssl_setup(&tls->ssl, &tls->config);
    if (result == 0)
        result = mbedtls_ssl_set_hostname(&tls->ssl, tls->host);
    if (result == 0)
        mbedtls_ssl_set_bio(&tls->ssl, tls, bio_send, bio_recv, NULL);
    return result;
}

#if VITALS_DEBUG >= 1
/* For the debug log: in TLS 1.3 the request is encrypted, so it can't be seen */
static const char *client_certificate_asked(VhTls *tls)
{
    if (tls->scan.certificate_request)
        return "yes";
    if (mbedtls_ssl_get_version_number(&tls->ssl) == MBEDTLS_SSL_VERSION_TLS1_2 && tls->scan.done)
        return "no";
    return "unknown";
}
#endif

/* The handshake runs on a thread of its own, with a known stack: an app may call from a thread
 * whose stack is too small for one (TLS 1.3 with elliptic curves, in a game's network thread) */
typedef struct VhHandshake
{
    VhTls *tls;
    int result;
    int done;
} VhHandshake;

static void handshake_thread(void *argument)
{
    VhHandshake *handshake = argument;
    int result = mbedtls_ssl_handshake(&handshake->tls->ssl);
    /* The caller's frame holds handshake: once done is seen, it may be gone */
    vh_lock();
    handshake->result = result;
    handshake->done = 1;
    vh_platform_notify();
    vh_unlock();
}

static int run_handshake(VhTls *tls)
{
    VhHandshake handshake = {tls, 0, 0};
    if (vh_platform_thread(handshake_thread, &handshake) < 0) {
        VITALS_LOG("handshake thread not started host=%s: on the caller's", tls->host);
        return mbedtls_ssl_handshake(&tls->ssl);
    }
    for (;;) {
        unsigned int generation = vh_platform_generation();
        vh_lock();
        int done = handshake.done;
        vh_unlock();
        if (done)
            return handshake.result;
        vh_platform_wait(generation, -1);
    }
}

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
        return store_outcome(result == MBEDTLS_ERR_SSL_ALLOC_FAILED ? VITALS_OUTCOME_NO_MEMORY : VITALS_OUTCOME_INTERNAL,
                             (uint32_t)result, ssl_error, ssl_detail);
    }
    VITALS_VERBOSE("handshake start %s profile=%s", tls->host, console ? "console" : "modern");
    result = run_handshake(tls);
    uint32_t verify = mbedtls_ssl_get_verify_result(&tls->ssl);
    if (result != 0) {
        VITALS_LOG("handshake failed host=%s client_cert_asked=%s", tls->host, client_certificate_asked(tls));
        VITALS_LOG("handshake failed host=%s tls=%08X io=%08X verify=%08X", tls->host, (unsigned int)result,
                   (unsigned int)tls->io_error, (unsigned int)verify);
        if (result == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED || (verify != UINT32_MAX && verify != 0))
            result = store_outcome(VITALS_OUTCOME_CERTIFICATE,
                                   vitals_filter_certificate_flags(certificate_flags(verify), open->https_options),
                                   ssl_error, ssl_detail);
        else
            result = store_outcome(tls->io_error != 0 ? VITALS_OUTCOME_IO : VITALS_OUTCOME_HANDSHAKE, (uint32_t)result,
                                   ssl_error, ssl_detail);
        if (tls->io_error != 0 || vh_transport_aborted(transport))
            result = tls_error(tls);
        vh_tls_close(tls);
        vitals_user_runtime_report("handshake failed", 1);
        return result;
    }

    /* Only the checks the options ask for; the app's callback can accept the rest */
    uint32_t flags = vitals_filter_certificate_flags(certificate_flags(verify), open->https_options);
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
               tls->host, mbedtls_ssl_get_version(&tls->ssl), mbedtls_ssl_get_ciphersuite(&tls->ssl),
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
        int sent = mbedtls_ssl_write(&tls->ssl, at, size);
        if (sent <= 0)
            return tls_error(tls);
        at += sent;
        size -= (size_t)sent;
    }
    return 0;
}

int vh_tls_recv(VhTls *tls, void *data, size_t size)
{
    unsigned int budget = VH_TICKET_BUDGET;
    int received;
    do {
        tls->io_error = 0;
        received = mbedtls_ssl_read(&tls->ssl, data, size);
        if (received <= 0)
            VITALS_VERBOSE("tls read host=%s rc=%08X io=%08X", tls->host, (unsigned int)received,
                           (unsigned int)tls->io_error);
        /* A post-handshake record is consumed without data: read on */
    } while ((received == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET ||
              (received == MBEDTLS_ERR_SSL_WANT_READ && tls->io_error == 0)) &&
             --budget != 0);
    if (received > 0)
        return received;
    /* close_notify, or a server that closes without it, both end the response */
    if (received == 0 || received == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || received == MBEDTLS_ERR_SSL_CONN_EOF)
        return 0;
    return tls_error(tls);
}

/* ---- sceHttpsLoadCert ---- */

static int has_pem_marker(const unsigned char *data, size_t size)
{
    static const char marker[] = "-----BEGIN";
    for (size_t i = 0; i + sizeof(marker) - 1u <= size; ++i)
        if (memcmp(data + i, marker, sizeof(marker) - 1u) == 0)
            return 1;
    return 0;
}

/* data is followed by a NUL that size leaves out, which PEM parsing needs */
static int parse_certificate_data(mbedtls_x509_crt *chain, const unsigned char *data, size_t size)
{
    if (has_pem_marker(data, size))
        return mbedtls_x509_crt_parse(chain, data, size + 1u);
    return mbedtls_x509_crt_parse_der(chain, data, size);
}

static int parse_key_data(mbedtls_pk_context *key, const unsigned char *data, size_t size)
{
    return mbedtls_pk_parse_key(key, data, has_pem_marker(data, size) ? size + 1u : size, NULL, 0,
                                mbedtls_ctr_drbg_random, &g_random);
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
        mbedtls_platform_zeroize(g_client_key, g_client_key_size);
    free(g_client_certificate);
    free(g_client_key);
    g_client_certificate = g_client_key = NULL;
    g_client_certificate_size = g_client_key_size = 0;
}

/* As Sony's: it replaces everything loaded before. The CA certificates must all parse; the client
 * certificate and key are checked here too, and refused when they don't, with the reason logged */
int vh_tls_load_certs(int count, const SceHttpsData **list, const SceHttpsData *cert, const SceHttpsData *key)
{
    if (tls_ready() < 0)
        return (int)SCE_HTTP_ERROR_SSL;
    mbedtls_x509_crt *chain = count > 0 ? mbedtls_calloc(1, sizeof(*chain)) : NULL;
    if (count > 0 && chain == NULL)
        return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
    if (chain != NULL)
        mbedtls_x509_crt_init(chain);
    for (int i = 0; i < count; ++i) {
        size_t size = 0;
        unsigned char *data = copy_data(list[i], &size);
        int parsed = data != NULL ? parse_certificate_data(chain, data, size) : -1;
        free(data);
        if (parsed != 0) {
            VITALS_LOG("load cert: CA %d of %d unreadable rc=%08X", i + 1, count, (unsigned int)parsed);
            free_chain(chain);
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
        mbedtls_x509_crt check_certificate;
        mbedtls_pk_context check_key;
        mbedtls_x509_crt_init(&check_certificate);
        mbedtls_pk_init(&check_key);
        int certificate_rc = certificate != NULL ? parse_certificate_data(&check_certificate, certificate, certificate_size) : -1;
        int key_rc = private_key != NULL ? parse_key_data(&check_key, private_key, key_size) : -1;
        VITALS_LOG("load cert: client certificate %u bytes rc=%08X, key %u bytes rc=%08X",
                   (unsigned int)certificate_size, (unsigned int)certificate_rc, (unsigned int)key_size,
                   (unsigned int)key_rc);
        mbedtls_x509_crt_free(&check_certificate);
        mbedtls_pk_free(&check_key);
        if (certificate_rc != 0 || key_rc != 0)
            result = (int)SCE_HTTP_ERROR_INVALID_VALUE;
    }
    if (result < 0) {
        if (private_key != NULL)
            mbedtls_platform_zeroize(private_key, key_size);
        free(certificate);
        free(private_key);
        free_chain(chain);
        return result;
    }
    free_chain(g_loaded);
    g_loaded = chain;
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
    free_chain(g_loaded);
    g_loaded = NULL;
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
    unsigned char *copy = copy_bytes(data, size);
    if (copy == NULL)
        return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
    if (g_loaded == NULL) {
        g_loaded = mbedtls_calloc(1, sizeof(*g_loaded));
        if (g_loaded == NULL) {
            free(copy);
            return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
        }
        mbedtls_x509_crt_init(g_loaded);
    }
    int parsed = parse_certificate_data(g_loaded, copy, size);
    free(copy);
    if (parsed == MBEDTLS_ERR_X509_ALLOC_FAILED)
        return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
    if (parsed != 0)
        VITALS_LOG("private CA certificate of %u bytes unreadable rc=%08X: not trusted", size, (unsigned int)parsed);
    return 0;
}

void vh_tls_clear_cas(void)
{
    free_chain(g_loaded);
    g_loaded = NULL;
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
        mbedtls_platform_zeroize(*slot, *slot_size);
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
