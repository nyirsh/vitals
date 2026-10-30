#include "vs.h"

#include "ca_index.h"
#include "diagnostics.h"
#include "vitals/error_map.h"
#include "vitals_ssl.h"

#include <mbedtls/platform.h>
#include <mbedtls/platform_util.h>

#include <stdlib.h>
#include <string.h>

/* VitalsSsl: what vitals' own callers (vitals-http) need beyond Sony's interface, as opaque
 * objects: a BIO over their own transport, the console's ClientHello, verification they decide
 * themselves, CA certificates and a client certificate of their own, and what a connection did */

#define STORE_MAGIC 0x53435356u

typedef struct VsStore {
    uint32_t magic;
    unsigned int references;
    mbedtls_x509_crt chain;
    int empty;
} VsStore;

/* The console's suites in its order: 3DES and RC4 are only offered (the patched Mbed TLS lists
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

static VsContext *context_of(void *handle)
{
    VsContext *context = handle;
    return context != NULL && context->magic == VS_CONTEXT_MAGIC ? context : NULL;
}

static VsSsl *ssl_of(void *handle)
{
    return vs_is_ssl(handle) ? handle : NULL;
}

static int is_store(const VsStore *store)
{
    return store != NULL && store->magic == STORE_MAGIC;
}

static int has_pem_marker(const unsigned char *data, size_t size)
{
    static const char marker[] = "-----BEGIN";
    for (size_t i = 0; i + sizeof(marker) - 1u <= size; ++i)
        if (memcmp(data + i, marker, sizeof(marker) - 1u) == 0)
            return 1;
    return 0;
}

/* A NUL-terminated copy, which PEM parsing needs */
static unsigned char *copy_terminated(const void *data, size_t size)
{
    unsigned char *copy = malloc(size + 1u);
    if (copy != NULL) {
        memcpy(copy, data, size);
        copy[size] = '\0';
    }
    return copy;
}

static int parse_certificates(mbedtls_x509_crt *chain, const void *data, size_t size)
{
    if (data == NULL || size == 0)
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    unsigned char *copy = copy_terminated(data, size);
    if (copy == NULL)
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    int result = has_pem_marker(copy, size) ? mbedtls_x509_crt_parse(chain, copy, size + 1u)
                                            : mbedtls_x509_crt_parse_der(chain, copy, size);
    free(copy);
    return result;
}

static int parse_key(mbedtls_pk_context *key, const void *data, size_t size)
{
    if (data == NULL || size == 0)
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    unsigned char *copy = copy_terminated(data, size);
    if (copy == NULL)
        return MBEDTLS_ERR_PK_ALLOC_FAILED;
    int result = mbedtls_pk_parse_key(key, copy, has_pem_marker(copy, size) ? size + 1u : size, NULL, 0,
                                      vs_tls_random, NULL);
    mbedtls_platform_zeroize(copy, size);
    free(copy);
    return result;
}

/* NID 0xEC2EA2B3 */
int vitalsSslInitShared(void)
{
    int result = vs_library_init(0);
    return result == VS_ERROR_ALREADY_INITED ? 0 : result;
}

/* NID 0x258C6C64 */
void *vitalsSslBioNew(VitalsSslSend send, VitalsSslReceive receive, void *context)
{
    if (send == NULL || receive == NULL)
        return NULL;
    VsBio *bio = calloc(1, sizeof(*bio));
    if (bio == NULL) {
        vs_note_out_of_memory();
        return NULL;
    }
    bio->magic = VS_BIO_MAGIC;
    bio->fd = -1;
    /* The host name command works on it as on a socket BIO */
    bio->has_fd = 1;
    bio->send = send;
    bio->receive = receive;
    bio->transport = context;
    return bio;
}

/* NID 0xC356276E */
int vitalsSslCtxSetProfile(void *handle, int profile)
{
    VsContext *context = context_of(handle);
    if (context == NULL || (profile != VITALS_SSL_PROFILE_MODERN && profile != VITALS_SSL_PROFILE_CONSOLE))
        return VS_ERROR_INVALID_VALUE;
    context->profile = profile;
    return 0;
}

int vs_apply_profile(VsSsl *ssl)
{
    if (ssl->context->profile != VITALS_SSL_PROFILE_CONSOLE)
        return 0;
    mbedtls_ssl_config *config = &ssl->config;
    mbedtls_ssl_conf_max_tls_version(config, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_ciphersuites(config, g_console_suites);
    mbedtls_ssl_conf_offer_unknown_ciphersuites(config, 1);
    mbedtls_ssl_conf_sig_algs(config, g_console_signatures);
    mbedtls_ssl_conf_extended_master_secret(config, MBEDTLS_SSL_EXTENDED_MS_DISABLED);
    mbedtls_ssl_conf_encrypt_then_mac(config, MBEDTLS_SSL_ETM_DISABLED);
    mbedtls_ssl_conf_session_tickets(config, MBEDTLS_SSL_SESSION_TICKETS_DISABLED);
    return 0;
}

/* NID 0x00FB3554 */
int vitalsSslCtxSetDeferredVerify(void *handle, int deferred)
{
    VsContext *context = context_of(handle);
    if (context == NULL)
        return VS_ERROR_INVALID_VALUE;
    context->deferred_verify = deferred != 0;
    return 0;
}

/* NID 0xFBCA83CB */
void *vitalsSslStoreNew(void)
{
    VsStore *store = calloc(1, sizeof(*store));
    if (store == NULL) {
        vs_note_out_of_memory();
        return NULL;
    }
    store->magic = STORE_MAGIC;
    store->references = 1;
    store->empty = 1;
    mbedtls_x509_crt_init(&store->chain);
    return store;
}

/* NID 0x5F84E0A4: under the lock, as handshakes read the store */
int vitalsSslStoreAdd(void *handle, const void *data, size_t size)
{
    VsStore *store = handle;
    if (!is_store(store))
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    vs_lock();
    int result = parse_certificates(&store->chain, data, size);
    if (store->chain.raw.p != NULL)
        store->empty = 0;
    vs_unlock();
    return result;
}

static void store_release(VsStore *store)
{
    vs_lock();
    unsigned int left = --store->references;
    vs_unlock();
    if (left == 0) {
        mbedtls_x509_crt_free(&store->chain);
        store->magic = 0;
        free(store);
    }
}

/* NID 0x8563BB9E */
void vitalsSslStoreRelease(void *handle)
{
    if (is_store(handle))
        store_release(handle);
}

/* NID 0x4AAF69E0 */
int vitalsSslCtxSetStore(void *handle, void *store_handle)
{
    VsContext *context = context_of(handle);
    VsStore *store = store_handle;
    if (context == NULL || (store != NULL && !is_store(store)))
        return VS_ERROR_INVALID_VALUE;
    if (store != NULL) {
        vs_lock();
        ++store->references;
        vs_unlock();
    }
    if (context->store != NULL)
        store_release(context->store);
    context->store = store;
    return 0;
}

static void free_identity(VsContext *context)
{
    if (context->own_certificate != NULL) {
        mbedtls_x509_crt_free(context->own_certificate);
        free(context->own_certificate);
    }
    if (context->own_key != NULL) {
        mbedtls_pk_free(context->own_key);
        free(context->own_key);
    }
    context->own_certificate = NULL;
    context->own_key = NULL;
}

/* NID 0x8DCEBE98 */
int vitalsSslCtxSetIdentity(void *handle, const void *certificate, size_t certificate_size, const void *key,
                            size_t key_size)
{
    VsContext *context = context_of(handle);
    if (context == NULL)
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    free_identity(context);
    context->own_certificate = calloc(1, sizeof(*context->own_certificate));
    context->own_key = calloc(1, sizeof(*context->own_key));
    if (context->own_certificate == NULL || context->own_key == NULL) {
        free(context->own_certificate);
        free(context->own_key);
        context->own_certificate = NULL;
        context->own_key = NULL;
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    }
    mbedtls_x509_crt_init(context->own_certificate);
    mbedtls_pk_init(context->own_key);
    int result = parse_certificates(context->own_certificate, certificate, certificate_size);
    if (result == 0)
        result = parse_key(context->own_key, key, key_size);
    if (result != 0)
        free_identity(context);
    return result;
}

/* NID 0x169DA221 */
int vitalsSslCheckCertificate(const void *data, size_t size)
{
    mbedtls_x509_crt chain;
    mbedtls_x509_crt_init(&chain);
    int result = parse_certificates(&chain, data, size);
    mbedtls_x509_crt_free(&chain);
    return result;
}

/* NID 0xDE8174EC */
int vitalsSslCheckKey(const void *data, size_t size)
{
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    int result = parse_key(&key, data, size);
    mbedtls_pk_free(&key);
    return result;
}

void vs_context_free_additions(VsContext *context)
{
    free_identity(context);
    vs_context_free_client_cas(context);
    if (context->store != NULL)
        store_release(context->store);
    context->store = NULL;
}

/* Copies the store's certificates that issued child onto *candidates, which Mbed TLS frees */
static int store_find(const VsStore *store, const mbedtls_x509_crt *child, mbedtls_x509_crt **candidates)
{
    int result = 0;
    vs_lock();
    for (const mbedtls_x509_crt *ca = store->empty ? NULL : &store->chain; ca != NULL && ca->raw.p != NULL;
         ca = ca->next) {
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
    vs_unlock();
    if (*candidates != NULL && (*candidates)->raw.p == NULL) {
        mbedtls_x509_crt_free(*candidates);
        mbedtls_free(*candidates);
        *candidates = NULL;
    }
    return result;
}

int vs_find_issuers_with_store(void *context, const mbedtls_x509_crt *child, mbedtls_x509_crt **candidates)
{
    VsSsl *ssl = context;
    int result = vs_find_trusted_issuers(NULL, child, candidates);
    if (result != 0 || ssl == NULL || ssl->context->store == NULL)
        return result;
    return store_find(ssl->context->store, child, candidates);
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

/* The bundle's roots, then the store's certificates, for vitalsSslCheckChain */
static int chain_issuers(void *context, const mbedtls_x509_crt *child, mbedtls_x509_crt **candidates)
{
    const VsStore *store = context;
    int result = vs_find_trusted_issuers(NULL, child, candidates);
    if (result != 0 || store == NULL)
        return result;
    return store_find(store, child, candidates);
}

static int chain_exact(void *context, mbedtls_x509_crt *certificate, int depth, uint32_t *flags)
{
    if (depth == 0 && (*flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED) != 0 &&
        vitals_ca_trusts_exact(chain_issuers, context, certificate))
        *flags &= ~(uint32_t)MBEDTLS_X509_BADCERT_NOT_TRUSTED;
    return 0;
}

/* NID 0x791117DC: the certificates can be another copy of vitals-ssl's (the libssl module's, when
 * vitals-http checks a context the NetCheck dialog made there): they are only read */
unsigned int vitalsSslCheckChain(void *const certificates[], int count, const char *host, void *store_handle)
{
    VsStore *store = is_store(store_handle) ? store_handle : NULL;
    const mbedtls_x509_crt *leaf = certificates != NULL && count > 0 ? vs_certificate(certificates[0]) : NULL;
    if (leaf == NULL)
        return VITALS_CERT_INVALID;
    /* As every connection's: SHA-1 signatures stay allowed for Sony's own servers */
    mbedtls_x509_crt_profile profile = mbedtls_x509_crt_profile_default;
    profile.allowed_mds |= MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA1);
    uint32_t flags = 0;
    int result = mbedtls_x509_crt_verify_with_ca_cb((mbedtls_x509_crt *)leaf, chain_issuers, store, &profile,
                                                    host != NULL && host[0] != '\0' ? host : NULL, &flags,
                                                    chain_exact, store);
    if (result != 0 && flags == 0)
        flags = MBEDTLS_X509_BADCERT_OTHER;
    return (unsigned int)certificate_flags(flags);
}

/* NID 0xD35E2515 */
unsigned int vitalsSslGetVerifyResult(void *handle)
{
    VsSsl *ssl = ssl_of(handle);
    return ssl != NULL && ssl->ready ? (unsigned int)mbedtls_ssl_get_verify_result(&ssl->tls) : 0xFFFFFFFFu;
}

/* NID 0x7B93015B */
unsigned int vitalsSslGetCertificateFlags(void *handle)
{
    uint32_t verify = vitalsSslGetVerifyResult(handle);
    return verify == 0xFFFFFFFFu ? 0u : (unsigned int)certificate_flags(verify);
}

/* NID 0xE6EB9C2D */
int vitalsSslGetTlsError(void *handle)
{
    VsSsl *ssl = ssl_of(handle);
    return ssl != NULL && ssl->failure == VS_FAILED_TLS ? ssl->tls_result : 0;
}

/* NID 0xE0613333 */
int vitalsSslTlsErrorIsMemory(int error)
{
    return error == MBEDTLS_ERR_SSL_ALLOC_FAILED || error == MBEDTLS_ERR_X509_ALLOC_FAILED ||
           error == MBEDTLS_ERR_MPI_ALLOC_FAILED || error == MBEDTLS_ERR_PK_ALLOC_FAILED;
}

/* NID 0x184CAB4B */
const char *vitalsSslGetVersion(void *handle)
{
    VsSsl *ssl = ssl_of(handle);
    return ssl != NULL && ssl->ready ? mbedtls_ssl_get_version(&ssl->tls) : "-";
}

/* NID 0x352F91AF */
const char *vitalsSslGetCiphersuite(void *handle)
{
    VsSsl *ssl = ssl_of(handle);
    const char *suite = ssl != NULL && ssl->ready ? mbedtls_ssl_get_ciphersuite(&ssl->tls) : NULL;
    return suite != NULL ? suite : "-";
}

/* NID 0xEB8141B2 */
int vitalsSslCertificateRequested(void *handle)
{
    VsSsl *ssl = ssl_of(handle);
    return ssl != NULL && ssl->certificate_requested;
}
