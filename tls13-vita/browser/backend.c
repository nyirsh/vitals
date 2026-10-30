#include "backend.h"
#include "diagnostics.h"
#include "vitals/error_map.h"
#include "vitals/registry.h"
#include "vitals/sony_abi.h"
#include "vitals_ssl.h"

#include <psp2/io/fcntl.h>
#include <psp2/kernel/threadmgr/mutex.h>
#include <psp2/net/net.h>
#include <psp2common/net.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* The browser's TLS is the libssl module's (vitals-ssl), which the kernel plugin loads into the
 * browser engine's process before this provider: each connection a vitals-ssl one over curl's
 * socket, stepped without blocking as curl drives it */

#define BROWSER_IO_CHUNK 1500
#define BROWSER_POLL_SLICE_MS 50
#define BROWSER_REJECTED_HOSTS 32
/* libssl's pool in the browser engine's process, set up on its first https connection: every
 * connection's memory comes from it */
#ifndef VITALS_BROWSER_SSL_POOL_BYTES
#define VITALS_BROWSER_SSL_POOL_BYTES (1024u * 1024u)
#endif
#ifndef VITALS_DEFAULT_CA_PATH
#define VITALS_DEFAULT_CA_PATH "vs0:/data/external/cert/CA_LIST.cer"
#endif
/* A page's own CA file, read whole */
#define BROWSER_CA_FILE_MAX (512u * 1024u)

enum BrowserState { BROWSER_INITIALIZING, BROWSER_HANDSHAKING, BROWSER_ACTIVE,
    BROWSER_EOF, BROWSER_FAILED };

enum DefaultCaState { DEFAULT_CA_UNINITIALIZED, DEFAULT_CA_READY, DEFAULT_CA_FAILED };

typedef struct BrowserConnection {
    void *native;
    int index;
    int socket;
    SceUID mutex;
    uint32_t closing;
    enum BrowserState state;
    int error;
    int net_error;
    int want;
    unsigned int pending_length;
    uint32_t old_recv;
    uint32_t old_send;
    uint8_t verify_peer;
    uint8_t verify_host;
    uint8_t custom_ca_requested;
    uint8_t notifying_close;
    uint8_t lookahead_valid;
    unsigned char lookahead;
    void *ssl;
    int ciphers[8];
    char hostname[1024];
    char ca_file[1024];
    unsigned char pending_write[BROWSER_IO_CHUNK];
} BrowserConnection;

static struct {
    VitalsBrowserOps ops;
    VitalsRegistry registry;
    SceUID registry_mutex;
    SceUID attach_mutex;
    /* Hosts whose certificate failed verification here, by hash, with the error each got. After
     * such a failure the browser retries the host itself with verification off, and without a
     * warning; those retries get the same error instead of Sony's TLS */
    SceUID rejected_mutex;
    uint64_t rejected_hosts[BROWSER_REJECTED_HOSTS];
    int rejected_codes[BROWSER_REJECTED_HOSTS];
    unsigned int rejected_next;
    int default_ca_error;
    uint32_t enabled;
    enum DefaultCaState default_ca_state;
    uint8_t initialized;
} browser;

/* Clears memory through a volatile pointer, which the compiler can't drop */
static void wipe(void *data, size_t size) {
    volatile unsigned char *at = data;
    while (size-- > 0) *at++ = 0;
}

static uintptr_t connection_key(const void *native, int index) {
    return (uintptr_t)native + (uintptr_t)(unsigned int)index;
}

static size_t ssl_offset(int index) {
    return VITALS_CURL_SSL_OFFSET + VITALS_CURL_SSL_STRIDE * (size_t)(unsigned int)index;
}

static void registry_lock(void *unused) {
    (void)unused;
    (void)sceKernelLockMutex(browser.registry_mutex, 1, NULL);
}

static void registry_unlock(void *unused) {
    (void)unused;
    (void)sceKernelUnlockMutex(browser.registry_mutex, 1);
}

static void free_connection(void *unused, void *payload) {
    BrowserConnection *connection = payload;
    (void)unused;
    if (connection == NULL) return;
    if (connection->ssl != NULL) sceSslInternalFree(connection->ssl);
    if (connection->mutex >= 0) (void)sceKernelDeleteMutex(connection->mutex);
    wipe(connection, sizeof(*connection));
    free(connection);
}

/* libssl reads the bundle itself; without one, the browser keeps its own TLS, as when the bundle
 * couldn't be read before */
static int ensure_default_ca(void) {
    int fd;
    if (browser.default_ca_state == DEFAULT_CA_READY) return 0;
    if (browser.default_ca_state == DEFAULT_CA_FAILED) return browser.default_ca_error;
    fd = sceIoOpen(browser.ops.default_ca_path != NULL ? browser.ops.default_ca_path : VITALS_DEFAULT_CA_PATH,
        SCE_O_RDONLY, 0);
    if (fd >= 0) {
        (void)sceIoClose(fd);
        browser.default_ca_state = DEFAULT_CA_READY;
        return 0;
    }
    browser.default_ca_error = fd;
    browser.default_ca_state = DEFAULT_CA_FAILED;
    return fd;
}

/* libssl set up in this process, with its pool, unless something already did: 0 or its error */
static int ensure_library(void) {
    int result = sceSslInternalIsInitalized();
    if (result == 0) return 0;
    /* libssl can't work the bundle's path out in this process: it is the one the engine's module
     * path gives */
    result = vitalsSslSetBundlePath(browser.ops.default_ca_path != NULL ? browser.ops.default_ca_path
                                                                       : VITALS_DEFAULT_CA_PATH);
    if (result != 0) return result;
    result = sceSslInit(VITALS_BROWSER_SSL_POOL_BYTES);
    VITALS_LOG("browser libssl pool=%u rc=0x%08X", VITALS_BROWSER_SSL_POOL_BYTES, (unsigned int)result);
    return result;
}

int vitals_browser_init(const VitalsBrowserOps *ops) {
    const VitalsRegistryOps registry_ops = {registry_lock, registry_unlock, free_connection, NULL};
    int result;

    if (browser.initialized || ops == NULL || ops->timeleft == NULL || ops->socket_wait == NULL)
        return -1;
    memset(&browser, 0, sizeof(browser));
    browser.registry_mutex = -1;
    browser.attach_mutex = -1;
    browser.rejected_mutex = -1;
    browser.ops = *ops;
    browser.registry_mutex = sceKernelCreateMutex("vitals browser registry", 0, 0, NULL);
    browser.attach_mutex = sceKernelCreateMutex("vitals browser attach", 0, 0, NULL);
    browser.rejected_mutex = sceKernelCreateMutex("vitals browser rejected", 0, 0, NULL);
    if (browser.registry_mutex < 0 || browser.attach_mutex < 0 || browser.rejected_mutex < 0) {
        result = VITALS_CURLE_OUT_OF_MEMORY;
        goto failed;
    }
    result = vitals_registry_init(&browser.registry, &registry_ops);
    if (result != 0) goto failed;
    browser.initialized = 1;
    return 0;

failed:
    if (browser.rejected_mutex >= 0) (void)sceKernelDeleteMutex(browser.rejected_mutex);
    if (browser.attach_mutex >= 0) (void)sceKernelDeleteMutex(browser.attach_mutex);
    if (browser.registry_mutex >= 0) (void)sceKernelDeleteMutex(browser.registry_mutex);
    memset(&browser, 0, sizeof(browser));
    return result;
}

void vitals_browser_enable(int enabled) {
    __atomic_store_n(&browser.enabled, enabled != 0, __ATOMIC_RELEASE);
}

int vitals_browser_destroy(void) {
    int result;
    if (!browser.initialized) return 0;
    result = vitals_registry_begin_stop_if_empty(&browser.registry);
    if (result != VITALS_REGISTRY_OK) return result;
    vitals_browser_enable(0);
    result = vitals_registry_destroy(&browser.registry);
    if (result != VITALS_REGISTRY_OK) return result;
    (void)sceKernelDeleteMutex(browser.rejected_mutex);
    (void)sceKernelDeleteMutex(browser.attach_mutex);
    (void)sceKernelDeleteMutex(browser.registry_mutex);
    memset(&browser, 0, sizeof(browser));
    return 0;
}

/* FNV-1a of the lowercased name; a collision can only refuse an unverified connection */
static uint64_t host_hash(const char *hostname) {
    uint64_t hash = UINT64_C(0xCBF29CE484222325);
    for (const unsigned char *c = (const unsigned char *)hostname; *c != '\0'; ++c) {
        hash ^= (uint64_t)(*c >= 'A' && *c <= 'Z' ? *c + ('a' - 'A') : *c);
        hash *= UINT64_C(0x100000001B3);
    }
    return hash;
}

static void remember_rejected(const char *hostname, int code) {
    uint64_t hash = host_hash(hostname);
    size_t slot;
    if (sceKernelLockMutex(browser.rejected_mutex, 1, NULL) < 0) return;
    for (slot = 0; slot < BROWSER_REJECTED_HOSTS; ++slot) {
        if (browser.rejected_codes[slot] != 0 && browser.rejected_hosts[slot] == hash) break;
    }
    if (slot == BROWSER_REJECTED_HOSTS) {
        slot = browser.rejected_next;
        browser.rejected_next = (browser.rejected_next + 1) % BROWSER_REJECTED_HOSTS;
    }
    browser.rejected_hosts[slot] = hash;
    browser.rejected_codes[slot] = code;
    (void)sceKernelUnlockMutex(browser.rejected_mutex, 1);
}

/* The error the host's certificate got here, or 0 */
static int rejected_code(const char *hostname) {
    uint64_t hash = host_hash(hostname);
    int code = 0;
    if (sceKernelLockMutex(browser.rejected_mutex, 1, NULL) < 0) return VITALS_CURLE_SSL_CONNECT_ERROR;
    for (size_t slot = 0; slot < BROWSER_REJECTED_HOSTS && code == 0; ++slot) {
        if (browser.rejected_codes[slot] != 0 && browser.rejected_hosts[slot] == hash)
            code = browser.rejected_codes[slot];
    }
    (void)sceKernelUnlockMutex(browser.rejected_mutex, 1);
    return code;
}

size_t vitals_browser_connection_count(void) {
    return browser.initialized ? vitals_registry_count(&browser.registry) : 0;
}

/* curl's socket doesn't block: nothing to give or no room is VITALS_SSL_WOULD_BLOCK, and libssl's
 * call then says to wait; anything else is the connection's failure, kept for the log */
static int bio_result(BrowserConnection *connection, int result) {
    if (result >= 0) return result;
    if ((uint32_t)result == (uint32_t)SCE_NET_ERROR_EAGAIN || (uint32_t)result == (uint32_t)SCE_NET_ERROR_EINTR)
        return VITALS_SSL_WOULD_BLOCK;
    connection->net_error = result;
    return result;
}

static int browser_send(void *context, const unsigned char *data, size_t size) {
    BrowserConnection *connection = context;
    int result;
    if (__atomic_load_n(&connection->closing, __ATOMIC_ACQUIRE) && !connection->notifying_close)
        return (int)SCE_NET_ERROR_ECONNABORTED;
    if (size > INT_MAX) return (int)SCE_NET_ERROR_EINVAL;
    result = sceNetSend(connection->socket, data, (unsigned int)size, SCE_NET_MSG_DONTWAIT);
    if (result == 0 && size != 0) return (int)SCE_NET_ERROR_EPIPE;
    return bio_result(connection, result);
}

static int browser_recv(void *context, unsigned char *data, size_t size) {
    BrowserConnection *connection = context;
    int result;
    if (__atomic_load_n(&connection->closing, __ATOMIC_ACQUIRE)) return (int)SCE_NET_ERROR_ECONNABORTED;
    if (size > INT_MAX) return (int)SCE_NET_ERROR_EINVAL;
    result = sceNetRecv(connection->socket, data, (unsigned int)size, SCE_NET_MSG_DONTWAIT);
    return bio_result(connection, result);
}

/* A page's own CA file, whole, into a store: the store, or NULL when it can't be read or has no
 * certificate */
static void *load_ca_file(const char *path) {
    void *store = NULL;
    unsigned char *data = NULL;
    int fd = sceIoOpen(path, SCE_O_RDONLY, 0);
    int64_t size;
    if (fd < 0) return NULL;
    size = sceIoLseek(fd, 0, SCE_SEEK_END);
    if (size <= 0 || size > BROWSER_CA_FILE_MAX || sceIoLseek(fd, 0, SCE_SEEK_SET) != 0) goto done;
    data = malloc((size_t)size + 1u);
    if (data == NULL) goto done;
    for (int64_t read = 0; read < size;) {
        int got = sceIoRead(fd, data + read, (unsigned int)(size - read));
        if (got <= 0) goto done;
        read += got;
    }
    data[size] = '\0';
    store = vitalsSslStoreNew();
    if (store != NULL && vitalsSslStoreAdd(store, data, (size_t)size) != 0) {
        vitalsSslStoreRelease(store);
        store = NULL;
    }
done:
    free(data);
    (void)sceIoClose(fd);
    return store;
}

/* IANA numbers of the suites offered: TLS 1.3's, then the TLS 1.2 ones the page's list allows */
#define SUITE_TLS1_3_AES_128_GCM_SHA256 0x1301
#define SUITE_TLS1_3_AES_256_GCM_SHA384 0x1302
#define SUITE_TLS1_3_CHACHA20_POLY1305_SHA256 0x1303

static int initialize_connection(BrowserConnection *connection, uint32_t cipher_mask) {
    static const char *const alpn[] = {"http/1.1", NULL};
    static const int tls12[] = {
        0xC02F, /* ECDHE-RSA-AES128-GCM-SHA256 */
        0xC030, /* ECDHE-RSA-AES256-GCM-SHA384 */
        0xC02B, /* ECDHE-ECDSA-AES128-GCM-SHA256 */
        0xC02C  /* ECDHE-ECDSA-AES256-GCM-SHA384 */
    };
    void *library = NULL, *context, *bio, *store = NULL;
    size_t count = 0;
    int result;

    connection->ciphers[count++] = SUITE_TLS1_3_AES_128_GCM_SHA256;
    connection->ciphers[count++] = SUITE_TLS1_3_AES_256_GCM_SHA384;
    connection->ciphers[count++] = SUITE_TLS1_3_CHACHA20_POLY1305_SHA256;
    for (size_t i = 0; i < sizeof(tls12)/sizeof(tls12[0]); ++i) {
        if (cipher_mask & (UINT32_C(1) << i)) connection->ciphers[count++] = tls12[i];
    }
    connection->ciphers[count] = 0;
    /* A certificate file the page's own configuration names is the only trust, for that one
     * connection */
    if (connection->custom_ca_requested) {
        store = load_ca_file(connection->ca_file);
        if (store == NULL) return VITALS_CURLE_SSL_CACERT_BADFILE;
    }
    if (sceSslInternalGetLibrary(&library) != 0) {
        if (store != NULL) vitalsSslStoreRelease(store);
        return VITALS_CURLE_SSL_CONNECT_ERROR;
    }
    context = sceSslInternalCtxNew(library, sceSslInternalClientMethod());
    if (context == NULL) {
        if (store != NULL) vitalsSslStoreRelease(store);
        return VITALS_CURLE_OUT_OF_MEMORY;
    }
    /* Verified, but decided after the handshake from curl's options */
    sceSslInternalCtxSetVerify(context, 1);
    result = vitalsSslCtxSetDeferredVerify(context, 1);
    if (result == 0) result = vitalsSslCtxSetCiphersuites(context, connection->ciphers);
    if (result == 0) result = vitalsSslCtxSetAlpn(context, alpn);
    if (result == 0 && store != NULL) result = vitalsSslCtxSetStore(context, store);
    if (result == 0 && store != NULL) result = vitalsSslCtxSetTrustBundle(context, 0);
    if (store != NULL) vitalsSslStoreRelease(store);
    if (result == 0) {
        connection->ssl = sceSslInternalNew(context);
        if (connection->ssl == NULL) result = VITALS_CURLE_OUT_OF_MEMORY;
    }
    /* The connection keeps the context */
    sceSslInternalCtxFree(context);
    if (result != 0) return result == VITALS_CURLE_OUT_OF_MEMORY ? result : VITALS_CURLE_SSL_CONNECT_ERROR;
    bio = vitalsSslBioNew(browser_send, browser_recv, connection);
    if (bio == NULL) return VITALS_CURLE_OUT_OF_MEMORY;
    (void)sceSslInternalBioCtrl(bio, VITALS_SSL_BIO_SET_HOST, 0, connection->hostname);
    sceSslInternalSetBio(connection->ssl, bio, bio);
    sceSslInternalSetConnectState(connection->ssl);
    connection->state = BROWSER_HANDSHAKING;
    return 0;
}

static void release_connection(VitalsRegistryHandle *handle, BrowserConnection *connection) {
    (void)sceKernelUnlockMutex(connection->mutex, 1);
    (void)vitals_registry_release(&browser.registry, handle);
}

static int acquire_connection(void *native, int index, VitalsRegistryHandle *handle,
    BrowserConnection **connection, int *handled) {
    int result;
    *handled = 0;
    if (!browser.initialized) return 0;
    if (native == NULL || index < 0 || index > 1) { *handled = 1; return VITALS_CURLE_BAD_FUNCTION_ARGUMENT; }
    if (sceKernelLockMutex(browser.attach_mutex, 1, NULL) < 0) { *handled = 1; return VITALS_CURLE_SSL_CONNECT_ERROR; }
    result = vitals_registry_acquire(&browser.registry, connection_key(native, index), handle);
    (void)sceKernelUnlockMutex(browser.attach_mutex, 1);
    if (result == VITALS_REGISTRY_NOT_FOUND) return 0;
    *handled = 1;
    if (result != VITALS_REGISTRY_OK) return VITALS_CURLE_AGAIN;
    *connection = handle->payload;
    if (sceKernelTryLockMutex((*connection)->mutex, 1) < 0) {
        (void)vitals_registry_release(&browser.registry, handle);
        return VITALS_CURLE_AGAIN;
    }
    if (__atomic_load_n(&(*connection)->closing, __ATOMIC_ACQUIRE)) {
        release_connection(handle, *connection);
        return VITALS_CURLE_ABORTED_BY_CALLBACK;
    }
    return 0;
}

static int create_or_acquire(void *native, int index, VitalsRegistryHandle *handle,
    BrowserConnection **output, int *handled) {
    VitalsBrowserOptions options;
    BrowserConnection *connection;
    size_t native_ssl = ssl_offset(index);
    const char *unverified_host;
    int result;

    *handled = 0;
    if (!browser.initialized) return 0;
    if (sceKernelLockMutex(browser.attach_mutex, 1, NULL) < 0) { *handled = 1; return VITALS_CURLE_SSL_CONNECT_ERROR; }
    result = vitals_registry_acquire(&browser.registry, connection_key(native, index), handle);
    if (result == VITALS_REGISTRY_OK) {
        (void)sceKernelUnlockMutex(browser.attach_mutex, 1);
        *handled = 1;
        connection = handle->payload;
        if (sceKernelTryLockMutex(connection->mutex, 1) < 0) {
            (void)vitals_registry_release(&browser.registry, handle);
            return VITALS_CURLE_AGAIN;
        }
        *output = connection;
        return 0;
    }
    if (result != VITALS_REGISTRY_NOT_FOUND) {
        *handled = 1;
        result = VITALS_CURLE_AGAIN;
        goto unlock;
    }
    if (!__atomic_load_n(&browser.enabled, __ATOMIC_ACQUIRE) ||
        vitals_read_u32(native, native_ssl + VITALS_CURL_SSL_HANDLE_OFFSET) != 0 ||
        vitals_read_u32(native, native_ssl + VITALS_CURL_SSL_CONTEXT_OFFSET) != 0) {
        result = 0;
        goto unlock;
    }
    unverified_host = vitals_browser_unverified_host(native);
    if (unverified_host != NULL && (result = rejected_code(unverified_host)) != 0) {
        VITALS_LOG("browser refused unverified retry: code=%d", result);
        *handled = 1;
        goto unlock;
    }
    result = vitals_browser_read_options(native, (unsigned int)index, browser.ops.default_ciphers,
        browser.ops.is_default_ctx_callback, &options);
    if (result == VITALS_BROWSER_CONFIG_LEGACY) {
        VITALS_LOG("browser connection uses legacy TLS: unsupported custom configuration");
        result = 0;
        goto unlock;
    }
    if (result != 0) { result = VITALS_CURLE_BAD_FUNCTION_ARGUMENT; goto unlock; }
    if (options.ca_file == NULL) {
        result = ensure_default_ca();
        if (result != 0) {
            VITALS_LOG("browser default trust initialization failed: 0x%08X; using legacy TLS", result);
            result = 0;
            goto unlock;
        }
    }
    result = ensure_library();
    if (result != 0) {
        VITALS_LOG("browser libssl unavailable: 0x%08X; using legacy TLS", result);
        result = 0;
        goto unlock;
    }
    *handled = 1;
    connection = calloc(1, sizeof(*connection));
    if (connection == NULL) { result = VITALS_CURLE_OUT_OF_MEMORY; goto unlock; }
    connection->mutex = sceKernelCreateMutex("vitals browser connection", 0, 0, NULL);
    if (connection->mutex < 0) { free(connection); result = VITALS_CURLE_OUT_OF_MEMORY; goto unlock; }
    connection->native = native;
    connection->index = index;
    connection->socket = options.socket;
    connection->verify_peer = options.verify_peer;
    connection->verify_host = options.verify_host;
    connection->custom_ca_requested = options.ca_file != NULL;
    memcpy(connection->hostname, options.hostname, strlen(options.hostname) + 1);
    if (options.ca_file != NULL) memcpy(connection->ca_file, options.ca_file, strlen(options.ca_file) + 1);
    connection->old_recv = vitals_read_u32(native, VITALS_CURL_RECV_OFFSET + 4 * (size_t)(unsigned int)index);
    connection->old_send = vitals_read_u32(native, VITALS_CURL_SEND_OFFSET + 4 * (size_t)(unsigned int)index);
    if (sceKernelLockMutex(connection->mutex, 1, NULL) < 0) {
        free_connection(NULL, connection);
        result = VITALS_CURLE_OUT_OF_MEMORY;
        goto unlock;
    }
    result = vitals_registry_insert(&browser.registry, connection_key(native, index), connection);
    if (result != VITALS_REGISTRY_OK) {
        (void)sceKernelUnlockMutex(connection->mutex, 1);
        free_connection(NULL, connection);
        result = VITALS_CURLE_OUT_OF_MEMORY;
        goto unlock;
    }
    result = vitals_registry_acquire(&browser.registry, connection_key(native, index), handle);
    if (result != VITALS_REGISTRY_OK) {
        (void)sceKernelUnlockMutex(connection->mutex, 1);
        (void)vitals_registry_remove(&browser.registry, connection_key(native, index));
        result = VITALS_CURLE_SSL_CONNECT_ERROR;
        goto unlock;
    }
    vitals_write_u32(native, native_ssl + VITALS_CURL_SSL_STATE_OFFSET, 1);
    vitals_write_u32(native, native_ssl + VITALS_CURL_SSL_CONNECTING_OFFSET, 1);
    (void)sceKernelUnlockMutex(browser.attach_mutex, 1);
    result = initialize_connection(connection, options.tls12_suites);
    if (result != 0) {
        VITALS_LOG("browser connection setup failed: socket=%d code=%d", connection->socket, result);
        connection->state = BROWSER_FAILED;
        connection->error = result;
    }
    *output = connection;
    return 0;
unlock:
    (void)sceKernelUnlockMutex(browser.attach_mutex, 1);
    return result;
}

/* OpenSSL's verify result for curl, from libssl's certificate flags (VITALS_CERT_*) */
static uint32_t verification_code(uint32_t flags) {
    if (flags == 0) return 0;
    if (flags & VITALS_CERT_HOSTNAME) return 62;
    if (flags & VITALS_CERT_EXPIRED) return 10;
    if (flags & VITALS_CERT_FUTURE) return 9;
    if (flags & VITALS_CERT_UNKNOWN_CA) return 20;
    return 1;
}

static int verify_connection(BrowserConnection *connection, void *easy) {
    uint32_t flags = vitalsSslGetCertificateFlags(connection->ssl);
    uint32_t chain_flags = flags & ~VITALS_CERT_HOSTNAME;
    /* Mbed TLS's check didn't run: no certificate came */
    if (vitalsSslGetVerifyResult(connection->ssl) == UINT32_MAX) {
        vitals_write_u32(easy, VITALS_CURL_VERIFY_RESULT_OFFSET, 1);
        return VITALS_CURLE_SSL_CONNECT_ERROR;
    }
    vitals_write_u32(easy, VITALS_CURL_VERIFY_RESULT_OFFSET, verification_code(flags));
    if (connection->verify_peer && chain_flags != 0) return VITALS_CURLE_SSL_CACERT;
    if (connection->verify_host && (flags & VITALS_CERT_HOSTNAME)) {
        return VITALS_CURLE_PEER_FAILED_VERIFICATION;
    }
    return 0;
}

int vitals_browser_connect(void *native, int index, unsigned char nonblocking,
    unsigned char *done, int *handled) {
    VitalsRegistryHandle handle;
    BrowserConnection *connection = NULL;
    void *easy;
    int result;

    if (handled == NULL) return VITALS_CURLE_BAD_FUNCTION_ARGUMENT;
    *handled = 0;
    if (done == NULL || native == NULL || index < 0 || index > 1) {
        *handled = 1;
        return VITALS_CURLE_BAD_FUNCTION_ARGUMENT;
    }
    *done = 0;
    result = create_or_acquire(native, index, &handle, &connection, handled);
    if (!*handled) return result;
    if (result != 0) return result == VITALS_CURLE_AGAIN ? 0 : result;
    easy = (void *)(uintptr_t)vitals_read_u32(native, VITALS_CURL_EASY_OFFSET);
    if (__atomic_load_n(&connection->closing, __ATOMIC_ACQUIRE) || easy == NULL) {
        result = VITALS_CURLE_ABORTED_BY_CALLBACK;
        goto failed;
    }
    if (connection->state == BROWSER_ACTIVE) { *done = 1; result = 0; goto finished; }
    if (connection->state == BROWSER_FAILED) { result = connection->error; goto finished; }
    if (connection->state != BROWSER_HANDSHAKING) { result = VITALS_CURLE_SSL_CONNECT_ERROR; goto failed; }

    for (;;) {
        int remaining = browser.ops.timeleft(easy, NULL, 1);
        if (__atomic_load_n(&connection->closing, __ATOMIC_ACQUIRE)) {
            result = VITALS_CURLE_ABORTED_BY_CALLBACK;
            goto failed;
        }
        if (remaining < 0) { result = VITALS_CURLE_OPERATION_TIMEDOUT; goto failed; }
        if (connection->want != 0) {
            int timeout = nonblocking ? 0 :
                (remaining == 0 || remaining > BROWSER_POLL_SLICE_MS ? BROWSER_POLL_SLICE_MS : remaining);
            result = browser.ops.socket_wait(connection->want == 2 ? connection->socket : -1,
                -1, connection->want == 3 ? connection->socket : -1, timeout);
            if (result < 0) { result = VITALS_CURLE_SSL_CONNECT_ERROR; goto failed; }
            if (result == 0) {
                if (nonblocking) { result = 0; goto finished; }
                continue;
            }
        }
        connection->net_error = 0;
        result = vitalsSslHandshake(connection->ssl);
        if (result != 1) {
            int kind = sceSslInternalGetError(connection->ssl, result);
            /* As Sony's, libssl reports any failed receive as a wait: the socket's own error says */
            if ((kind == VITALS_SSL_KIND_WANT_READ || kind == VITALS_SSL_KIND_WANT_WRITE) &&
                connection->net_error == 0) {
                connection->want = kind;
                vitals_write_u32(native, ssl_offset(index) + VITALS_CURL_SSL_CONNECTING_OFFSET,
                    (uint32_t)connection->want);
                if (nonblocking) { result = 0; goto finished; }
                continue;
            }
            uint32_t flags = vitalsSslGetCertificateFlags(connection->ssl);
            VITALS_LOG("browser handshake failed: tls=0x%08X net=0x%08X verify=0x%08X",
                vitalsSslGetTlsError(connection->ssl), connection->net_error,
                vitalsSslGetVerifyResult(connection->ssl));
            if ((uint32_t)connection->net_error == (uint32_t)SCE_NET_ERROR_ETIMEDOUT)
                result = VITALS_CURLE_OPERATION_TIMEDOUT;
            else if (flags != 0) {
                vitals_write_u32(easy, VITALS_CURL_VERIFY_RESULT_OFFSET, verification_code(flags));
                result = VITALS_CURLE_SSL_CACERT;
            } else result = VITALS_CURLE_SSL_CONNECT_ERROR;
            goto failed;
        }
        result = verify_connection(connection, easy);
        if (result != 0) goto failed;
        connection->state = BROWSER_ACTIVE;
        connection->want = 0;
        vitals_write_u32(native, ssl_offset(index) + VITALS_CURL_SSL_STATE_OFFSET, 2);
        vitals_write_u32(native, ssl_offset(index) + VITALS_CURL_SSL_CONNECTING_OFFSET, 0);
        vitals_write_u32(native, VITALS_CURL_RECV_OFFSET + 4 * (size_t)(unsigned int)index,
            (uint32_t)(uintptr_t)vitals_browser_recv);
        vitals_write_u32(native, VITALS_CURL_SEND_OFFSET + 4 * (size_t)(unsigned int)index,
            (uint32_t)(uintptr_t)vitals_browser_send);
        VITALS_LOG("browser handshake complete: socket=%d version=%s cipher=%s", connection->socket,
            vitalsSslGetVersion(connection->ssl), vitalsSslGetCiphersuite(connection->ssl));
        *done = 1;
        goto finished;
    }
failed:
    VITALS_LOG("browser connect rejected: socket=%d code=%d", connection->socket, result);
    if (result == VITALS_CURLE_SSL_CACERT || result == VITALS_CURLE_PEER_FAILED_VERIFICATION)
        remember_rejected(connection->hostname, result);
    connection->state = BROWSER_FAILED;
    connection->error = result;
finished:
    release_connection(&handle, connection);
    return result;
}

/* libssl's read or write result for curl: bytes, 0 at the server's close_notify, or -1 with the
 * error (CURLE_AGAIN to wait) */
static int map_io(BrowserConnection *connection, int result, int sending, int *error) {
    int kind;
    if (result > 0) { *error = 0; return result; }
    kind = sceSslInternalGetError(connection->ssl, result);
    if ((kind == VITALS_SSL_KIND_WANT_READ || kind == VITALS_SSL_KIND_WANT_WRITE) && connection->net_error == 0) {
        *error = VITALS_CURLE_AGAIN;
        return -1;
    }
    if (!sending && result == 0 && kind == VITALS_SSL_KIND_ZERO_RETURN) {
        connection->state = BROWSER_EOF;
        *error = 0;
        return 0;
    }
    connection->state = BROWSER_FAILED;
    connection->error = sending ? VITALS_CURLE_SEND_ERROR : VITALS_CURLE_RECV_ERROR;
    *error = connection->error;
    return -1;
}

int vitals_browser_recv(void *native, int index, void *data, unsigned int length, int *error) {
    VitalsRegistryHandle handle;
    BrowserConnection *connection = NULL;
    int handled, result;
    if (error == NULL) return -1;
    *error = VITALS_CURLE_RECV_ERROR;
    result = acquire_connection(native, index, &handle, &connection, &handled);
    if (result != 0 || !handled) { if (result == VITALS_CURLE_AGAIN) *error = result; return -1; }
    if (connection->state == BROWSER_EOF || length == 0) { *error = 0; result = 0; goto finished; }
    if (connection->state != BROWSER_ACTIVE || data == NULL) { result = -1; goto finished; }
    if (connection->pending_length != 0) { *error = VITALS_CURLE_AGAIN; result = -1; goto finished; }
    if (connection->lookahead_valid) {
        *(unsigned char *)data = connection->lookahead;
        connection->lookahead_valid = 0;
        *error = 0;
        result = 1;
        goto finished;
    }
    if (length > BROWSER_IO_CHUNK) length = BROWSER_IO_CHUNK;
    /* libssl reads past TLS 1.3's session tickets itself */
    connection->net_error = 0;
    result = sceSslInternalRead(connection->ssl, data, (int)length);
    result = map_io(connection, result, 0, error);
finished:
    release_connection(&handle, connection);
    return result;
}

int vitals_browser_send(void *native, int index, const void *data, unsigned int length, int *error) {
    VitalsRegistryHandle handle;
    BrowserConnection *connection = NULL;
    int handled, result;
    if (error == NULL) return -1;
    *error = VITALS_CURLE_SEND_ERROR;
    result = acquire_connection(native, index, &handle, &connection, &handled);
    if (result != 0 || !handled) { if (result == VITALS_CURLE_AGAIN) *error = result; return -1; }
    if (connection->state != BROWSER_ACTIVE || (length != 0 && data == NULL)) { result = -1; goto finished; }
    if (length > BROWSER_IO_CHUNK) length = BROWSER_IO_CHUNK;
    if (connection->pending_length != 0 && (length != connection->pending_length ||
        memcmp(data, connection->pending_write, length) != 0)) {
        connection->state = BROWSER_FAILED;
        connection->error = VITALS_CURLE_SEND_ERROR;
        result = -1;
        goto clear;
    }
    if (length == 0) { *error = 0; result = 0; goto finished; }
    if (connection->pending_length == 0) {
        memcpy(connection->pending_write, data, length);
        connection->pending_length = length;
    }
    connection->net_error = 0;
    result = sceSslInternalWrite(connection->ssl, connection->pending_write, (int)connection->pending_length);
    result = map_io(connection, result, 1, error);
    if (*error == VITALS_CURLE_AGAIN) goto finished;
clear:
    wipe(connection->pending_write, sizeof(connection->pending_write));
    connection->pending_length = 0;
finished:
    release_connection(&handle, connection);
    return result;
}

int vitals_browser_pending(void *native, int index, int *handled) {
    VitalsRegistryHandle handle;
    BrowserConnection *connection = NULL;
    int result;
    if (handled == NULL) return 0;
    result = acquire_connection(native, index, &handle, &connection, handled);
    if (result != 0 || !*handled) return 0;
    result = connection->state == BROWSER_ACTIVE && connection->pending_length == 0 &&
        (connection->lookahead_valid || vitalsSslCheckPending(connection->ssl));
    release_connection(&handle, connection);
    return result;
}

int vitals_browser_check(void *native, int *handled) {
    VitalsRegistryHandle handle;
    BrowserConnection *connection = NULL;
    int result;

    if (handled == NULL) return -1;
    result = acquire_connection(native, 0, &handle, &connection, handled);
    if (result != 0 || !*handled) return -1;
    if (connection->state == BROWSER_EOF || connection->state == BROWSER_FAILED) {
        result = 0;
        goto finished;
    }
    if (connection->state != BROWSER_ACTIVE || connection->pending_length != 0) {
        result = -1;
        goto finished;
    }
    if (connection->lookahead_valid || sceSslInternalPending(connection->ssl) != 0) {
        result = 1;
        goto finished;
    }
    connection->net_error = 0;
    result = sceSslInternalRead(connection->ssl, &connection->lookahead, 1);
    int kind = result > 0 ? VITALS_SSL_KIND_NONE : sceSslInternalGetError(connection->ssl, result);
    if (result > 0) {
        connection->lookahead_valid = 1;
        result = 1;
    } else if ((kind == VITALS_SSL_KIND_WANT_READ || kind == VITALS_SSL_KIND_WANT_WRITE) &&
        connection->net_error == 0) {
        result = -1;
    } else if (result == 0 && kind == VITALS_SSL_KIND_ZERO_RETURN) {
        connection->state = BROWSER_EOF;
        result = 0;
    } else {
        connection->state = BROWSER_FAILED;
        connection->error = VITALS_CURLE_RECV_ERROR;
        result = 0;
    }
finished:
    release_connection(&handle, connection);
    return result;
}

int vitals_browser_close(void *native, int index, int *handled) {
    VitalsRegistryHandle handle;
    BrowserConnection *connection;
    int result;
    if (handled == NULL) return VITALS_CURLE_BAD_FUNCTION_ARGUMENT;
    *handled = 0;
    if (!browser.initialized) return 0;
    if (native == NULL || index < 0 || index > 1) { *handled = 1; return VITALS_CURLE_BAD_FUNCTION_ARGUMENT; }
    if (sceKernelLockMutex(browser.attach_mutex, 1, NULL) < 0) { *handled = 1; return VITALS_CURLE_SSL_CONNECT_ERROR; }
    result = vitals_registry_acquire(&browser.registry, connection_key(native, index), &handle);
    if (result != VITALS_REGISTRY_OK) {
        (void)sceKernelUnlockMutex(browser.attach_mutex, 1);
        *handled = result != VITALS_REGISTRY_NOT_FOUND;
        return 0;
    }
    *handled = 1;
    connection = handle.payload;
    __atomic_store_n(&connection->closing, 1, __ATOMIC_RELEASE);
    (void)sceKernelUnlockMutex(browser.attach_mutex, 1);
    if (sceKernelLockMutex(connection->mutex, 1, NULL) < 0) {
        (void)vitals_registry_release(&browser.registry, &handle);
        return VITALS_CURLE_SSL_CONNECT_ERROR;
    }
    if (connection->native != NULL) {
        /* BIO cancellation stays set: teardown must not flush pending application data */
        if ((connection->state == BROWSER_ACTIVE || connection->state == BROWSER_EOF) &&
            connection->pending_length == 0) {
            connection->notifying_close = 1;
            (void)sceSslInternalShutdown(connection->ssl);
            connection->notifying_close = 0;
        }
        vitals_write_u32(native, VITALS_CURL_RECV_OFFSET + 4 * (size_t)(unsigned int)index, connection->old_recv);
        vitals_write_u32(native, VITALS_CURL_SEND_OFFSET + 4 * (size_t)(unsigned int)index, connection->old_send);
        vitals_write_u32(native, ssl_offset(index) + VITALS_CURL_SSL_STATE_OFFSET, 0);
        vitals_write_u32(native, ssl_offset(index) + VITALS_CURL_SSL_CONNECTING_OFFSET, 0);
        connection->native = NULL;
        (void)vitals_registry_remove(&browser.registry, connection_key(native, index));
    }
    release_connection(&handle, connection);
    return 0;
}
