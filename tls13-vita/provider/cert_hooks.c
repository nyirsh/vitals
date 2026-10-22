#include "cert_hooks.h"

#include "diagnostics.h"
#include "http_trace.h"
#include "provider.h"

#include <psp2/kernel/threadmgr/mutex.h>
#include <psp2/net/http.h>

#include <mbedtls/platform.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define VITALS_SCE_HTTP_LIBRARY_NID UINT32_C(0xE8F15CDE)
#define VITALS_NID_HTTPS_LOAD_CERT UINT32_C(0xAE8D7C33)
#define VITALS_NID_HTTPS_UNLOAD_CERT UINT32_C(0x8577833F)

typedef int (*VitalsHttpsCallback)(
    unsigned int verification_error,
    void *const certificates[],
    int certificate_count,
    void *user_argument);

static int g_https_load_cert_hook_id = -1;
static int g_https_unload_cert_hook_id = -1;
static tai_hook_ref_t g_https_load_cert_hook_ref;
static tai_hook_ref_t g_https_unload_cert_hook_ref;
static uint32_t g_legacy_certificates_loaded;
/* CA certificates a game loaded with sceHttpsLoadCert, trusted in addition to the bundle
 * Guarded by the registry mutex; handshakes copy matching entries out under it */
static mbedtls_x509_crt *g_game_cas;

static void *next_hook_function(tai_hook_ref_t reference) {
    struct _tai_hook_user *current = (struct _tai_hook_user *)reference;
    struct _tai_hook_user *next = (struct _tai_hook_user *)current->next;

    return next == NULL ? current->old : next->func;
}

static void free_game_cas(void) {
    if (sceKernelLockMutex(g_vitals_http.registry_mutex, 1, NULL) < 0) return;
    mbedtls_x509_crt *previous = g_game_cas;
    g_game_cas = NULL;
    (void)sceKernelUnlockMutex(g_vitals_http.registry_mutex, 1);
    if (previous != NULL) {
        mbedtls_x509_crt_free(previous);
        mbedtls_free(previous);
    }
}

static int contains_pem_marker(const char *data, unsigned int size) {
    static const char marker[] = "-----BEGIN";
    for (unsigned int i = 0; i + sizeof(marker) - 1u <= size; ++i) {
        if (memcmp(data + i, marker, sizeof(marker) - 1u) == 0) return 1;
    }
    return 0;
}

/* Parses the game's PEM or DER certificates into a fresh chain that replaces the previous
 * one, matching sceHttpsLoadCert replacing earlier material
 * Returns the number parsed */
static int load_game_cas(int count, const SceHttpsData **certificates) {
    mbedtls_x509_crt *chain = mbedtls_calloc(1, sizeof(*chain));
    int added = 0;

    if (chain == NULL) return -1;
    mbedtls_x509_crt_init(chain);
    for (int i = 0; i < count; ++i) {
        const SceHttpsData *data = certificates[i];
        if (data == NULL || data->ptr == NULL || data->size == 0) continue;
        int parsed;
        if (contains_pem_marker(data->ptr, data->size)) {
            /* PEM parsing requires a terminating NUL that the game need not supply */
            unsigned char *pem = malloc((size_t)data->size + 1u);
            if (pem == NULL) continue;
            memcpy(pem, data->ptr, data->size);
            pem[data->size] = '\0';
            parsed = mbedtls_x509_crt_parse(chain, pem, (size_t)data->size + 1u);
            free(pem);
        } else {
            parsed = mbedtls_x509_crt_parse_der(chain, (const unsigned char *)data->ptr, data->size);
        }
        VITALS_VERBOSE("event=game_ca.parse index=%d size=%u rc=%08X", i, data->size, parsed);
        if (parsed >= 0) ++added;
    }
    if (added == 0) {
        mbedtls_x509_crt_free(chain);
        mbedtls_free(chain);
        return 0;
    }
    if (sceKernelLockMutex(g_vitals_http.registry_mutex, 1, NULL) < 0) {
        mbedtls_x509_crt_free(chain);
        mbedtls_free(chain);
        return -1;
    }
    mbedtls_x509_crt *previous = g_game_cas;
    g_game_cas = chain;
    (void)sceKernelUnlockMutex(g_vitals_http.registry_mutex, 1);
    if (previous != NULL) {
        mbedtls_x509_crt_free(previous);
        mbedtls_free(previous);
    }
    return added;
}

int vitals_game_ca_find(const mbedtls_x509_crt *child, mbedtls_x509_crt **candidates) {
    mbedtls_x509_crt *head = *candidates;
    int allocated = 0, result = 0;

    if (__atomic_load_n(&g_game_cas, __ATOMIC_ACQUIRE) == NULL) return 0;
    if (head == NULL) {
        head = mbedtls_calloc(1, sizeof(*head));
        if (head == NULL) return MBEDTLS_ERR_X509_ALLOC_FAILED;
        mbedtls_x509_crt_init(head);
        allocated = 1;
    }
    if (sceKernelLockMutex(g_vitals_http.registry_mutex, 1, NULL) < 0) {
        result = -1;
        goto done;
    }
    for (const mbedtls_x509_crt *ca = g_game_cas; ca != NULL && ca->raw.p != NULL; ca = ca->next) {
        if (ca->subject_raw.len == child->issuer_raw.len &&
            memcmp(ca->subject_raw.p, child->issuer_raw.p, ca->subject_raw.len) == 0)
            (void)mbedtls_x509_crt_parse_der(head, ca->raw.p, ca->raw.len);
    }
    (void)sceKernelUnlockMutex(g_vitals_http.registry_mutex, 1);
done:
    if (allocated && (result != 0 || head->raw.p == NULL)) {
        mbedtls_x509_crt_free(head);
        mbedtls_free(head);
        return result;
    }
    *candidates = head;
    return result;
}

static int hook_https_load_cert(
    int certificate_count,
    const SceHttpsData **certificates,
    const SceHttpsData *client_certificate,
    const SceHttpsData *private_key) {
    typedef int (*Continuation)(
        int,
        const SceHttpsData **,
        const SceHttpsData *,
        const SceHttpsData *);
    int result = ((Continuation)next_hook_function(g_https_load_cert_hook_ref))(
        certificate_count,
        certificates,
        client_certificate,
        private_key);

    VITALS_LOG("https load cert count=%d client=%d key=%d rc=%08X", certificate_count,
        client_certificate != NULL, private_key != NULL, (unsigned int)result);
    if (result < 0) return result;
    /* The provider cannot present a client identity; those connections stay on BSAFE */
    if (client_certificate != NULL || private_key != NULL) {
        __atomic_store_n(&g_legacy_certificates_loaded, 1, __ATOMIC_RELEASE);
        VITALS_LOG("client certificate material loaded; new connections use BSAFE");
    } else if (certificate_count > 0 && certificates != NULL) {
        int added = load_game_cas(certificate_count, certificates);
        VITALS_LOG("game CA certificates trusted=%d of %d", added, certificate_count);
        if (added <= 0) {
            __atomic_store_n(&g_legacy_certificates_loaded, 1, __ATOMIC_RELEASE);
            VITALS_LOG("custom certificate material unreadable; new connections use BSAFE");
        }
    }
    return result;
}

static int hook_https_unload_cert(void) {
    typedef int (*Continuation)(void);
    int result = ((Continuation)next_hook_function(g_https_unload_cert_hook_ref))();

    VITALS_LOG("https unload cert rc=%08X", (unsigned int)result);
    if (result >= 0) {
        __atomic_store_n(&g_legacy_certificates_loaded, 0, __ATOMIC_RELEASE);
        free_game_cas();
        VITALS_LOG("custom certificate material unloaded; provider connections enabled");
    }
    return result;
}

int vitals_cert_hooks_install(void) {
    g_https_load_cert_hook_id = -1;
    g_https_unload_cert_hook_id = -1;
    memset(&g_https_load_cert_hook_ref, 0, sizeof(g_https_load_cert_hook_ref));
    memset(&g_https_unload_cert_hook_ref, 0, sizeof(g_https_unload_cert_hook_ref));
    __atomic_store_n(&g_legacy_certificates_loaded, 0, __ATOMIC_RELEASE);

    g_https_load_cert_hook_id = taiHookFunctionExport(
        &g_https_load_cert_hook_ref,
        "SceLibHttp",
        VITALS_SCE_HTTP_LIBRARY_NID,
        VITALS_NID_HTTPS_LOAD_CERT,
        hook_https_load_cert);
    VITALS_VERBOSE("event=hook.install kind=load_cert nid=%08X rc=%08X",
        VITALS_NID_HTTPS_LOAD_CERT, g_https_load_cert_hook_id);
    if (g_https_load_cert_hook_id < 0) {
        vitals_cert_hooks_release();
        return g_https_load_cert_hook_id;
    }

    g_https_unload_cert_hook_id = taiHookFunctionExport(
        &g_https_unload_cert_hook_ref,
        "SceLibHttp",
        VITALS_SCE_HTTP_LIBRARY_NID,
        VITALS_NID_HTTPS_UNLOAD_CERT,
        hook_https_unload_cert);
    VITALS_VERBOSE("event=hook.install kind=unload_cert nid=%08X rc=%08X",
        VITALS_NID_HTTPS_UNLOAD_CERT, g_https_unload_cert_hook_id);
    if (g_https_unload_cert_hook_id < 0) {
        vitals_cert_hooks_release();
        return g_https_unload_cert_hook_id;
    }

    vitals_http_trace_install();
    return 0;
}

void vitals_cert_hooks_release(void) {
    __atomic_store_n(&g_legacy_certificates_loaded, 0, __ATOMIC_RELEASE);
    free_game_cas();
    vitals_http_trace_release();
    if (g_https_unload_cert_hook_id >= 0) {
        taiHookRelease(g_https_unload_cert_hook_id, g_https_unload_cert_hook_ref);
        g_https_unload_cert_hook_id = -1;
        memset(&g_https_unload_cert_hook_ref, 0, sizeof(g_https_unload_cert_hook_ref));
    }
    if (g_https_load_cert_hook_id >= 0) {
        taiHookRelease(g_https_load_cert_hook_id, g_https_load_cert_hook_ref);
        g_https_load_cert_hook_id = -1;
        memset(&g_https_load_cert_hook_ref, 0, sizeof(g_https_load_cert_hook_ref));
    }
}

int vitals_legacy_certificates_loaded(void) {
    return __atomic_load_n(&g_legacy_certificates_loaded, __ATOMIC_ACQUIRE) != 0;
}

int vitals_cert_callback_decide(
    void *sony_connection,
    uint32_t verification_detail,
    int *accepted) {
    uintptr_t callback_address;
    uintptr_t callback_argument;
    int callback_result;

    if (sony_connection == NULL || accepted == NULL) {
        return -1;
    }
    *accepted = 0;
    callback_address = vitals_connection_callback_address(sony_connection);
    if (callback_address == 0) {
        *accepted = verification_detail == 0;
        return 0;
    }
    /* libssl stays Sony's shared copy, which must not be hooked, so a game's certificate
     * callback sees the verification result with an empty certificate list */
    callback_argument = vitals_connection_callback_arg_address(sony_connection);
    callback_result = ((VitalsHttpsCallback)callback_address)(
        verification_detail, NULL, 0, (void *)callback_argument);
    *accepted = vitals_cert_callback_accepted(
        callback_result, verification_detail, callback_address, &g_vitals_http.cert_policy);
    return 0;
}
