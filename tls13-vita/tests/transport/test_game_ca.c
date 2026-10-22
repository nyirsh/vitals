/* Host test of the game certificates (the Sound Shapes fix): what a game passes to
 * sceHttpsLoadCert is trusted in addition to the bundle, replaced by later loads, dropped by
 * sceHttpsUnloadCert, and found by issuer during handshakes
 * The certificates are roots from the bundled store (argv[1]); a root is its own issuer */
#include "../../provider/cert_hooks.c"
#include "crypto_platform.h"

#include <psa/crypto.h>

#include <assert.h>
#include <stdio.h>

VitalsProviderGlobal g_vitals_http;

/* ---- taiHEN: records the two hooks, and continues to a stand-in for Sony's functions ---- */
static int sony_load_result, sony_load_calls, sony_unload_calls, released;
static int sony_load_cert(int count, const SceHttpsData **certificates, const SceHttpsData *client,
                          const SceHttpsData *key)
{
    (void)count, (void)certificates, (void)client, (void)key;
    ++sony_load_calls;
    return sony_load_result;
}
static int sony_unload_cert(void)
{
    ++sony_unload_calls;
    return 0;
}
static struct _tai_hook_user records[2];

int taiHookFunctionExport(tai_hook_ref_t *reference, const char *module, uint32_t library, uint32_t nid,
                          const void *function)
{
    assert(strcmp(module, "SceLibHttp") == 0 && library == VITALS_SCE_HTTP_LIBRARY_NID);
    int index = nid == VITALS_NID_HTTPS_LOAD_CERT ? 0 : 1;
    assert(index == 0 || nid == VITALS_NID_HTTPS_UNLOAD_CERT);
    records[index] = (struct _tai_hook_user){NULL, (void *)(uintptr_t)function,
        index == 0 ? (void *)(uintptr_t)sony_load_cert : (void *)(uintptr_t)sony_unload_cert};
    *reference = (tai_hook_ref_t)&records[index];
    return 10 + index;
}
int taiHookRelease(int id, tai_hook_ref_t reference)
{
    assert((id == 10 && reference == (tai_hook_ref_t)&records[0]) ||
           (id == 11 && reference == (tai_hook_ref_t)&records[1]));
    ++released;
    return 0;
}

/* ---- Certificates from the bundle ---- */
#define ROOTS 3
static char pem[ROOTS][8192];   /* PEM text, as a game might pass it */
static unsigned char der[ROOTS][4096];
static size_t der_size[ROOTS];
static mbedtls_x509_crt roots[ROOTS];

static void read_roots(const char *path)
{
    FILE *file = fopen(path, "rb");
    assert(file != NULL);
    static char bundle[1 << 20];
    size_t size = fread(bundle, 1, sizeof(bundle) - 1, file);
    fclose(file);
    bundle[size] = '\0';
    const char *cursor = bundle;
    for (int i = 0; i < ROOTS; ++i)
    {
        const char *begin = strstr(cursor, "-----BEGIN CERTIFICATE-----");
        const char *end = begin ? strstr(begin, "-----END CERTIFICATE-----") : NULL;
        assert(begin != NULL && end != NULL);
        end += strlen("-----END CERTIFICATE-----");
        assert((size_t)(end - begin) < sizeof(pem[i]));
        memcpy(pem[i], begin, (size_t)(end - begin));
        pem[i][end - begin] = '\0';
        cursor = end;
        mbedtls_x509_crt_init(&roots[i]);
        assert(mbedtls_x509_crt_parse(&roots[i], (const unsigned char *)pem[i], strlen(pem[i]) + 1) == 0);
        assert(roots[i].raw.len <= sizeof(der[i]));
        memcpy(der[i], roots[i].raw.p, roots[i].raw.len);
        der_size[i] = roots[i].raw.len;
        /* Each is a root: its own issuer */
        assert(roots[i].issuer_raw.len == roots[i].subject_raw.len);
    }
}

/* The game's data, without a terminating NUL even for PEM (games need not supply one) */
static SceHttpsData pem_data(int i) { return (SceHttpsData){pem[i], (unsigned int)strlen(pem[i])}; }
static SceHttpsData der_data(int i) { return (SceHttpsData){(char *)der[i], (unsigned int)der_size[i]}; }

typedef int (*LoadCert)(int, const SceHttpsData **, const SceHttpsData *, const SceHttpsData *);
typedef int (*UnloadCert)(void);
static int load(int count, const SceHttpsData **certificates, const SceHttpsData *client, const SceHttpsData *key)
{
    return ((LoadCert)records[0].func)(count, certificates, client, key);
}
static int unload(void) { return ((UnloadCert)records[1].func)(); }

/* How many candidates the handshake lookup returns for child, and whether expected is among them */
static int found(int child, int expected)
{
    mbedtls_x509_crt *candidates = NULL;
    assert(vitals_game_ca_find(&roots[child], &candidates) == 0);
    int count = 0, seen = 0;
    for (mbedtls_x509_crt *c = candidates; c != NULL && c->raw.p != NULL; c = c->next)
    {
        ++count;
        if (c->raw.len == der_size[expected] && memcmp(c->raw.p, der[expected], c->raw.len) == 0)
            seen = 1;
    }
    if (candidates != NULL)
    {
        mbedtls_x509_crt_free(candidates);
        mbedtls_free(candidates);
    }
    return count == 1 && seen ? 1 : count == 0 ? 0 : -1;
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    /* As the provider's trust store does: certificates are parsed through PSA crypto */
    assert(vitals_crypto_platform_init() == 0 && psa_crypto_init() == PSA_SUCCESS);
    read_roots(argv[1]);
    g_vitals_http.registry_mutex = sceKernelCreateMutex("game ca test", 0, 0, NULL);
    assert(g_vitals_http.registry_mutex >= 0);
    assert(vitals_cert_hooks_install() == 0 && records[0].func != NULL && records[1].func != NULL);

    /* Nothing loaded: nothing found, provider connections allowed */
    assert(found(0, 0) == 0 && !vitals_legacy_certificates_loaded());

    /* PEM and DER, with empty entries skipped; each root is found for itself only */
    SceHttpsData a = pem_data(0), b = der_data(1), empty = {NULL, 0}, zero = {pem[2], 0};
    const SceHttpsData *first[] = {&a, NULL, &empty, &zero, &b};
    assert(load(5, first, NULL, NULL) == 0 && sony_load_calls == 1);
    assert(!vitals_legacy_certificates_loaded());
    assert(found(0, 0) == 1 && found(1, 1) == 1 && found(2, 2) == 0);

    /* Candidates the bundle already found are kept, and the game's are appended */
    mbedtls_x509_crt *candidates = mbedtls_calloc(1, sizeof(*candidates));
    mbedtls_x509_crt_init(candidates);
    assert(mbedtls_x509_crt_parse_der(candidates, der[2], der_size[2]) == 0);
    assert(vitals_game_ca_find(&roots[0], &candidates) == 0);
    assert(candidates->raw.len == der_size[2] && candidates->next != NULL &&
           candidates->next->raw.len == der_size[0]);
    mbedtls_x509_crt_free(candidates);
    mbedtls_free(candidates);

    /* A later load replaces the earlier certificates */
    SceHttpsData c = pem_data(2);
    const SceHttpsData *second[] = {&c};
    assert(load(1, second, NULL, NULL) == 0);
    assert(found(0, 0) == 0 && found(1, 1) == 0 && found(2, 2) == 1);

    /* Nothing readable: the game's certificates cannot be honored, so its connections stay on
     * Sony's stack, and the previous ones are not discarded */
    char garbage[] = "not a certificate at all";
    SceHttpsData bad = {garbage, (unsigned int)strlen(garbage)};
    SceHttpsData broken_pem = {pem[0], 200};
    const SceHttpsData *unreadable[] = {&bad, &broken_pem};
    assert(load(2, unreadable, NULL, NULL) == 0);
    assert(vitals_legacy_certificates_loaded() && found(2, 2) == 1);

    /* Unloading drops them and allows the provider again */
    assert(unload() == 0 && sony_unload_calls == 1);
    assert(!vitals_legacy_certificates_loaded() && found(2, 2) == 0);

    /* A client certificate or key keeps the game on Sony's stack; nothing is loaded */
    const SceHttpsData *with_client[] = {&a};
    assert(load(1, with_client, &b, NULL) == 0);
    assert(vitals_legacy_certificates_loaded() && found(0, 0) == 0);
    assert(unload() == 0 && !vitals_legacy_certificates_loaded());
    assert(load(0, NULL, NULL, &b) == 0 && vitals_legacy_certificates_loaded());
    assert(unload() == 0);

    /* When Sony's own call fails, nothing changes */
    sony_load_result = -123;
    assert(load(1, first, NULL, NULL) == -123);
    assert(!vitals_legacy_certificates_loaded() && found(0, 0) == 0);
    sony_load_result = 0;

    /* Releasing the hooks frees the certificates */
    assert(load(1, first, NULL, NULL) == 0 && found(0, 0) == 1);
    vitals_cert_hooks_release();
    assert(released == 2 && found(0, 0) == 0);

    for (int i = 0; i < ROOTS; ++i)
        mbedtls_x509_crt_free(&roots[i]);
    assert(sceKernelDeleteMutex(g_vitals_http.registry_mutex) == 0);
    mbedtls_psa_crypto_free();
    vitals_crypto_platform_free();
    puts("game certificates: PEM and DER loads, issuer lookup, replacement, unload, client certificates PASS");
    return 0;
}
