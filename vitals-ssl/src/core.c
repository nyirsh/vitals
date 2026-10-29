#include "vs.h"

#include "ca_index.h"
#include "crypto_platform.h"
#include "diagnostics.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/platform_util.h>
#include <psa/crypto.h>

#include <string.h>

/* sceSslInit and sceSslTerm, the memory pool, the library object and the error translator. As
 * Sony's: everything comes from the pool the app gives sceSslInit, and an app's connections share
 * one random generator and the CA bundle's index */

static int g_initialized;
/* What 2185BB05 hands out and SSL_CTX_new takes; nothing reads it */
static struct { uint32_t magic; } g_library = {0x4C425356u};
static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_random;
/* Built on the first connection that verifies, from the pool too */
static VitalsCaIndex g_ca_index;
static int g_ca_index_state;
/* Set when an allocation failed, until the error translator reads it (Sony's error queue) */
static int g_out_of_memory;

int vs_initialized(void)
{
    vs_lock();
    int initialized = g_initialized;
    vs_unlock();
    return initialized;
}

void vs_note_out_of_memory(void)
{
    vs_lock();
    g_out_of_memory = 1;
    vs_unlock();
}

int vs_take_out_of_memory(void)
{
    vs_lock();
    int out_of_memory = g_out_of_memory;
    g_out_of_memory = 0;
    vs_unlock();
    return out_of_memory;
}

int vs_tls_random(void *context, unsigned char *output, size_t size)
{
    (void)context;
    return mbedtls_ctr_drbg_random(&g_random, output, size);
}

/* The CA bundle's index, once; a missing bundle leaves nothing trusted */
static int ca_index_ready(void)
{
    vs_lock();
    if (g_ca_index_state == 0) {
        char path[VITALS_CA_INDEX_PATH_SIZE];
        g_ca_index_state = vs_platform_ca_path(path, sizeof(path)) == 0 &&
                                   vitals_ca_index_build(&g_ca_index, path) == 0
                               ? 1
                               : -1;
        VITALS_LOG("roots=%u", g_ca_index_state > 0 ? (unsigned int)g_ca_index.count : 0u);
    }
    int ready = g_ca_index_state > 0;
    vs_unlock();
    return ready;
}

int vs_find_trusted_issuers(void *context, const mbedtls_x509_crt *child, mbedtls_x509_crt **candidates)
{
    (void)context;
    *candidates = NULL;
    return ca_index_ready() ? vitals_ca_index_find(&g_ca_index, child, candidates) : 0;
}

/* As vitals-http: a self-signed server certificate that is itself in the bundle counts as trusted;
 * its other checks (host name, dates) still apply */
int vs_trust_exact_self_signed(void *context, mbedtls_x509_crt *certificate, int depth, uint32_t *flags)
{
    if (depth == 0 && (*flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED) != 0 &&
        vitals_ca_trusts_exact(vs_find_trusted_issuers, context, certificate))
        *flags &= ~(uint32_t)MBEDTLS_X509_BADCERT_NOT_TRUSTED;
    return 0;
}

/* NID 0x3C733316, Sony 0x81047F09 */
int sceSslInit(unsigned poolSize)
{
    vs_lock();
    int result = 0;
    if (g_initialized)
        result = VS_ERROR_ALREADY_INITED;
    else if (poolSize == 0)
        result = VS_ERROR_INVALID_VALUE;
    else
        result = vs_platform_heap_create(poolSize);
    if (result != 0) {
        vs_unlock();
        VITALS_LOG("init pool=%u rc=%08X", poolSize, (unsigned int)result);
        return result;
    }
    if (vitals_crypto_platform_init() != 0 || psa_crypto_init() != PSA_SUCCESS)
        result = VS_ERROR_INTERNAL;
    if (result == 0) {
        mbedtls_entropy_init(&g_entropy);
        mbedtls_ctr_drbg_init(&g_random);
        if (mbedtls_ctr_drbg_seed(&g_random, mbedtls_entropy_func, &g_entropy,
                                  (const unsigned char *)"vitals-ssl", 10) != 0) {
            mbedtls_ctr_drbg_free(&g_random);
            mbedtls_entropy_free(&g_entropy);
            result = VS_ERROR_OUT_OF_MEMORY;
        }
    }
    if (result != 0) {
        mbedtls_psa_crypto_free();
        vitals_crypto_platform_free();
        vs_platform_heap_destroy();
    } else {
        g_initialized = 1;
        g_out_of_memory = 0;
        g_ca_index_state = 0;
    }
    vs_unlock();
    VITALS_LOG("init pool=%u rc=%08X", poolSize, (unsigned int)result);
    return result;
}

/* NID 0x03CE6E3A, Sony 0x810480AD */
int sceSslTerm(void)
{
    vs_lock();
    if (!g_initialized) {
        vs_unlock();
        return VS_ERROR_BEFORE_INIT;
    }
    if (g_ca_index_state > 0)
        vitals_ca_index_free(&g_ca_index);
    g_ca_index_state = 0;
    mbedtls_ctr_drbg_free(&g_random);
    mbedtls_entropy_free(&g_entropy);
    mbedtls_psa_crypto_free();
    vitals_crypto_platform_free();
    vs_platform_heap_destroy();
    g_initialized = 0;
    vs_unlock();
    VITALS_LOG("term");
    return 0;
}

/* NID 0xBD203262, Sony 0x81048169: reserved is left as the caller had it, as Sony's */
int sceSslGetMemoryPoolStats(SceSslMemoryPoolStats *currentStat)
{
    vs_lock();
    int result = 0;
    if (!g_initialized)
        result = VS_ERROR_BEFORE_INIT;
    else if (currentStat == NULL)
        result = VS_ERROR_INVALID_VALUE;
    else
        vs_platform_heap_stats(&currentStat->poolSize, &currentStat->maxInuseSize,
                               &currentStat->currentInuseSize);
    vs_unlock();
    return result;
}

/* NID 0x4B4A2307, Sony 0x8104808D */
int sceSslInternalIsInitalized(void)
{
    return vs_initialized() ? 0 : VS_ERROR_BEFORE_INIT;
}

/* NID 0x2185BB05, Sony 0x81048141: the library object SSL_CTX_new takes */
int sceSslInternalGetLibrary(void **library)
{
    if (!vs_initialized())
        return VS_ERROR_BEFORE_INIT;
    if (library == NULL)
        return VS_ERROR_INVALID_VALUE;
    *library = &g_library;
    return 0;
}

int vs_is_library(const void *library)
{
    return library == &g_library;
}

/* NID 0x461C5990, Sony 0x81048205: an internal failure as an SCE error code.
 * kind 0: a reason from the certificate functions (0 is success); 10001 to 10026 but 10005 and
 *         10024, and 10028 to 10037, become 0x80432AF0 + reason, 10005 is out of memory, anything
 *         else unknown
 * kind 1: the code the caller gives, or out of memory when an allocation failed
 * any other kind: invalid */
int sceSslInternalErrorCode(int kind, int reason)
{
    if (kind == 0) {
        if (reason == 0)
            return 0;
        if (reason == 10005)
            return VS_ERROR_OUT_OF_MEMORY;
        if ((reason >= 10001 && reason <= 10023) || reason == 10025 || reason == 10026 ||
            (reason >= 10028 && reason <= 10037))
            return (int)(0x80432AF0u + (unsigned int)reason);
        return VS_ERROR_UNKNOWN_REASON;
    }
    if (kind == 1)
        return vs_take_out_of_memory() ? VS_ERROR_OUT_OF_MEMORY : reason;
    return VS_ERROR_INVALID_VALUE;
}
