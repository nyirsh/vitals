#include "vs.h"

#include "diagnostics.h"

#include <mbedtls/oid.h>

#include <string.h>

/* SceSsl's certificate functions, as <psp2/libssl.h> declares them, on the certificates libhttp
 * gives an app's sceHttpsSetSslCallback (certificate.c's objects). sceSslInit, sceSslTerm and
 * sceSslGetMemoryPoolStats are in core.c. The stub every unwritten export calls is here too.
 * "Sony" is the function's address in the libssl the app bundles (vitals-app/assets/lssl.suprx) */

int ssl_not_implemented(const char *function)
{
    VITALS_LOG("%s is not implemented", function);
    (void)function;
    return SCE_SSL_ERROR_INTERNAL;
}

/* SceRtcTick: microseconds since 0001-01-01 */
#define TICKS_TO_1970 62135596800ull

static int get_time(SceSslCert *sslCert, SceRtcTick *tick, int not_after)
{
    const mbedtls_x509_crt *crt = vs_certificate(sslCert);
    if (crt == NULL || tick == NULL)
        return VS_ERROR_INVALID_VALUE;
    int64_t seconds = vs_certificate_time(crt, not_after);
    tick->tick = ((uint64_t)(seconds + (int64_t)TICKS_TO_1970)) * 1000000ull;
    return 0;
}

/* NID 0x901C5C15, Sony 0x810494F1: the serial number's bytes, as long as the certificate */
int sceSslGetSerialNumber(SceSslCert *sslCert, const char **sboData, unsigned *sboLen)
{
    const mbedtls_x509_crt *crt = vs_certificate(sslCert);
    if (crt == NULL || sboData == NULL || sboLen == NULL)
        return VS_ERROR_INVALID_VALUE;
    *sboData = (const char *)crt->serial.p;
    *sboLen = (unsigned)crt->serial.len;
    return 0;
}

/* NID 0x70DEA174, Sony 0x8104963D */
int sceSslGetNotBefore(SceSslCert *sslCert, SceRtcTick *begin)
{
    return get_time(sslCert, begin, 0);
}

/* NID 0xF5ED7B68, Sony 0x81049769 */
int sceSslGetNotAfter(SceSslCert *sslCert, SceRtcTick *limit)
{
    return get_time(sslCert, limit, 1);
}

/* NID 0x95E14CA6, Sony 0x81049895 */
int sceSslGetNameEntryCount(SceSslCertName *certName)
{
    int count = vs_name_count(certName);
    return count >= 0 ? count : VS_ERROR_INVALID_VALUE;
}

/* NID 0x2A857867, Sony 0x810498F1: an entry's attribute ("CN", or the OID as dotted text when
 * Mbed TLS has no short name for it) and value, each cut to fit and NUL-terminated; valueLen is
 * the whole value's length */
int sceSslGetNameEntryInfo(SceSslCertName *certName, int entryNum, char *oidname,
                           unsigned maxOidnameLen, char *value, unsigned maxValueLen,
                           unsigned *valueLen)
{
    const mbedtls_x509_name *entry = vs_name_entry(certName, entryNum);
    if (entry == NULL)
        return VS_ERROR_INVALID_VALUE;
    if (oidname != NULL && maxOidnameLen > 0) {
        const char *short_name = NULL;
        if (mbedtls_oid_get_attr_short_name(&entry->oid, &short_name) == 0 && short_name != NULL) {
            size_t length = strlen(short_name);
            length = length < maxOidnameLen - 1 ? length : maxOidnameLen - 1;
            memcpy(oidname, short_name, length);
            oidname[length] = '\0';
        } else if (mbedtls_oid_get_numeric_string(oidname, maxOidnameLen, &entry->oid) < 0) {
            oidname[0] = '\0';
        }
    }
    if (value != NULL && maxValueLen > 0) {
        size_t length = entry->val.len < maxValueLen - 1 ? entry->val.len : maxValueLen - 1;
        memcpy(value, entry->val.p, length);
        value[length] = '\0';
    }
    if (valueLen != NULL)
        *valueLen = (unsigned)entry->val.len;
    return 0;
}

static SceSslCertName *get_name(SceSslCert *sslCert, int subject)
{
    const mbedtls_x509_crt *crt = vs_certificate(sslCert);
    if (crt == NULL)
        return NULL;
    SceSslCertName *name = vs_name_new(subject ? &crt->subject_raw : &crt->issuer_raw);
    if (name == NULL)
        vs_note_out_of_memory();
    return name;
}

/* NID 0x9B2F1BC1, Sony 0x81049571: freed with sceSslFreeSslCertName */
SceSslCertName *sceSslGetSubjectName(SceSslCert *sslCert)
{
    return get_name(sslCert, 1);
}

/* NID 0x412711E5, Sony 0x810495B9 */
SceSslCertName *sceSslGetIssuerName(SceSslCert *sslCert)
{
    return get_name(sslCert, 0);
}

/* NID 0xC73687E4, Sony 0x81049601 */
int sceSslFreeSslCertName(SceSslCertName *certName)
{
    if (vs_name_count(certName) < 0)
        return VS_ERROR_INVALID_VALUE;
    vs_name_free(certName);
    return 0;
}
