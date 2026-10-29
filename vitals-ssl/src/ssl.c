#include "ssl.h"

#include "diagnostics.h"

/* SceSsl's certificate functions, as <psp2/libssl.h> declares them. Not written yet: each one
 * fails. sceSslInit, sceSslTerm and sceSslGetMemoryPoolStats are in core.c.
 * "Sony" is the function's address in the libssl the app bundles (vitals-app/assets/lssl.suprx) */

int ssl_not_implemented(const char *function)
{
    VITALS_LOG("%s is not implemented", function);
    (void)function;
    return SCE_SSL_ERROR_INTERNAL;
}

/* NID 0x901C5C15, Sony 0x810494F1 */
int sceSslGetSerialNumber(SceSslCert *sslCert, const char **sboData, unsigned *sboLen)
{
    (void)sslCert, (void)sboData, (void)sboLen;
    return ssl_not_implemented(__func__);
}

/* NID 0x70DEA174, Sony 0x8104963D */
int sceSslGetNotBefore(SceSslCert *sslCert, SceRtcTick *begin)
{
    (void)sslCert, (void)begin;
    return ssl_not_implemented(__func__);
}

/* NID 0xF5ED7B68, Sony 0x81049769 */
int sceSslGetNotAfter(SceSslCert *sslCert, SceRtcTick *limit)
{
    (void)sslCert, (void)limit;
    return ssl_not_implemented(__func__);
}

/* NID 0x95E14CA6, Sony 0x81049895 */
int sceSslGetNameEntryCount(SceSslCertName *certName)
{
    (void)certName;
    return ssl_not_implemented(__func__);
}

/* NID 0x2A857867, Sony 0x810498F1 */
int sceSslGetNameEntryInfo(SceSslCertName *certName, int entryNum, char *oidname,
                           unsigned maxOidnameLen, char *value, unsigned maxValueLen,
                           unsigned *valueLen)
{
    (void)certName, (void)entryNum, (void)oidname, (void)maxOidnameLen, (void)value,
        (void)maxValueLen, (void)valueLen;
    return ssl_not_implemented(__func__);
}

/* NID 0x9B2F1BC1, Sony 0x81049571 */
SceSslCertName *sceSslGetSubjectName(SceSslCert *sslCert)
{
    (void)sslCert;
    ssl_not_implemented(__func__);
    return NULL;
}

/* NID 0x412711E5, Sony 0x810495B9 */
SceSslCertName *sceSslGetIssuerName(SceSslCert *sslCert)
{
    (void)sslCert;
    ssl_not_implemented(__func__);
    return NULL;
}

/* NID 0xC73687E4, Sony 0x81049601 */
int sceSslFreeSslCertName(SceSslCertName *certName)
{
    (void)certName;
    return ssl_not_implemented(__func__);
}
