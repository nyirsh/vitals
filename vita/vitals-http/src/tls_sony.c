#include "tls_sony.h"

#include "vitals/log.h"
#include "vitals/error_map.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* vitals-http's TLS on Sony's libssl (the Options' tls.off), as Sony's libhttp does it: a socket
 * BIO, Sony's TLS, and the server's chain checked by this library with libssl's certificate
 * functions (vitals-ssl/README.md: Sony's libhttp's 0x81014592), against the roots libssl has built
 * in and the CA certificates the app loaded. Only functions the console's own libssl exports are
 * called, with the arguments Sony's libhttp gives them, so vitals-ssl, which has them all, runs this
 * too (the host tests do). A function it doesn't export is an import the loader leaves unresolved,
 * and calling it crashes the process: sceSslInternalBioCtrl is one */

/* The functions of Sony's libssl this needs, under libssl's NIDs (vitals-ssl/libssl_api.yml.in) */
typedef int (*SonyVerifyCallback)(void *ssl, void *certificates[], int count, void *argument, int *reason);
typedef int (*SonyClientCertCallback)(void *ssl, void **certificate, void **key);
int sceSslInternalGetLibrary(void **library);
const void *sceSslInternalClientMethod(void);
void *sceSslInternalCtxNew(const void *library, const void *method);
void sceSslInternalCtxFree(void *context);
uint32_t sceSslInternalCtxSetOptions(void *context, uint32_t options);
long sceSslInternalCtxCtrl(void *context, int command, long value, void *pointer);
void sceSslInternalCtxSetClientCertCallback(void *context, SonyClientCertCallback callback);
void sceSslInternalCtxSetVerify(void *context, int mode);
void sceSslInternalCtxSetCertVerifyCallback(void *context, SonyVerifyCallback callback, void *argument);
void *sceSslInternalBioNewSocket(int fd, int close_flag);
void *sceSslInternalNew(void *context);
void sceSslInternalFree(void *ssl);
void sceSslInternalSetBio(void *ssl, void *read_bio, void *write_bio);
void sceSslInternalSetConnectState(void *ssl);
int sceSslInternalConnect(void *ssl);
int sceSslInternalGetItem(void *ssl, int item, const void **out);
int sceSslInternalCertSubject(void *cert, int format, void **name);
int sceSslInternalCertIssuer(void *cert, int format, void **name);
int sceSslInternalNameFree(void *name);
int sceSslInternalNameEqual(const void *a, const void *b);
int sceSslInternalNameInfo(void *name, int item, void *out);
int sceSslInternalEntryInfo(void *entry, int item, void *out);
int sceSslInternalEntryFree(void *entry);
int sceSslInternalExtensionNew(const void *library, int type, void **out);
int sceSslInternalExtensionFree(void *extension);
int sceSslInternalExtensionInfo(void *extension, int item, void *out);
int sceSslInternalCertPublicKey(void *cert, int format, void **key);
int sceSslInternalKeyFree(void *key);
int sceSslInternalCertVerifySignature(void *cert, void *key, int *valid);
int sceSslInternalCertFromBinary(const void *library, int flags, int format, unsigned int length,
                                 const unsigned char *data, unsigned int *consumed, void **out);
int sceSslInternalCertFree(void *cert);
int sceSslInternalCertInfo(void *cert, int item, void *out);
int sceSslInternalCertToBinary(void *cert, int format, unsigned int size, unsigned char *buffer,
                               unsigned int *length);
int sceSslInternalTimeProvider(const void *library, int type, void **out);
int sceSslInternalTimeProviderFree(void *provider);
int sceSslInternalTimeNew(const void *provider, void **out);
int sceSslInternalTimeFree(void *time);
int sceSslInternalTimeNow(void *now);
int sceSslInternalTimeExport(const void *now, int format, void *value, unsigned int size);
int sceSslInternalTimeImport(void *time, int format, const void *value, unsigned int size);
int sceSslInternalCertNotAfter(void *cert, void *time);
int sceSslInternalCertNotBefore(void *cert, void *time);
int sceSslInternalTimeCompare(const void *a, const void *b, int *order);
int sceSslInternalGetCertificateAuthorityByName(const void *name, char ***entries, char *buffer,
                                                unsigned int size, unsigned int *total, int flag);
int sceSslInternalGetCaNameCount(void *ssl);
int sceSslInternalGetCaName(void *ssl, int index, void **name);
void *sceSslInternalBufferNew(void);
int sceSslInternalBufferWrite(void *buffer, const void *data, int length);
int sceSslInternalBufferFree(void *buffer);
int sceSslInternalKeyFromBuffer(void *buffer, const void *library, void **out, int format, int flags);
int sceSslInternalKeyMatches(void *cert, void *key);

/* What libhttp gives them (vitals-ssl/README.md) */
#define SONY_CTX_OPTIONS 0x20001FFBu
#define SONY_CTRL_SESSION_CACHE 44
/* The connection's Cert-C objects (24C6257F's items): 1 the context (time provider, extensions), 5
 * what certificates are parsed with (Sony's libhttp's for the client certificate; the console's
 * libssl refuses item 1 there, 10011), 6 what keys are */
#define SONY_ITEM_CERT_C 1
#define SONY_ITEM_CERT_PARSE 5
#define SONY_ITEM_KEY_C 6
#define SONY_CERT_INFO_SAN 0x4003
#define SONY_CERT_INFO_BASIC_CONSTRAINTS 0x4005
#define SONY_CERT_INFO_SIGNATURE 0x8007
#define SONY_EXTENSION_VALUE 0x8002
#define SONY_EXTENSION_CA 0x8007
#define SONY_EXTENSION_PATH_LENGTH 0x8008
#define SONY_NAME_COUNT 10
#define SONY_NAME_ENTRY 11
#define SONY_ENTRY_TYPE 1
#define SONY_ENTRY_VALUE 2
#define SONY_TIME_FORMAT 3
/* Signatures libhttp refuses: MD2 and MD4 (7), MD5 (8) */
#define SONY_SIGNATURE_MD 7
#define SONY_SIGNATURE_MD5 8
/* The reason a refusal gives libssl: handshake_failure */
#define SONY_REASON_REFUSED 10
/* The longest chain looked at */
#define SONY_CHAIN_MAX 10

typedef struct {
    unsigned int length;
    const unsigned char *data;
} SonyItem;

typedef struct {
    int tag;
    unsigned int length;
    const unsigned char *data;
} SonyTaggedItem;

typedef struct {
    int index;
    void *entry;
} SonyEntryRequest;

/* ---- PEM ---- */

static int base64_value(unsigned char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

/* The DER of the next certificate block in text[*at, length), *at moved past it: its size (out,
 * the caller's to free), or 0 when there's none left */
static size_t next_pem(const unsigned char *text, size_t length, size_t *at, unsigned char **out)
{
    static const char begin[] = "-----BEGIN CERTIFICATE-----", end[] = "-----END CERTIFICATE-----";
    *out = NULL;
    while (*at < length) {
        const unsigned char *start = NULL;
        for (size_t i = *at; i + sizeof(begin) - 1 <= length; ++i)
            if (memcmp(text + i, begin, sizeof(begin) - 1) == 0) {
                start = text + i + sizeof(begin) - 1;
                break;
            }
        if (start == NULL) {
            *at = length;
            return 0;
        }
        const unsigned char *stop = NULL;
        for (const unsigned char *p = start; p + sizeof(end) - 1 <= text + length; ++p)
            if (memcmp(p, end, sizeof(end) - 1) == 0) {
                stop = p;
                break;
            }
        if (stop == NULL) {
            *at = length;
            return 0;
        }
        *at = (size_t)(stop - text) + sizeof(end) - 1;
        unsigned char *der = malloc((size_t)(stop - start) * 3 / 4 + 3);
        if (der == NULL)
            return 0;
        size_t size = 0;
        unsigned int bits = 0, count = 0;
        int bad = 0;
        for (const unsigned char *p = start; p < stop; ++p) {
            if (*p == '=' || *p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
                continue;
            int value = base64_value(*p);
            if (value < 0) {
                bad = 1;
                break;
            }
            bits = bits << 6 | (unsigned int)value;
            if (++count == 4) {
                der[size++] = (unsigned char)(bits >> 16);
                der[size++] = (unsigned char)(bits >> 8);
                der[size++] = (unsigned char)bits;
                bits = count = 0;
            }
        }
        if (!bad && count == 3) {
            der[size++] = (unsigned char)(bits >> 10);
            der[size++] = (unsigned char)(bits >> 2);
        } else if (!bad && count == 2) {
            der[size++] = (unsigned char)(bits >> 4);
        } else if (count == 1) {
            bad = 1;
        }
        if (!bad && size > 0) {
            *out = der;
            return size;
        }
        free(der);
    }
    return 0;
}

/* ---- the chain's certificates ---- */

/* A certificate of the check: the server's (the connection's) or one this made (freed after) */
typedef struct {
    void *cert;
    int owned;
    /* Trusted as it is: one the app loaded or the store has */
    int anchor;
} SonyCert;

typedef struct {
    const void *cert_c, *parse_c;
    const VhSonyTrust *trust;
    SonyCert made[2 * SONY_CHAIN_MAX];
    int made_count;
    int failed;
} SonyCheck;

static void *make_cert(SonyCheck *check, const unsigned char *der, size_t size, int anchor)
{
    void *cert = NULL;
    unsigned int consumed = 0;
    if (check->made_count == (int)(sizeof(check->made) / sizeof(check->made[0])))
        return NULL;
    int rc = sceSslInternalCertFromBinary(check->parse_c, 0, 1, (unsigned int)size, der, &consumed, &cert);
    if (rc != 0 || cert == NULL) {
        VITALS_LOG("sony certificate of %u bytes unreadable rc=%08X", (unsigned int)size, (unsigned int)rc);
        return NULL;
    }
    check->made[check->made_count++] = (SonyCert){cert, 1, anchor};
    return cert;
}

static void free_made(SonyCheck *check)
{
    for (int i = 0; i < check->made_count; ++i)
        if (check->made[i].owned)
            (void)sceSslInternalCertFree(check->made[i].cert);
    check->made_count = 0;
}

/* A certificate's DER (the caller's to free), or NULL */
static unsigned char *der_of(void *cert, unsigned int *length)
{
    *length = 0;
    if (sceSslInternalCertToBinary(cert, 4, 0, NULL, length) != 0 || *length == 0)
        return NULL;
    unsigned char *der = malloc(*length);
    if (der != NULL && sceSslInternalCertToBinary(cert, 4, *length, der, length) != 0) {
        free(der);
        der = NULL;
    }
    return der;
}

static int same_der(void *a, void *b)
{
    unsigned int la, lb;
    unsigned char *da = der_of(a, &la), *db = der_of(b, &lb);
    int same = da != NULL && db != NULL && la == lb && memcmp(da, db, la) == 0;
    free(da);
    free(db);
    return same;
}

/* Whether a's subject (subject) or issuer (!subject) is b's subject */
static int names_meet(void *a, int subject, void *b)
{
    void *first = NULL, *second = NULL;
    int same = 0;
    if ((subject ? sceSslInternalCertSubject(a, 1, &first) : sceSslInternalCertIssuer(a, 1, &first)) == 0 &&
        sceSslInternalCertSubject(b, 1, &second) == 0)
        same = sceSslInternalNameEqual(first, second) == 1;
    if (first != NULL)
        (void)sceSslInternalNameFree(first);
    if (second != NULL)
        (void)sceSslInternalNameFree(second);
    return same;
}

static int self_issued(void *cert)
{
    return names_meet(cert, 0, cert);
}

/* The app's loaded CA certificates, made into certificates for the check */
static void make_loaded(SonyCheck *check)
{
    for (const VhSonyCa *ca = check->trust != NULL ? check->trust->cas : NULL; ca != NULL; ca = ca->next) {
        size_t at = 0;
        unsigned char *der = NULL;
        size_t size;
        int any = 0;
        while ((size = next_pem(ca->data, ca->size, &at, &der)) > 0) {
            any = 1;
            (void)make_cert(check, der, size, 1);
            free(der);
        }
        /* Not PEM: DER, as the app gave it */
        if (!any && ca->size > 0 && ca->data[0] == 0x30)
            (void)make_cert(check, ca->data, ca->size, 1);
    }
}

/* The store's root whose subject is the name, made into a certificate (asked again, libssl may give
 * the next with the name); NULL when there's none */
static void *store_root(SonyCheck *check, void *name)
{
    unsigned int total = 0;
    char **entries = NULL;
    if (sceSslInternalGetCertificateAuthorityByName(name, NULL, NULL, 0, &total, 0) != 1 || total == 0)
        return NULL;
    char *buffer = malloc(total);
    void *cert = NULL;
    if (buffer != NULL &&
        sceSslInternalGetCertificateAuthorityByName(name, &entries, buffer, total, &total, 0) == 1 &&
        entries != NULL && entries[0] != NULL) {
        size_t at = 0;
        unsigned char *der = NULL;
        size_t size = next_pem((const unsigned char *)entries[0], strlen(entries[0]), &at, &der);
        if (size > 0)
            cert = make_cert(check, der, size, 1);
        free(der);
    }
    free(buffer);
    return cert;
}

/* Whether cert is itself trusted: the same as one the app loaded, or as the store's root of its
 * name (a self-signed server certificate the app or the store trusts, as vitals-ssl does) */
static int is_anchor(SonyCheck *check, void *cert)
{
    for (int i = 0; i < check->made_count; ++i)
        if (check->made[i].anchor && check->made[i].cert != cert && same_der(check->made[i].cert, cert))
            return 1;
    void *subject = NULL;
    int anchor = 0;
    if (sceSslInternalCertSubject(cert, 1, &subject) == 0) {
        void *root = store_root(check, subject);
        anchor = root != NULL && same_der(root, cert);
        (void)sceSslInternalNameFree(subject);
    }
    return anchor;
}

/* Whether issuer may have signed below: a CA (version 1 certificates, the old roots, have no
 * basicConstraints) with room in its path length for depth certificates below */
static int may_issue(SonyCheck *check, void *issuer, int depth)
{
    void *extension = NULL;
    if (sceSslInternalExtensionNew(check->cert_c, -1, &extension) != 0 || extension == NULL)
        return 0;
    int allowed = 1;
    if (sceSslInternalCertInfo(issuer, SONY_CERT_INFO_BASIC_CONSTRAINTS, extension) == 0) {
        int ca = 0, path_length = 0;
        if (sceSslInternalExtensionInfo(extension, SONY_EXTENSION_CA, &ca) != 0 || !ca)
            allowed = 0;
        else if (sceSslInternalExtensionInfo(extension, SONY_EXTENSION_PATH_LENGTH, &path_length) == 0 &&
                 path_length >= 0 && depth > path_length + 1)
            allowed = 0;
    }
    (void)sceSslInternalExtensionFree(extension);
    return allowed;
}

/* Whether issuer's key made cert's signature, with a digest libhttp accepts */
static int signed_by(void *cert, void *issuer)
{
    int code = 0, valid = 0;
    void *key = NULL;
    if (sceSslInternalCertInfo(cert, SONY_CERT_INFO_SIGNATURE, &code) == 0 &&
        (code == SONY_SIGNATURE_MD || code == SONY_SIGNATURE_MD5))
        return 0;
    if (sceSslInternalCertPublicKey(issuer, 1, &key) != 0 || key == NULL)
        return 0;
    int result = sceSslInternalCertVerifySignature(cert, key, &valid);
    (void)sceSslInternalKeyFree(key);
    return result == 0 && valid == 1;
}

/* cert's issuer, which signed it, among the server's certificates, the app's and the store's:
 * the certificate, and *anchor when it's trusted; NULL when there's none */
static void *find_issuer(SonyCheck *check, void *cert, void *certificates[], int count, int depth, int *anchor)
{
    *anchor = 0;
    for (int i = 0; i < count; ++i)
        if (certificates[i] != cert && names_meet(cert, 0, certificates[i]) && signed_by(cert, certificates[i]) &&
            may_issue(check, certificates[i], depth))
            return certificates[i];
    for (int i = 0; i < check->made_count; ++i)
        if (check->made[i].anchor && names_meet(cert, 0, check->made[i].cert) &&
            signed_by(cert, check->made[i].cert) && may_issue(check, check->made[i].cert, depth)) {
            *anchor = 1;
            return check->made[i].cert;
        }
    void *issuer_name = NULL;
    void *found = NULL;
    if (sceSslInternalCertIssuer(cert, 1, &issuer_name) == 0) {
        /* libssl gives the next root with the name when asked again: cross-signed ones share it */
        for (int attempt = 0; attempt < 4 && found == NULL; ++attempt) {
            void *root = store_root(check, issuer_name);
            if (root == NULL)
                break;
            if (signed_by(cert, root) && may_issue(check, root, depth))
                found = root;
        }
        (void)sceSslInternalNameFree(issuer_name);
    }
    *anchor = found != NULL;
    return found;
}

/* ---- the host name ---- */

static int lower(int c)
{
    return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
}

/* A certificate's DNS name against the host: equal ignoring case, or a "*." wildcard for one label */
static int dns_matches(const unsigned char *name, size_t length, const char *host)
{
    size_t host_length = strlen(host);
    if (length >= 2 && name[0] == '*' && name[1] == '.') {
        const char *dot = strchr(host, '.');
        if (dot == NULL || dot == host)
            return 0;
        host = dot + 1;
        host_length = strlen(host);
        name += 2;
        length -= 2;
    }
    if (length != host_length)
        return 0;
    for (size_t i = 0; i < length; ++i)
        if (lower(name[i]) != lower((unsigned char)host[i]))
            return 0;
    return 1;
}

/* An IPv4 address's four bytes, or 0 when host isn't one */
static int ipv4(const char *host, unsigned char out[4])
{
    unsigned int part = 0, parts = 0, digits = 0;
    for (const char *p = host;; ++p) {
        if (*p >= '0' && *p <= '9') {
            part = part * 10 + (unsigned int)(*p - '0');
            if (++digits > 3 || part > 255)
                return 0;
        } else if ((*p == '.' || *p == '\0') && digits > 0 && parts < 4) {
            out[parts++] = (unsigned char)part;
            part = digits = 0;
            if (*p == '\0')
                return parts == 4;
        } else {
            return 0;
        }
    }
}

/* A DER length at *p (before end): the length, *p past it; -1 when it's broken */
static long der_length(const unsigned char **p, const unsigned char *end)
{
    if (*p >= end)
        return -1;
    unsigned int first = *(*p)++;
    if (first < 0x80)
        return (long)first;
    unsigned int bytes = first & 0x7F;
    if (bytes == 0 || bytes > 3 || end - *p < (long)bytes)
        return -1;
    long length = 0;
    while (bytes-- > 0)
        length = length << 8 | *(*p)++;
    return length;
}

/* 1 when subjectAltName's GeneralNames (DER) have the host, 0 when they don't, -1 when there are
 * none of the kind the host is (then the subject's CN decides). The value is taken as the
 * extension's OCTET STRING, its SEQUENCE, or the names alone, whichever it turns out to be */
static int san_matches(const unsigned char *der, size_t size, const char *host)
{
    const unsigned char *p = der, *end = der + size;
    unsigned char address[4];
    int is_address = ipv4(host, address), seen = 0;
    for (int unwrap = 0; unwrap < 2 && p < end && (*p == 0x04 || *p == 0x30); ++unwrap) {
        ++p;
        long length = der_length(&p, end);
        if (length < 0 || length > end - p)
            return 0;
        end = p + length;
    }
    while (p < end) {
        unsigned char tag = *p++;
        long item = der_length(&p, end);
        if (item < 0 || item > end - p)
            return 0;
        /* [2] dNSName, [7] iPAddress */
        if (tag == 0x82 && !is_address) {
            seen = 1;
            if (dns_matches(p, (size_t)item, host))
                return 1;
        } else if (tag == 0x87 && is_address) {
            seen = 1;
            if (item == 4 && memcmp(p, address, 4) == 0)
                return 1;
        } else if (tag == 0x82 || tag == 0x87) {
            seen = 1;
        }
        p += item;
    }
    return seen ? 0 : -1;
}

/* Whether the server's certificate is the host's: subjectAltName, and only without one the
 * subject's CN (2.5.4.3), as libhttp checks it */
static int host_matches(SonyCheck *check, void *cert, const char *host)
{
    void *extension = NULL;
    int matched = -1;
    int rc = sceSslInternalExtensionNew(check->cert_c, -1, &extension);
    if (rc == 0 && extension != NULL) {
        SonyItem value = {0, NULL};
        int info = sceSslInternalCertInfo(cert, SONY_CERT_INFO_SAN, extension), got = -1;
        if (info == 0 && (got = sceSslInternalExtensionInfo(extension, SONY_EXTENSION_VALUE, &value)) == 0 &&
            value.data != NULL)
            matched = san_matches(value.data, value.length, host);
        VITALS_LOG("sony subjectAltName info=%08X value=%08X length=%u first=%02X matched=%d", (unsigned int)info,
                   (unsigned int)got, value.length, value.data != NULL && value.length > 0 ? value.data[0] : 0u, matched);
        (void)sceSslInternalExtensionFree(extension);
    } else {
        VITALS_LOG("sony extension object rc=%08X", (unsigned int)rc);
    }
    if (matched >= 0)
        return matched;
    static const unsigned char cn[] = {0x55, 0x04, 0x03};
    void *subject = NULL;
    int count = 0;
    matched = 0;
    if (sceSslInternalCertSubject(cert, 1, &subject) != 0)
        return 0;
    if (sceSslInternalNameInfo(subject, SONY_NAME_COUNT, &count) == 0)
        for (int i = 0; i < count && !matched; ++i) {
            SonyEntryRequest request = {i, NULL};
            SonyTaggedItem type = {0, 0, NULL}, value = {0, 0, NULL};
            if (sceSslInternalNameInfo(subject, SONY_NAME_ENTRY, &request) != 0 || request.entry == NULL)
                continue;
            if (sceSslInternalEntryInfo(request.entry, SONY_ENTRY_TYPE, &type) == 0 && type.length == sizeof(cn) &&
                memcmp(type.data, cn, sizeof(cn)) == 0 &&
                sceSslInternalEntryInfo(request.entry, SONY_ENTRY_VALUE, &value) == 0)
                matched = dns_matches(value.data, value.length, host);
            (void)sceSslInternalEntryFree(request.entry);
        }
    (void)sceSslInternalNameFree(subject);
    return matched;
}

/* ---- the check ---- */

/* The validity of each of the server's certificates against now: VITALS_CERT_EXPIRED and
 * VITALS_CERT_FUTURE */
static uint32_t check_times(SonyCheck *check, void *certificates[], int count)
{
    void *provider = NULL, *now = NULL, *when = NULL;
    unsigned char clock[8], value[8];
    uint32_t found = 0;
    int rc = sceSslInternalTimeProvider(check->cert_c, 0, &provider);
    if (rc != 0 || provider == NULL) {
        VITALS_LOG("sony time provider rc=%08X", (unsigned int)rc);
        return VITALS_CERT_INTERNAL;
    }
    int step = 0;
    /* The clock's own return isn't a status on the console (it gave what looks like an address):
     * only what it writes is used */
    memset(clock, 0, sizeof(clock));
    if ((rc = sceSslInternalTimeNew(provider, &now)) != 0 || (++step, rc = sceSslInternalTimeNew(provider, &when)) != 0 ||
        (++step, (void)sceSslInternalTimeNow(clock), rc = 0) != 0 ||
        (++step, rc = sceSslInternalTimeExport(clock, SONY_TIME_FORMAT, value, 8)) != 0 ||
        (++step, rc = sceSslInternalTimeImport(now, SONY_TIME_FORMAT, value, 8)) != 0) {
        VITALS_LOG("sony time step=%d rc=%08X", step, (unsigned int)rc);
        found = VITALS_CERT_INTERNAL;
    } else {
        for (int i = 0; i < count; ++i) {
            int order = 0;
            if (sceSslInternalCertNotAfter(certificates[i], when) == 0 &&
                sceSslInternalTimeCompare(when, now, &order) == 0 && order < 0)
                found |= VITALS_CERT_EXPIRED;
            if (sceSslInternalCertNotBefore(certificates[i], when) == 0 &&
                sceSslInternalTimeCompare(when, now, &order) == 0 && order > 0)
                found |= VITALS_CERT_FUTURE;
        }
    }
    if (when != NULL)
        (void)sceSslInternalTimeFree(when);
    if (now != NULL)
        (void)sceSslInternalTimeFree(now);
    (void)sceSslInternalTimeProviderFree(provider);
    return found;
}

uint32_t vh_sony_check_chain(void *ssl, void *certificates[], int count, const char *host, const VhSonyTrust *trust)
{
    SonyCheck check;
    memset(&check, 0, sizeof(check));
    check.trust = trust;
    int item = -1;
    if (ssl == NULL || certificates == NULL || count <= 0 || certificates[0] == NULL ||
        (item = sceSslInternalGetItem(ssl, SONY_ITEM_CERT_C, &check.cert_c)) != 0 || check.cert_c == NULL) {
        VITALS_LOG("sony chain: no Cert-C context count=%d rc=%08X", count, (unsigned int)item);
        return VITALS_CERT_INVALID | VITALS_CERT_UNKNOWN_CA;
    }
    if ((item = sceSslInternalGetItem(ssl, SONY_ITEM_CERT_PARSE, &check.parse_c)) != 0 || check.parse_c == NULL) {
        VITALS_LOG("sony chain: no certificate context rc=%08X", (unsigned int)item);
        check.parse_c = check.cert_c;
    }
    make_loaded(&check);
    uint32_t found = check_times(&check, certificates, count);
    if (host != NULL && host[0] != '\0' && !host_matches(&check, certificates[0], host))
        found |= VITALS_CERT_HOSTNAME;
    /* Up from the server's certificate: each one signed by the next, to a trusted one */
    void *cert = certificates[0];
    int trusted = is_anchor(&check, cert);
    for (int depth = 1; !trusted && depth <= SONY_CHAIN_MAX; ++depth) {
        int anchor = 0;
        /* A self-signed certificate that isn't trusted ends the chain */
        if (self_issued(cert))
            break;
        void *issuer = find_issuer(&check, cert, certificates, count, depth, &anchor);
        if (issuer == NULL)
            break;
        if (anchor || is_anchor(&check, issuer)) {
            trusted = 1;
            break;
        }
        cert = issuer;
    }
    if (!trusted)
        found |= VITALS_CERT_UNKNOWN_CA;
    free_made(&check);
    VITALS_LOG("sony chain host=%s count=%d found=%02X", host != NULL ? host : "-", count, (unsigned int)found);
    return found;
}

/* ---- the connection ---- */

struct VhSonyTls {
    /* First, the verify callback's argument as Sony's libhttp lays it out (tls.c's VhCertCheck): the
     * console's libssl reads the host name for SNI from its second word, having no BIO_ctrl to be
     * given it */
    uint32_t flags;
    const char *host;
    int *result;
    unsigned int *bits;
    void *callback, *callback_argument, *reserved[4], *lock, *unlock;
    /* The rest is this library's */
    int check_result;
    unsigned int check_bits;
    void *context, *ssl;
    const VhSonyConnection *connection;
    /* What the check found, filtered by the HTTPS options, and whether the connection was refused */
    uint32_t found_flags;
    int refused;
};

_Static_assert(offsetof(struct VhSonyTls, host) == sizeof(void *),
               "the console's libssl reads the host name from the argument's second word");

static int verify(void *ssl, void *certificates[], int count, void *argument, int *reason)
{
    VhSonyTls *tls = argument;
    const VhSonyConnection *connection = tls->connection;
    uint32_t found = 0;
    if ((connection->https_options & VITALS_SCE_HTTPS_OPTION_SERVER_VERIFY) != 0)
        found = connection->check(connection->argument, ssl, certificates, count,
                                  (connection->https_options & VITALS_SCE_HTTPS_OPTION_CN_CHECK) != 0 ? connection->host
                                                                                                      : NULL);
    tls->found_flags = vitals_filter_certificate_flags(found, connection->https_options);
    unsigned int detail = vitals_map_certificate_detail(tls->found_flags);
    int accepted = detail == 0;
    /* As Sony's: the app's callback decides, with the problems and the server's certificates */
    if (detail != 0 && connection->ssl_callback != NULL)
        accepted = connection->ssl_callback(detail, certificates, count, connection->ssl_argument) >= 0;
    tls->refused = !accepted;
    tls->check_result = accepted ? 0 : (int)0x80435806;
    tls->check_bits = detail;
    *reason = accepted ? 0 : SONY_REASON_REFUSED;
    VITALS_LOG("sony certificate host=%s found=%02X detail=%02X callback=%d accepted=%d", connection->host,
               (unsigned int)found, detail, connection->ssl_callback != NULL, accepted);
    return accepted;
}

/* The certificate and key the app loaded, as Sony's libhttp's callback gives them: when they belong
 * together and the server named the certificate's issuer among the CAs it takes. A server that names
 * none gets them too, as on vitals-ssl (where Sony's would send nothing): many don't, and the app
 * loaded them for this server */
static VhSonyClientSource g_client_source;
static void *g_client_argument;

static int client_certificate(void *ssl, void **certificate, void **key)
{
    *certificate = *key = NULL;
    const void *cert_c = NULL, *key_c = NULL;
    VhSonyIdentity identity = {NULL, 0, NULL, 0};
    if (g_client_source == NULL || !g_client_source(g_client_argument, &identity) ||
        sceSslInternalGetItem(ssl, SONY_ITEM_CERT_PARSE, &cert_c) != 0 ||
        sceSslInternalGetItem(ssl, SONY_ITEM_KEY_C, &key_c) != 0) {
        free(identity.certificate);
        free(identity.key);
        return 0;
    }
    void *cert = NULL, *private_key = NULL;
    unsigned char *der = NULL;
    size_t at = 0, size = next_pem(identity.certificate, identity.certificate_size, &at, &der);
    unsigned int consumed = 0;
    if (size > 0)
        (void)sceSslInternalCertFromBinary(cert_c, 0, 1, (unsigned int)size, der, &consumed, &cert);
    else
        (void)sceSslInternalCertFromBinary(cert_c, 0, 1, (unsigned int)identity.certificate_size,
                                           identity.certificate, &consumed, &cert);
    free(der);
    void *buffer = sceSslInternalBufferNew();
    if (buffer != NULL) {
        for (size_t done = 0; done < identity.key_size;) {
            int written = sceSslInternalBufferWrite(buffer, identity.key + done, (int)(identity.key_size - done));
            if (written <= 0)
                break;
            done += (size_t)written;
        }
        (void)sceSslInternalKeyFromBuffer(buffer, key_c, &private_key, 6, 0x1100);
        (void)sceSslInternalBufferFree(buffer);
    }
    memset(identity.key, 0, identity.key_size);
    free(identity.key);
    free(identity.certificate);
    int given = 0;
    if (cert != NULL && private_key != NULL && sceSslInternalKeyMatches(cert, private_key) == 1) {
        void *issuer = NULL;
        if (sceSslInternalCertIssuer(cert, 1, &issuer) == 0) {
            int names = sceSslInternalGetCaNameCount(ssl);
            given = names <= 0;
            for (int i = 0; i < names && !given; ++i) {
                void *name = NULL;
                if (sceSslInternalGetCaName(ssl, i, &name) == 0 && name != NULL)
                    given = sceSslInternalNameEqual(name, issuer) == 1;
            }
            (void)sceSslInternalNameFree(issuer);
        }
    }
    VITALS_LOG("sony client certificate given=%d", given);
    if (!given) {
        if (cert != NULL)
            (void)sceSslInternalCertFree(cert);
        (void)sceSslInternalKeyFree(private_key);
        return 0;
    }
    *certificate = cert;
    *key = private_key;
    return 1;
}

int vh_sony_tls_start(VhSonyTls **out, const VhSonyConnection *connection)
{
    *out = NULL;
    void *library = NULL;
    if (sceSslInternalGetLibrary(&library) != 0)
        return -1;
    VhSonyTls *tls = calloc(1, sizeof(*tls));
    if (tls == NULL)
        return -1;
    tls->connection = connection;
    tls->flags = connection->https_options;
    tls->host = connection->host;
    tls->result = &tls->check_result;
    tls->bits = &tls->check_bits;
    tls->context = sceSslInternalCtxNew(library, sceSslInternalClientMethod());
    if (tls->context == NULL) {
        free(tls);
        return -1;
    }
    /* As Sony's libhttp sets it up: its options, no session cache, the verify mode and its check */
    (void)sceSslInternalCtxSetOptions(tls->context, SONY_CTX_OPTIONS);
    (void)sceSslInternalCtxCtrl(tls->context, SONY_CTRL_SESSION_CACHE, 0, NULL);
    if (connection->client_source != NULL) {
        g_client_source = connection->client_source;
        g_client_argument = connection->client_argument;
        sceSslInternalCtxSetClientCertCallback(tls->context, client_certificate);
    }
    sceSslInternalCtxSetVerify(tls->context, 1);
    sceSslInternalCtxSetCertVerifyCallback(tls->context, verify, tls);
    tls->ssl = sceSslInternalNew(tls->context);
    void *bio = tls->ssl != NULL ? sceSslInternalBioNewSocket(connection->socket, 0) : NULL;
    if (bio == NULL) {
        vh_sony_tls_close(tls);
        return -1;
    }
    /* No BIO_ctrl for the host name (SNI): the console's own libssl doesn't export it (0x16D7C7CA,
     * which the copy vitals-ssl was read from has), and calling the import it leaves unresolved
     * crashes the process. It reads the name from the verify callback's argument instead (above) */
    sceSslInternalSetBio(tls->ssl, bio, bio);
    sceSslInternalSetConnectState(tls->ssl);
    *out = tls;
    return 0;
}

int vh_sony_tls_connect(VhSonyTls *tls, uint32_t *flags, int *refused)
{
    int connected = sceSslInternalConnect(tls->ssl);
    *flags = tls->found_flags;
    *refused = tls->refused;
    return connected;
}

void *vh_sony_tls_ssl(VhSonyTls *tls)
{
    return tls->ssl;
}

void vh_sony_tls_close(VhSonyTls *tls)
{
    if (tls == NULL)
        return;
    if (tls->ssl != NULL)
        sceSslInternalFree(tls->ssl);
    if (tls->context != NULL)
        sceSslInternalCtxFree(tls->context);
    free(tls);
}
