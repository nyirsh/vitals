#include "vs.h"

#include "ca_index.h"
#include "diagnostics.h"

#include <mbedtls/asn1.h>
#include <mbedtls/base64.h>
#include <mbedtls/md.h>
#include <mbedtls/oid.h>
#include <mbedtls/platform.h>
#include <mbedtls/platform_util.h>
#include <psp2/io/fcntl.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* SSL-C's certificate objects as Sony's libhttp uses them: certificates, names and their
 * entries, extensions, times, public keys and the CA store, each reached only through these
 * functions, over Mbed TLS. libhttp's verify callback (0x81014592) checks a server's chain with
 * them; see the README for what each call returns.
 * Failures return SSL-C's reasons (100xx), which the error translator (461C5990) turns into SCE
 * errors. "Sony" is the function's address in the libssl the app bundles */

#define CERT_MAGIC 0x54435356u
#define NAME_MAGIC 0x4E435356u
#define ENTRY_MAGIC 0x45435356u
#define EXTENSION_MAGIC 0x58435356u
#define TIME_MAGIC 0x4D435356u
#define KEY_MAGIC 0x4B435356u

/* SSL-C's reasons */
#define R_FAILED 10001
#define R_ALLOC_FAILURE 10005
#define R_BUFFER_TOO_SMALL 10006
#define R_NOT_FOUND 10008
#define R_NOT_SUPPORTED 10011
#define R_NULL_ARG 10017

/* What GetCertificateAuthority returns when nothing matches, as Sony's */
#define CA_NOT_FOUND ((int)0x80010086)

/* The info numbers libhttp reads */
#define CERT_INFO_SERIAL 2
#define CERT_INFO_SUBJECT_ALT_NAME 0x4003
#define CERT_INFO_BASIC_CONSTRAINTS 0x4005
#define CERT_INFO_SIGNATURE 0x8007
#define CERT_INFO_PUBLIC_KEY 0x8009
#define CERT_INFO_ISSUER 0x800A
#define CERT_INFO_SUBJECT 0x800B
#define EXTENSION_INFO_CRITICAL 0x8001
#define EXTENSION_INFO_VALUE 0x8002
#define EXTENSION_INFO_CA 0x8007
#define EXTENSION_INFO_PATH_LENGTH 0x8008
#define NAME_INFO_COUNT 10
#define NAME_INFO_ENTRY 11
#define ENTRY_INFO_TYPE 1
#define ENTRY_INFO_VALUE 2

/* Mbed TLS's, not in its public headers */
int mbedtls_x509_get_name(unsigned char **p, const unsigned char *end, mbedtls_x509_name *cur);

/* R_ITEM: a length and bytes, which libhttp reads directly */
typedef struct VsItem {
    unsigned int length;
    const unsigned char *data;
} VsItem;

/* What an entry's info gives: an ASN.1 tag before the item */
typedef struct VsTaggedItem {
    int tag;
    unsigned int length;
    const unsigned char *data;
} VsTaggedItem;

/* 91C2531C's entry request: the index in, the entry out */
typedef struct VsEntryRequest {
    int index;
    void *entry;
} VsEntryRequest;

/* The OID object libhttp keeps on its stack (16 bytes): 4D80D3F7 points it at bytes */
typedef struct VsOid {
    uint32_t reserved;
    const unsigned char *data;
    unsigned int length;
    uint32_t flags;
} VsOid;

typedef struct VsName {
    uint32_t magic;
    unsigned char *der; /* the Name SEQUENCE's contents, which head points into */
    size_t length;
    mbedtls_x509_name head;
} VsName;

typedef struct VsEntry {
    uint32_t magic;
    int tag;
    unsigned char *oid;
    size_t oid_length;
    unsigned char *value;
    size_t value_length;
} VsEntry;

typedef struct VsExtension {
    uint32_t magic;
    int found;
    int critical;
    unsigned char *value; /* extnValue's contents */
    size_t length;
    int basic_constraints;
    int ca;
    int path_length;
} VsExtension;

typedef struct VsTime {
    uint32_t magic;
    int64_t seconds; /* since 1970 */
} VsTime;

typedef struct VsKey {
    uint32_t magic;
    mbedtls_pk_context pk;
} VsKey;

/* The Cert-C context SSL item 1 (and 5, 6) gives, and the time provider D3C049B9 gives: nothing
 * reads them */
static struct { uint32_t magic; } g_cert_library = {0x43435356u};
static struct { uint32_t magic; } g_time_provider = {0x50435356u};

const void *vs_cert_library(void)
{
    return &g_cert_library;
}

static int is_cert(const VsCert *cert)
{
    return cert != NULL && cert->magic == CERT_MAGIC && cert->crt != NULL;
}

const mbedtls_x509_crt *vs_certificate(const void *handle)
{
    const VsCert *cert = handle;
    return is_cert(cert) ? cert->crt : NULL;
}

void vs_cert_borrow(VsCert *cert, mbedtls_x509_crt *crt)
{
    memset(cert, 0, sizeof(*cert));
    cert->magic = CERT_MAGIC;
    cert->crt = crt;
}

void vs_cert_return(VsCert *cert)
{
    cert->magic = 0;
    cert->crt = NULL;
}

/* Seconds since 1970 for a certificate's time (UTC) */
static int64_t epoch_seconds(const mbedtls_x509_time *time)
{
    int64_t year = time->year, month = time->mon;
    year -= month <= 2;
    int64_t era = (year >= 0 ? year : year - 399) / 400;
    int64_t of_era = year - era * 400;
    int64_t of_year = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + time->day - 1;
    int64_t of_era_days = of_era * 365 + of_era / 4 - of_era / 100 + of_year;
    int64_t days = era * 146097 + of_era_days - 719468;
    return days * 86400 + time->hour * 3600 + time->min * 60 + time->sec;
}

int64_t vs_certificate_time(const mbedtls_x509_crt *crt, int not_after)
{
    return epoch_seconds(not_after ? &crt->valid_to : &crt->valid_from);
}

/* Names */

static int is_name(const VsName *name)
{
    return name != NULL && name->magic == NAME_MAGIC;
}

/* A copy of a Name (its DER, tag and all), parsed */
void *vs_name_new(const mbedtls_x509_buf *raw)
{
    unsigned char *p = raw->p;
    size_t length = 0;
    if (p == NULL ||
        mbedtls_asn1_get_tag(&p, raw->p + raw->len, &length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
        return NULL;
    VsName *name = calloc(1, sizeof(*name));
    if (name == NULL)
        return NULL;
    name->magic = NAME_MAGIC;
    name->length = length;
    if (length > 0) {
        name->der = malloc(length);
        unsigned char *start = name->der;
        if (start == NULL) {
            free(name);
            return NULL;
        }
        memcpy(start, p, length);
        if (mbedtls_x509_get_name(&start, name->der + length, &name->head) != 0) {
            vs_name_free(name);
            return NULL;
        }
    }
    return name;
}

void vs_name_free(void *handle)
{
    VsName *name = handle;
    if (!is_name(name))
        return;
    mbedtls_asn1_free_named_data_list_shallow(name->head.next);
    free(name->der);
    name->magic = 0;
    free(name);
}

int vs_name_count(const void *handle)
{
    const VsName *name = handle;
    if (!is_name(name))
        return -1;
    int count = 0;
    for (const mbedtls_x509_name *entry = &name->head; entry != NULL && entry->oid.p != NULL; entry = entry->next)
        ++count;
    return count;
}

const mbedtls_x509_name *vs_name_entry(const void *handle, int index)
{
    const VsName *name = handle;
    if (!is_name(name) || index < 0)
        return NULL;
    const mbedtls_x509_name *entry = &name->head;
    for (; entry != NULL && entry->oid.p != NULL && index > 0; entry = entry->next)
        --index;
    return entry != NULL && entry->oid.p != NULL ? entry : NULL;
}

static int same_text(const mbedtls_x509_buf *a, const mbedtls_x509_buf *b)
{
    if (a->len != b->len)
        return 0;
    for (size_t i = 0; i < a->len; ++i) {
        unsigned char x = a->p[i], y = b->p[i];
        if (x >= 'A' && x <= 'Z')
            x = (unsigned char)(x + ('a' - 'A'));
        if (y >= 'A' && y <= 'Z')
            y = (unsigned char)(y + ('a' - 'A'));
        if (x != y)
            return 0;
    }
    return 1;
}

/* As Mbed TLS compares names: the same attributes in order, string values without regard to case */
static int names_equal(const VsName *a, const VsName *b)
{
    if (a->length == b->length && (a->length == 0 || memcmp(a->der, b->der, a->length) == 0))
        return 1;
    const mbedtls_x509_name *x = &a->head, *y = &b->head;
    for (; x != NULL && y != NULL && x->oid.p != NULL && y->oid.p != NULL; x = x->next, y = y->next) {
        if (x->oid.len != y->oid.len || memcmp(x->oid.p, y->oid.p, x->oid.len) != 0 ||
            x->MBEDTLS_PRIVATE(next_merged) != y->MBEDTLS_PRIVATE(next_merged) || !same_text(&x->val, &y->val))
            return 0;
    }
    return (x == NULL || x->oid.p == NULL) && (y == NULL || y->oid.p == NULL);
}

static int name_of(const VsCert *cert, int subject, void **out)
{
    if (!is_cert(cert) || out == NULL)
        return R_NULL_ARG;
    *out = vs_name_new(subject ? &cert->crt->subject_raw : &cert->crt->issuer_raw);
    return *out != NULL ? 0 : R_ALLOC_FAILURE;
}

/* NID 0x08179EBD, Sony 0x81001761: the subject's name, freed with CE37B69E */
int sceSslInternalCertSubject(void *cert, int format, void **name)
{
    (void)format;
    return name_of(cert, 1, name);
}

/* NID 0x81FA5DBE, Sony 0x81001753: the issuer's name */
int sceSslInternalCertIssuer(void *cert, int format, void **name)
{
    (void)format;
    return name_of(cert, 0, name);
}

/* NID 0xCE37B69E, Sony 0x81004FE9: frees a name */
int sceSslInternalNameFree(void *name)
{
    if (!is_name(name))
        return R_NULL_ARG;
    vs_name_free(name);
    return 0;
}

/* NID 0x568F0E80, Sony 0x81001AA3: 1 when two names are the same */
int sceSslInternalNameEqual(const void *a, const void *b)
{
    return is_name(a) && is_name(b) && names_equal(a, b);
}

/* NID 0x91C2531C, Sony 0x810051C5: 10 the number of entries (an int), 11 the entry of a
 * VsEntryRequest's index, freed with 17BF2367 */
int sceSslInternalNameInfo(void *name, int item, void *out)
{
    if (!is_name(name) || out == NULL)
        return R_NULL_ARG;
    if (item == NAME_INFO_COUNT) {
        *(int *)out = vs_name_count(name);
        return 0;
    }
    if (item != NAME_INFO_ENTRY)
        return R_NOT_SUPPORTED;
    VsEntryRequest *request = out;
    const mbedtls_x509_name *found = vs_name_entry(name, request->index);
    if (found == NULL)
        return R_NOT_FOUND;
    VsEntry *entry = calloc(1, sizeof(*entry));
    if (entry == NULL)
        return R_ALLOC_FAILURE;
    entry->oid = malloc(found->oid.len + 1);
    entry->value = malloc(found->val.len + 1);
    if (entry->oid == NULL || entry->value == NULL) {
        free(entry->oid);
        free(entry->value);
        free(entry);
        return R_ALLOC_FAILURE;
    }
    entry->magic = ENTRY_MAGIC;
    entry->tag = found->val.tag;
    memcpy(entry->oid, found->oid.p, found->oid.len);
    entry->oid_length = found->oid.len;
    memcpy(entry->value, found->val.p, found->val.len);
    entry->value_length = found->val.len;
    request->entry = entry;
    return 0;
}

/* NID 0xB5A099D2, Sony 0x8100505D: 1 the entry's type (an OID's bytes), 2 its value, each as a
 * VsTaggedItem that lasts as long as the entry */
int sceSslInternalEntryInfo(void *handle, int item, void *out)
{
    VsEntry *entry = handle;
    if (entry == NULL || entry->magic != ENTRY_MAGIC || out == NULL)
        return R_NULL_ARG;
    VsTaggedItem *result = out;
    if (item == ENTRY_INFO_TYPE) {
        result->tag = MBEDTLS_ASN1_OID;
        result->length = (unsigned int)entry->oid_length;
        result->data = entry->oid;
    } else if (item == ENTRY_INFO_VALUE) {
        result->tag = entry->tag;
        result->length = (unsigned int)entry->value_length;
        result->data = entry->value;
    } else {
        return R_NOT_SUPPORTED;
    }
    return 0;
}

/* NID 0x17BF2367, Sony 0x81005043: frees an entry */
int sceSslInternalEntryFree(void *handle)
{
    VsEntry *entry = handle;
    if (entry == NULL || entry->magic != ENTRY_MAGIC)
        return R_NULL_ARG;
    entry->magic = 0;
    free(entry->oid);
    free(entry->value);
    free(entry);
    return 0;
}

/* NID 0x4D80D3F7, Sony 0x810090D3: points an OID object at bytes (libhttp's mode 1; mode 0, a
 * copy in Sony's, is a reference here too, as nothing frees the object) */
int sceSslInternalOidSet(void *handle, int mode, const unsigned char *data, unsigned int length)
{
    VsOid *oid = handle;
    (void)mode;
    if (oid == NULL)
        return R_NULL_ARG;
    oid->reserved = 0;
    oid->data = length > 0 ? data : NULL;
    oid->length = data != NULL ? length : 0;
    oid->flags = 0;
    return 0;
}

/* NID 0x3DE4F3DB, Sony 0x810092C9: the OID as dotted text ("2.5.4.3"), NUL-terminated */
int sceSslInternalOidText(const void *handle, int format, unsigned int size, char *text)
{
    const VsOid *oid = handle;
    (void)format;
    if (oid == NULL || text == NULL)
        return R_NULL_ARG;
    if (oid->data == NULL)
        return R_NOT_FOUND;
    mbedtls_asn1_buf buffer = {MBEDTLS_ASN1_OID, oid->length, (unsigned char *)oid->data};
    int written = mbedtls_oid_get_numeric_string(text, size, &buffer);
    if (written == MBEDTLS_ERR_OID_BUF_TOO_SMALL)
        return R_BUFFER_TOO_SMALL;
    return written < 0 ? R_FAILED : 0;
}

/* Extensions */

static int is_extension(const VsExtension *extension)
{
    return extension != NULL && extension->magic == EXTENSION_MAGIC;
}

static void extension_clear(VsExtension *extension)
{
    free(extension->value);
    extension->value = NULL;
    extension->length = 0;
    extension->found = 0;
    extension->critical = 0;
    extension->basic_constraints = 0;
    extension->ca = 0;
    extension->path_length = INT_MAX;
}

/* NID 0xBF99D664, Sony 0x81002BF5: an empty extension object, which 64BDF1BB fills */
int sceSslInternalExtensionNew(const void *library, int type, void **out)
{
    (void)library, (void)type;
    if (out == NULL)
        return R_NULL_ARG;
    VsExtension *extension = calloc(1, sizeof(*extension));
    *out = extension;
    if (extension == NULL)
        return R_ALLOC_FAILURE;
    extension->magic = EXTENSION_MAGIC;
    extension_clear(extension);
    return 0;
}

/* NID 0xF030A0DE, Sony 0x81002039: frees it */
int sceSslInternalExtensionFree(void *handle)
{
    VsExtension *extension = handle;
    if (!is_extension(extension))
        return R_NULL_ARG;
    extension_clear(extension);
    extension->magic = 0;
    free(extension);
    return 0;
}

/* basicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL } */
static int parse_basic_constraints(VsExtension *extension)
{
    unsigned char *p = extension->value, *end = p + extension->length;
    size_t length = 0;
    extension->basic_constraints = 1;
    if (mbedtls_asn1_get_tag(&p, end, &length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0 ||
        p + length != end)
        return R_FAILED;
    if (p < end && *p == MBEDTLS_ASN1_BOOLEAN && mbedtls_asn1_get_bool(&p, end, &extension->ca) != 0)
        return R_FAILED;
    if (p < end && (mbedtls_asn1_get_int(&p, end, &extension->path_length) != 0 || extension->path_length < 0))
        return R_FAILED;
    extension->ca = extension->ca != 0;
    return p == end ? 0 : R_FAILED;
}

/* Finds the extension with the OID among the certificate's and copies its value */
static int find_extension(const mbedtls_x509_crt *crt, const char *oid, size_t oid_length, VsExtension *extension)
{
    extension_clear(extension);
    if (crt->v3_ext.p == NULL)
        return R_NOT_FOUND;
    unsigned char *p = crt->v3_ext.p, *end = p + crt->v3_ext.len;
    size_t length = 0;
    if (mbedtls_asn1_get_tag(&p, end, &length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
        return R_FAILED;
    end = p + length;
    while (p < end) {
        unsigned char *next;
        if (mbedtls_asn1_get_tag(&p, end, &length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
            return R_FAILED;
        next = p + length;
        mbedtls_x509_buf id = {MBEDTLS_ASN1_OID, 0, NULL};
        int critical = 0;
        if (mbedtls_asn1_get_tag(&p, next, &id.len, MBEDTLS_ASN1_OID) != 0)
            return R_FAILED;
        id.p = p;
        p += id.len;
        if (p < next && *p == MBEDTLS_ASN1_BOOLEAN && mbedtls_asn1_get_bool(&p, next, &critical) != 0)
            return R_FAILED;
        if (mbedtls_asn1_get_tag(&p, next, &length, MBEDTLS_ASN1_OCTET_STRING) != 0 || p + length != next)
            return R_FAILED;
        if (id.len == oid_length && memcmp(id.p, oid, oid_length) == 0) {
            extension->value = malloc(length > 0 ? length : 1);
            if (extension->value == NULL)
                return R_ALLOC_FAILURE;
            memcpy(extension->value, p, length);
            extension->length = length;
            extension->critical = critical != 0;
            extension->found = 1;
            return 0;
        }
        p = next;
    }
    return R_NOT_FOUND;
}

/* NID 0x93EAE08A, Sony 0x81002953: 0x8001 whether it's critical, 0x8002 its value (a VsItem that
 * lasts as long as the extension); for basicConstraints 0x8007 cA and 0x8008 the path length,
 * INT_MAX without one */
int sceSslInternalExtensionInfo(void *handle, int item, void *out)
{
    VsExtension *extension = handle;
    if (!is_extension(extension) || out == NULL)
        return R_NULL_ARG;
    if (!extension->found)
        return R_NOT_FOUND;
    switch (item) {
    case EXTENSION_INFO_CRITICAL:
        *(int *)out = extension->critical;
        return 0;
    case EXTENSION_INFO_VALUE:
        ((VsItem *)out)->length = (unsigned int)extension->length;
        ((VsItem *)out)->data = extension->value;
        return 0;
    case EXTENSION_INFO_CA:
    case EXTENSION_INFO_PATH_LENGTH:
        if (!extension->basic_constraints)
            return R_NOT_SUPPORTED;
        *(int *)out = item == EXTENSION_INFO_CA ? extension->ca : extension->path_length;
        return 0;
    default:
        return R_NOT_SUPPORTED;
    }
}

/* Keys */

static int is_key(const VsKey *key)
{
    return key != NULL && key->magic == KEY_MAGIC;
}

static int public_key_of(const VsCert *cert, void **out)
{
    if (!is_cert(cert) || out == NULL)
        return R_NULL_ARG;
    *out = NULL;
    VsKey *key = calloc(1, sizeof(*key));
    if (key == NULL)
        return R_ALLOC_FAILURE;
    key->magic = KEY_MAGIC;
    mbedtls_pk_init(&key->pk);
    int result = mbedtls_pk_parse_public_key(&key->pk, cert->crt->pk_raw.p, cert->crt->pk_raw.len);
    if (result != 0) {
        mbedtls_pk_free(&key->pk);
        free(key);
        return result == MBEDTLS_ERR_PK_ALLOC_FAILED ? R_ALLOC_FAILURE : R_FAILED;
    }
    *out = key;
    return 0;
}

/* NID 0x170D595D, Sony 0x81005113: the certificate's public key, freed with 46358909 */
int sceSslInternalCertPublicKey(void *cert, int format, void **key)
{
    (void)format;
    return public_key_of(cert, key);
}

/* NID 0x46358909, Sony 0x8101FB59: frees a key */
int sceSslInternalKeyFree(void *handle)
{
    VsKey *key = handle;
    if (!is_key(key))
        return R_NULL_ARG;
    mbedtls_pk_free(&key->pk);
    key->magic = 0;
    free(key);
    return 0;
}

/* NID 0x306E2A22, Sony 0x81005081: *valid 1 when the key made the certificate's signature, 0 when it didn't */
int sceSslInternalCertVerifySignature(void *handle, void *key_handle, int *valid)
{
    VsCert *cert = handle;
    VsKey *key = key_handle;
    if (!is_cert(cert) || !is_key(key) || valid == NULL)
        return R_NULL_ARG;
    const mbedtls_x509_crt *crt = cert->crt;
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(crt->MBEDTLS_PRIVATE(sig_md));
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    *valid = 0;
    if (md == NULL || mbedtls_md(md, crt->tbs.p, crt->tbs.len, hash) != 0)
        return 0;
    *valid = mbedtls_pk_verify_ext(crt->MBEDTLS_PRIVATE(sig_pk), crt->MBEDTLS_PRIVATE(sig_opts), &key->pk,
                                   crt->MBEDTLS_PRIVATE(sig_md), hash, mbedtls_md_get_size(md),
                                   crt->MBEDTLS_PRIVATE(sig).p, crt->MBEDTLS_PRIVATE(sig).len) == 0;
    return 0;
}

/* Certificates */

/* NID 0x29AAC768, Sony 0x810050D5: a certificate from DER, freed with 144FA354 */
int sceSslInternalCertFromBinary(const void *library, int flags, int format, unsigned int length,
                                 const unsigned char *data, unsigned int *consumed, void **out)
{
    (void)library, (void)flags, (void)format;
    if (data == NULL || out == NULL)
        return R_NULL_ARG;
    *out = NULL;
    VsCert *cert = calloc(1, sizeof(*cert));
    if (cert == NULL)
        return R_ALLOC_FAILURE;
    mbedtls_x509_crt_init(&cert->own);
    int result = mbedtls_x509_crt_parse_der(&cert->own, data, length);
    if (result != 0) {
        mbedtls_x509_crt_free(&cert->own);
        free(cert);
        return result == MBEDTLS_ERR_X509_ALLOC_FAILED ? R_ALLOC_FAILURE : R_FAILED;
    }
    cert->magic = CERT_MAGIC;
    cert->crt = &cert->own;
    cert->owned = 1;
    if (consumed != NULL)
        *consumed = (unsigned int)cert->own.raw.len;
    *out = cert;
    return 0;
}

/* NID 0x144FA354, Sony 0x81004FD1: frees a certificate 29AAC768 made; the server's, which the
 * verify callback is given, stay the connection's */
int sceSslInternalCertFree(void *handle)
{
    VsCert *cert = handle;
    if (!is_cert(cert))
        return R_NULL_ARG;
    if (!cert->owned)
        return 0;
    mbedtls_x509_crt_free(&cert->own);
    cert->magic = 0;
    free(cert);
    return 0;
}

/* 7 for a signature with MD2 or MD4, 8 with MD5, which libhttp refuses; otherwise 16 plus Mbed
 * TLS's digest number */
static int signature_code(const mbedtls_x509_crt *crt)
{
    if (crt->MBEDTLS_PRIVATE(sig_md) == MBEDTLS_MD_MD5)
        return 8;
    return 16 + (int)crt->MBEDTLS_PRIVATE(sig_md);
}

/* NID 0x64BDF1BB, Sony 0x81004F83: an item of the certificate: 2 the serial number (a VsItem that
 * lasts as long as the certificate), 0x4003 subjectAltName and 0x4005 basicConstraints into an
 * extension object, 0x8007 the signature's algorithm, 0x8009 the public key, 0x800A and 0x800B
 * the issuer's and subject's names */
int sceSslInternalCertInfo(void *handle, int item, void *out)
{
    VsCert *cert = handle;
    if (!is_cert(cert) || out == NULL)
        return R_NULL_ARG;
    const mbedtls_x509_crt *crt = cert->crt;
    switch (item) {
    case CERT_INFO_SERIAL:
        ((VsItem *)out)->length = (unsigned int)crt->serial.len;
        ((VsItem *)out)->data = crt->serial.p;
        return 0;
    case CERT_INFO_SUBJECT_ALT_NAME:
        if (!is_extension(out))
            return R_NULL_ARG;
        return find_extension(crt, MBEDTLS_OID_SUBJECT_ALT_NAME, MBEDTLS_OID_SIZE(MBEDTLS_OID_SUBJECT_ALT_NAME),
                              out);
    case CERT_INFO_BASIC_CONSTRAINTS: {
        VsExtension *extension = out;
        if (!is_extension(extension))
            return R_NULL_ARG;
        int result = find_extension(crt, MBEDTLS_OID_BASIC_CONSTRAINTS,
                                    MBEDTLS_OID_SIZE(MBEDTLS_OID_BASIC_CONSTRAINTS), extension);
        if (result == 0)
            return parse_basic_constraints(extension);
        /* A version 3 certificate without one isn't a CA, as RFC 5280 and Mbed TLS have it, where
         * libhttp would skip the check: only version 1 certificates (old roots) have none */
        if (result == R_NOT_FOUND && crt->version >= 3) {
            extension->found = 1;
            extension->basic_constraints = 1;
            return 0;
        }
        return result;
    }
    case CERT_INFO_SIGNATURE:
        *(int *)out = signature_code(crt);
        return 0;
    case CERT_INFO_PUBLIC_KEY:
        return public_key_of(cert, out);
    case CERT_INFO_ISSUER:
    case CERT_INFO_SUBJECT:
        return name_of(cert, item == CERT_INFO_SUBJECT, out);
    default:
        return R_NOT_SUPPORTED;
    }
}

/* NID 0x08ED1B25, Sony 0x81001C71: the DER encoding into buffer; its length with no buffer */
int sceSslInternalCertToBinary(void *handle, int format, unsigned char *buffer, unsigned int size,
                               unsigned int *length)
{
    VsCert *cert = handle;
    (void)format;
    if (!is_cert(cert) || length == NULL)
        return R_NULL_ARG;
    *length = (unsigned int)cert->crt->raw.len;
    if (buffer == NULL)
        return 0;
    if (size < cert->crt->raw.len)
        return R_BUFFER_TOO_SMALL;
    memcpy(buffer, cert->crt->raw.p, cert->crt->raw.len);
    return 0;
}

/* Times */

static int is_time(const VsTime *time)
{
    return time != NULL && time->magic == TIME_MAGIC;
}

/* NID 0xD3C049B9, Sony 0x81028CFB: the time provider of the Cert-C context */
int sceSslInternalTimeProvider(const void *library, int type, void **out)
{
    (void)library, (void)type;
    if (out == NULL)
        return R_NULL_ARG;
    *out = &g_time_provider;
    return 0;
}

/* NID 0xD4ADF069, Sony 0x81028D75: frees it */
int sceSslInternalTimeProviderFree(void *provider)
{
    return provider == &g_time_provider ? 0 : R_NULL_ARG;
}

/* NID 0x5E50CB55, Sony 0x81028D87: a time object, freed with 6CDB4EE8 */
int sceSslInternalTimeNew(const void *provider, void **out)
{
    (void)provider;
    if (out == NULL)
        return R_NULL_ARG;
    VsTime *time = calloc(1, sizeof(*time));
    *out = time;
    if (time == NULL)
        return R_ALLOC_FAILURE;
    time->magic = TIME_MAGIC;
    return 0;
}

/* NID 0x6CDB4EE8, Sony 0x81028D99: frees it */
int sceSslInternalTimeFree(void *handle)
{
    VsTime *time = handle;
    if (!is_time(time))
        return R_NULL_ARG;
    time->magic = 0;
    free(time);
    return 0;
}

/* NID 0x4AAF0D45, Sony 0x8102A239: the current time, 8 bytes of seconds since 1970 */
int sceSslInternalTimeNow(void *now)
{
    if (now == NULL)
        return R_NULL_ARG;
    int64_t seconds = (int64_t)mbedtls_time(NULL);
    memcpy(now, &seconds, sizeof(seconds));
    return 0;
}

/* NID 0x6D2A86F0, Sony 0x8102A351: that time as a value of a format (libhttp's 3, 8 bytes) */
int sceSslInternalTimeExport(const void *now, int format, void *value, unsigned int size)
{
    (void)format;
    if (now == NULL || value == NULL)
        return R_NULL_ARG;
    if (size < sizeof(int64_t))
        return R_BUFFER_TOO_SMALL;
    memcpy(value, now, sizeof(int64_t));
    return 0;
}

/* NID 0x88391E03, Sony 0x81028E09: sets a time object from such a value */
int sceSslInternalTimeImport(void *handle, int format, const void *value, unsigned int size)
{
    VsTime *time = handle;
    (void)format;
    if (!is_time(time) || value == NULL)
        return R_NULL_ARG;
    if (size < sizeof(int64_t))
        return R_BUFFER_TOO_SMALL;
    memcpy(&time->seconds, value, sizeof(int64_t));
    return 0;
}

static int time_of(VsCert *cert, VsTime *time, int not_after)
{
    if (!is_cert(cert) || !is_time(time))
        return R_NULL_ARG;
    time->seconds = vs_certificate_time(cert->crt, not_after);
    return 0;
}

/* NID 0x2074A6EB, Sony 0x81001CE9: the certificate's notAfter into a time object */
int sceSslInternalCertNotAfter(void *cert, void *time)
{
    return time_of(cert, time, 1);
}

/* NID 0x2464F9D0, Sony 0x81001D33: its notBefore */
int sceSslInternalCertNotBefore(void *cert, void *time)
{
    return time_of(cert, time, 0);
}

/* NID 0x04BAED82, Sony 0x81028DC1: -1, 0 or 1 as the first time is before, at or after the second */
int sceSslInternalTimeCompare(const void *a, const void *b, int *order)
{
    const VsTime *first = a, *second = b;
    if (!is_time(first) || !is_time(second) || order == NULL)
        return R_NULL_ARG;
    *order = first->seconds < second->seconds ? -1 : first->seconds > second->seconds ? 1 : 0;
    return 0;
}

/* NID 0xD1A82B1A, Sony 0x81028DE9: the time as text, "YYYYMMDDHHMMSSZ" (GeneralizedTime), NUL-terminated */
int sceSslInternalTimeText(const void *handle, int format, char *text, unsigned int *length, unsigned int size)
{
    const VsTime *time = handle;
    (void)format;
    if (!is_time(time) || text == NULL)
        return R_NULL_ARG;
    if (size < 16)
        return R_BUFFER_TOO_SMALL;
    int64_t days = time->seconds / 86400, rest = time->seconds % 86400;
    if (rest < 0) {
        rest += 86400;
        --days;
    }
    /* Civil date from days since 1970 */
    int64_t z = days + 719468, era = (z >= 0 ? z : z - 146096) / 146097;
    int64_t of_era = z - era * 146097;
    int64_t year_of_era = (of_era - of_era / 1460 + of_era / 36524 - of_era / 146096) / 365;
    int64_t of_year = of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    int64_t month_index = (5 * of_year + 2) / 153;
    int day = (int)(of_year - (153 * month_index + 2) / 5 + 1);
    int month = (int)(month_index < 10 ? month_index + 3 : month_index - 9);
    int year = (int)(year_of_era + era * 400 + (month <= 2));
    if (year < 0 || year > 9999)
        return R_FAILED;
    int fields[6] = {year, month, day, (int)(rest / 3600), (int)(rest / 60 % 60), (int)(rest % 60)};
    int widths[6] = {4, 2, 2, 2, 2, 2};
    char *out = text;
    for (int i = 0; i < 6; ++i) {
        for (int digit = widths[i] - 1; digit >= 0; --digit) {
            int value = fields[i];
            for (int k = 0; k < digit; ++k)
                value /= 10;
            *out++ = (char)('0' + value % 10);
        }
    }
    *out++ = 'Z';
    *out = '\0';
    if (length != NULL)
        *length = 15;
    return 0;
}

/* The CA store: Sony's libssl has its roots built in; these serve CA_LIST.cer's, as PEM text,
 * which libhttp decodes and parses with 29AAC768 */

#define LOOKUP_SLOTS 8

/* Which of the roots with a name a thread was given last: libhttp asks again for the same name
 * when the one it got doesn't verify the certificate, and is given the next, then none (Sony's
 * libssl has one root per name; with the same answer libhttp would ask forever) */
static struct {
    int used;
    unsigned int thread;
    uint32_t name;
    unsigned int next;
} g_lookups[LOOKUP_SLOTS];

static uint32_t hash_bytes(const unsigned char *data, size_t length)
{
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < length; ++i)
        hash = (hash ^ data[i]) * 16777619u;
    return hash;
}

void vs_certificate_lookups_reset(void)
{
    unsigned int thread = vs_platform_thread_id();
    vs_lock();
    for (int i = 0; i < LOOKUP_SLOTS; ++i)
        if (g_lookups[i].used && g_lookups[i].thread == thread)
            g_lookups[i].used = 0;
    vs_unlock();
}

/* The thread's slot for the name: the index of the root it's given next, advanced when it's given
 * one */
static unsigned int lookup_next(uint32_t name, int advance)
{
    unsigned int thread = vs_platform_thread_id();
    vs_lock();
    int slot = -1;
    for (int i = 0; i < LOOKUP_SLOTS && slot < 0; ++i)
        if (g_lookups[i].used && g_lookups[i].thread == thread)
            slot = i;
    if (slot >= 0 && g_lookups[slot].name != name) {
        g_lookups[slot].name = name;
        g_lookups[slot].next = 0;
    }
    unsigned int next = slot >= 0 ? g_lookups[slot].next : 0;
    if (advance) {
        for (int i = 0; i < LOOKUP_SLOTS && slot < 0; ++i)
            if (!g_lookups[i].used)
                slot = i;
        if (slot < 0)
            slot = (int)(thread % LOOKUP_SLOTS);
        g_lookups[slot].used = 1;
        g_lookups[slot].thread = thread;
        g_lookups[slot].name = name;
        g_lookups[slot].next = next + 1;
    }
    vs_unlock();
    return next;
}

static size_t pem_size(size_t der_length)
{
    size_t base64 = 4 * ((der_length + 2) / 3);
    return sizeof("-----BEGIN CERTIFICATE-----\n") - 1 + base64 + (base64 + 63) / 64 +
           sizeof("-----END CERTIFICATE-----\n") - 1 + 1;
}

/* PEM text of DER, NUL-terminated, into out (pem_size bytes) */
static int write_pem(const unsigned char *der, size_t length, char *out)
{
    static const char begin[] = "-----BEGIN CERTIFICATE-----\n", end[] = "-----END CERTIFICATE-----\n";
    size_t base64 = 4 * ((length + 2) / 3), written = 0;
    unsigned char *encoded = malloc(base64 + 1);
    if (encoded == NULL)
        return R_ALLOC_FAILURE;
    if (mbedtls_base64_encode(encoded, base64 + 1, &written, der, length) != 0) {
        free(encoded);
        return R_FAILED;
    }
    memcpy(out, begin, sizeof(begin) - 1);
    out += sizeof(begin) - 1;
    for (size_t i = 0; i < written; i += 64) {
        size_t line = written - i < 64 ? written - i : 64;
        memcpy(out, encoded + i, line);
        out += line;
        *out++ = '\n';
    }
    memcpy(out, end, sizeof(end));
    free(encoded);
    return 0;
}

/* Where answers go: an array of pointers at the buffer's start, then the texts */
static int place_answers(char ***entries, char *buffer, unsigned int size, size_t count, size_t text_size,
                         char ***texts, char **text)
{
    size_t table = count * sizeof(char *);
    if (size < table + text_size)
        return VS_ERROR_INVALID_VALUE;
    *texts = (char **)(void *)buffer;
    *text = buffer + table;
    *entries = *texts;
    return 0;
}

/* NID 0x3746501F, Sony 0x810481CD: the root whose subject is the name, as (name, &entries,
 * buffer, size, &total, flag) → 1 with entries[0] its PEM text, or 0 when there's none; with no
 * buffer only total, the size the buffer needs */
int sceSslInternalGetCertificateAuthorityByName(const void *name_handle, char ***entries, char *buffer,
                                                unsigned int size, unsigned int *total, int flag)
{
    const VsName *name = name_handle;
    (void)flag;
    if (total != NULL)
        *total = 0;
    if (entries != NULL)
        *entries = NULL;
    if (!is_name(name) || name->length == 0)
        return 0;
    const VitalsCaIndex *index = vs_ca_index();
    if (index == NULL)
        return 0;
    mbedtls_x509_crt child, *candidates = NULL;
    memset(&child, 0, sizeof(child));
    child.issuer = name->head;
    if (vitals_ca_index_find((void *)index, &child, &candidates) != 0 || candidates == NULL)
        return 0;
    int writing = entries != NULL && buffer != NULL;
    uint32_t key = hash_bytes(name->der, name->length);
    unsigned int wanted = lookup_next(key, 0), ordinal = 0;
    const mbedtls_x509_crt *found = NULL;
    for (const mbedtls_x509_crt *candidate = candidates; candidate != NULL && candidate->raw.p != NULL;
         candidate = candidate->next) {
        VsName *subject = vs_name_new(&candidate->subject_raw);
        int same = subject != NULL && names_equal(subject, name);
        vs_name_free(subject);
        if (same && ordinal++ == wanted) {
            found = candidate;
            break;
        }
    }
    int result = 0;
    if (found != NULL) {
        size_t text_size = pem_size(found->raw.len);
        if (total != NULL)
            *total = (unsigned int)(sizeof(char *) + text_size);
        result = 1;
        if (writing) {
            char **texts, *text;
            result = place_answers(entries, buffer, size, 1, text_size, &texts, &text);
            if (result == 0)
                result = write_pem(found->raw.p, found->raw.len, text);
            if (result == 0) {
                texts[0] = text;
                (void)lookup_next(key, 1);
                result = 1;
            } else {
                *entries = NULL;
                result = result == R_ALLOC_FAILURE ? VS_ERROR_OUT_OF_MEMORY : result;
            }
        }
    }
    mbedtls_x509_crt_free(candidates);
    mbedtls_free(candidates);
    return result;
}

/* Reads root i's PEM block from the bundle into text, NUL-terminated */
static int read_block(const VitalsCaIndex *index, SceUID fd, size_t i, char *text)
{
    const VitalsCaEntry *entry = &index->entries[i];
    size_t consumed = 0;
    if (sceIoLseek(fd, entry->offset, SCE_SEEK_SET) < 0)
        return VS_ERROR_INTERNAL;
    while (consumed < entry->length) {
        int count = sceIoRead(fd, text + consumed, (SceSize)(entry->length - consumed));
        if (count <= 0)
            return VS_ERROR_INTERNAL;
        consumed += (size_t)count;
    }
    text[consumed++] = '\n';
    text[consumed] = '\0';
    return 0;
}

/* NID 0x064DFC99, Sony 0x810481E1: roots by number, as (group, mask, &entries, buffer, size,
 * &total) → how many, or 0x80010086 when the group has none of them. The bundle's roots are in
 * groups of 32 from 1, a mask bit for each; group 0 with mask 0xFFFFFFFF is all of them. With no
 * buffer only total, the size the buffer needs */
int sceSslInternalGetCertificateAuthority(unsigned int group, unsigned int mask, char ***entries, char *buffer,
                                          unsigned int size, unsigned int *total)
{
    if (total != NULL)
        *total = 0;
    if (entries != NULL)
        *entries = NULL;
    const VitalsCaIndex *index = vs_ca_index();
    size_t count = 0, text_size = 0, first = 0, last = 0;
    if (index != NULL && group == 0 && mask == 0xFFFFFFFFu) {
        last = index->count;
    } else if (index != NULL && group > 0 && (size_t)(group - 1) * 32 < index->count) {
        first = (size_t)(group - 1) * 32;
        last = first + 32 < index->count ? first + 32 : index->count;
    }
    for (size_t i = first; i < last; ++i) {
        if (group != 0 && (mask & (1u << (i - first))) == 0)
            continue;
        ++count;
        text_size += index->entries[i].length + 2;
    }
    if (count == 0)
        return CA_NOT_FOUND;
    if (total != NULL)
        *total = (unsigned int)(count * sizeof(char *) + text_size);
    if (entries == NULL || buffer == NULL)
        return (int)count;
    char **texts, *text;
    int result = place_answers(entries, buffer, size, count, text_size, &texts, &text);
    if (result != 0)
        return result;
    SceUID fd = sceIoOpen(index->path, SCE_O_RDONLY, 0);
    if (fd < 0) {
        *entries = NULL;
        return VS_ERROR_INTERNAL;
    }
    size_t written = 0;
    for (size_t i = first; i < last && result == 0; ++i) {
        if (group != 0 && (mask & (1u << (i - first))) == 0)
            continue;
        result = read_block(index, fd, i, text);
        texts[written++] = text;
        text += index->entries[i].length + 2;
    }
    (void)sceIoClose(fd);
    if (result != 0) {
        *entries = NULL;
        return result;
    }
    return (int)count;
}

/* NID 0x349B0E73, Sony 0x810481F5: the serial numbers a root's group refuses, as (group, mask,
 * &entries, &count) with entries VsItems; Sony's has ten for one root, the bundle's roots none */
int sceSslInternalCaRevoked(unsigned int group, unsigned int mask, const void **entries, unsigned int *count)
{
    (void)group, (void)mask;
    if (entries == NULL || count == NULL)
        return VS_ERROR_INVALID_VALUE;
    *entries = NULL;
    *count = 0;
    return 0;
}
