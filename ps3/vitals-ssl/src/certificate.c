/* SSL-C's certificate API as Sony's libhttp calls it (its verify callback at 0x25088, its CA loader
 * at 0x25dcc, its client certificate at 0x26058): certificates, names and their entries,
 * extensions, keys, BER items and times, over Mbed TLS. From the Vita's
 * vitals-ssl/src/certificate.c, for the PS3's API, which is SSL-C's own (SSLCERT_*) rather than
 * Cert-C's; each function's comment gives the address of Sony's code (dumps/ps3/4.93-cex/libssl.prx), where
 * SSLCERT's go through SSL-C's table */

#include "certificate.h"

#include "core.h"
#include "crypto_platform.h"
#include "ssl_api.h"
#include "vs.h"

#include <mbedtls/asn1.h>
#include <mbedtls/md.h>
#include <mbedtls/oid.h>
#include <mbedtls/platform.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/psa_util.h>
#include <psa/crypto.h>

#include <stdio.h>
#include <string.h>

#define VS_CALLOC mbedtls_calloc
#define VS_FREE mbedtls_free

/* SSL-C's reasons */
#define R_FAILED 10001
#define R_BUFFER_TOO_SMALL 10006
#define R_NULL_ARG 10017

/* OpenSSL's ASN.1 time tags, which the date getters give and R_time_import takes */
#define VS_UTC_TIME 23
#define VS_GENERALIZED_TIME 24

/* ---- certificates ---- */

int vs_is_cert(const void *handle)
{
	const VsCert *cert = handle;
	return cert != NULL && cert->magic == VS_CERT_MAGIC && cert->crt != NULL;
}

const mbedtls_x509_crt *vs_cert_crt(const void *handle)
{
	return vs_is_cert(handle) ? ((const VsCert *)handle)->crt : NULL;
}

static void forget_cached(VsCert *cert)
{
	if (cert->public_key != NULL) {
		mbedtls_pk_free(&cert->public_key->pk);
		cert->public_key->magic = 0;
		VS_FREE(cert->public_key);
		cert->public_key = NULL;
	}
}

void vs_cert_borrow(VsCert *cert, mbedtls_x509_crt *crt)
{
	memset(cert, 0, sizeof(*cert));
	cert->magic = VS_CERT_MAGIC;
	cert->crt = crt;
}

void vs_cert_return(VsCert *cert)
{
	forget_cached(cert);
	cert->magic = 0;
	cert->crt = NULL;
}

static int is_pem(const unsigned char *data, size_t length)
{
	static const char begin[] = "-----BEGIN";
	for (size_t at = 0; at + sizeof(begin) - 1 <= length; ++at)
		if (memcmp(data + at, begin, sizeof(begin) - 1) == 0)
			return 1;
	return 0;
}

VsCert *vs_cert_parse(const unsigned char *data, size_t length)
{
	VsCert *cert = VS_CALLOC(1, sizeof(*cert));
	if (cert == NULL)
		return NULL;
	mbedtls_x509_crt_init(&cert->own);
	/* PEM (text before it allowed, as libhttp's next certificate starts at the previous one's
	 * newline) wants its NUL: a copy with one */
	int result;
	if (is_pem(data, length)) {
		unsigned char *text = VS_CALLOC(1, length + 1);
		result = MBEDTLS_ERR_X509_ALLOC_FAILED;
		if (text != NULL) {
			memcpy(text, data, length);
			result = mbedtls_x509_crt_parse(&cert->own, text, length + 1);
			VS_FREE(text);
		}
	} else {
		result = mbedtls_x509_crt_parse_der(&cert->own, data, length);
	}
	if (result != 0 || cert->own.raw.p == NULL) {
		mbedtls_x509_crt_free(&cert->own);
		VS_FREE(cert);
		return NULL;
	}
	cert->magic = VS_CERT_MAGIC;
	cert->crt = &cert->own;
	cert->owned = 1;
	return cert;
}

/* SSLCERT_free (0x365e8): a certificate parsed for the caller; the server's, which the verify
 * callback is given, stay the connection's */
void SSLCERT_free(void *handle)
{
	VsCert *cert = handle;
	if (!vs_is_cert(cert) || !cert->owned)
		return;
	forget_cached(cert);
	mbedtls_x509_crt_free(&cert->own);
	cert->magic = 0;
	VS_FREE(cert);
}

/* ---- names ---- */

static VsName *name_of(VsCert *cert, int subject)
{
	if (!vs_is_cert(cert))
		return NULL;
	VsName *name = subject ? &cert->subject : &cert->issuer;
	if (name->magic != VS_NAME_MAGIC) {
		name->magic = VS_NAME_MAGIC;
		name->head = subject ? &cert->crt->subject : &cert->crt->issuer;
		name->raw = subject ? cert->crt->subject_raw : cert->crt->issuer_raw;
	}
	return name;
}

/* SSLCERT_get_subject_name and SSLCERT_get_issuer_name (0x1c6e8, 0x1c6cc): the certificate's own
 * name, which lasts as long as it does; NULL without a certificate */
void *SSLCERT_get_subject_name(void *cert)
{
	return name_of(cert, 1);
}

void *SSLCERT_get_issuer_name(void *cert)
{
	return name_of(cert, 0);
}

static const VsName *is_name(const void *handle)
{
	const VsName *name = handle;
	return name != NULL && name->magic == VS_NAME_MAGIC ? name : NULL;
}

/* SSLCERT_NAME_get_entry_count (0x1c670): its entries, each attribute of each RDN; 0 without a name */
int SSLCERT_NAME_get_entry_count(const void *handle)
{
	const VsName *name = is_name(handle);
	int count = 0;
	for (const mbedtls_x509_name *entry = name != NULL ? name->head : NULL; entry != NULL && entry->oid.p != NULL;
	     entry = entry->next)
		++count;
	return count;
}

/* SSLCERT_NAME_get_entry (0x1c68c): entry index, NULL outside them */
void *SSLCERT_NAME_get_entry(const void *handle, int index)
{
	const VsName *name = is_name(handle);
	if (name == NULL || index < 0)
		return NULL;
	const mbedtls_x509_name *entry = name->head;
	for (; entry != NULL && entry->oid.p != NULL && index > 0; entry = entry->next)
		--index;
	return entry != NULL && entry->oid.p != NULL ? (void *)entry : NULL;
}

/* SSLCERT_NAME_ENTRY_get_info (0x2f050): the attribute's type, its tag (6, OBJECT), bytes and length,
 * and its value, its string type, bytes and length; each where its pointer isn't NULL. 1, or 0
 * without an entry */
int SSLCERT_NAME_ENTRY_get_info(const void *handle, int *oid_tag, const unsigned char **oid, int *oid_length,
                                int *value_type, const unsigned char **value, int *value_length)
{
	const mbedtls_x509_name *entry = handle;
	if (entry == NULL)
		return 0;
	if (oid_tag != NULL)
		*oid_tag = MBEDTLS_ASN1_OID;
	if (oid != NULL)
		*oid = entry->oid.p;
	if (oid_length != NULL)
		*oid_length = (int)entry->oid.len;
	if (value_type != NULL)
		*value_type = entry->val.tag;
	if (value != NULL)
		*value = entry->val.p;
	if (value_length != NULL)
		*value_length = (int)entry->val.len;
	return 1;
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

/* SSLCERT_NAME_cmp (0x1d8b4, OpenSSL 0.9.8's X509_NAME_cmp): 0 when the names are the same, as Mbed
 * TLS compares them (the same attributes in order, string values without regard to case), else the
 * difference of their entry counts, or 1 */
int SSLCERT_NAME_cmp(const void *first, const void *second)
{
	const VsName *a = is_name(first), *b = is_name(second);
	if (a == NULL || b == NULL)
		return a == b ? 0 : 1;
	if (a->raw.len == b->raw.len && memcmp(a->raw.p, b->raw.p, a->raw.len) == 0)
		return 0;
	int counts = SSLCERT_NAME_get_entry_count(a) - SSLCERT_NAME_get_entry_count(b);
	if (counts != 0)
		return counts;
	const mbedtls_x509_name *x = a->head, *y = b->head;
	for (; x != NULL && y != NULL && x->oid.p != NULL && y->oid.p != NULL; x = x->next, y = y->next) {
		if (x->oid.len != y->oid.len || memcmp(x->oid.p, y->oid.p, x->oid.len) != 0 ||
		    x->MBEDTLS_PRIVATE(next_merged) != y->MBEDTLS_PRIVATE(next_merged) || !same_text(&x->val, &y->val))
			return 1;
	}
	return 0;
}

uint32_t vs_name_hash_raw(const unsigned char *der, size_t length)
{
	unsigned char digest[16];
	size_t digest_length = 0;
	if (psa_hash_compute(PSA_ALG_MD5, der, length, digest, sizeof(digest), &digest_length) != PSA_SUCCESS)
		return 0;
	return (uint32_t)digest[0] | (uint32_t)digest[1] << 8 | (uint32_t)digest[2] << 16 | (uint32_t)digest[3] << 24;
}

/* SSLCERT_NAME_hash (0x1d640): OpenSSL 0.9.8's X509_NAME_hash, the first 4 bytes of the MD5 of the
 * name's DER, little-endian, as `openssl x509 -subject_hash_old` prints it; 0 without a name */
unsigned long SSLCERT_NAME_hash(const void *handle)
{
	const VsName *name = is_name(handle);
	return name != NULL ? vs_name_hash_raw(name->raw.p, name->raw.len) : 0;
}

/* SSLCERT_OID_to_string (0x2f6b4): X.520's attribute types (2.5.4.x), the long name or the short
 * one; NULL for any other OID, as Sony's table has no more */
const char *SSLCERT_OID_to_string(const unsigned char *oid, int length, int short_name)
{
	static const struct {
		unsigned char attribute;
		const char *name, *short_name;
	} names[] = {{3, "commonName", "CN"},
	             {4, "surname", "SN"},
	             {5, "serialNumber", "SERIAL"},
	             {6, "countryName", "C"},
	             {7, "localityName", "L"},
	             {8, "stateOrProvinceName", "ST"},
	             {10, "organizationName", "O"},
	             {11, "organizationalUnitName", "OU"},
	             {12, "title", "T"},
	             {13, "description", "D"},
	             {42, "givenName", "G"},
	             {43, "initials", "I"},
	             {45, "x500UniqueIdentifier", "X500UID"}};
	if (oid == NULL || length != 3 || oid[0] != 0x55 || oid[1] != 0x04)
		return NULL;
	for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
		if (names[i].attribute == oid[2])
			return short_name ? names[i].short_name : names[i].name;
	return NULL;
}

/* ---- dates ---- */

/* As the certificate would hold it: UTCTime from 1950 to 2049, GeneralizedTime otherwise (RFC 5280),
 * which Mbed TLS keeps only parsed */
static int date_text(const mbedtls_x509_time *time, char text[16])
{
	if (time->year >= 1950 && time->year < 2050) {
		snprintf(text, 16, "%02d%02d%02d%02d%02d%02dZ", time->year % 100, time->mon, time->day, time->hour,
		         time->min, time->sec);
		return VS_UTC_TIME;
	}
	snprintf(text, 16, "%04d%02d%02d%02d%02d%02dZ", time->year, time->mon, time->day, time->hour, time->min,
	         time->sec);
	return VS_GENERALIZED_TIME;
}

static int date_of(VsCert *cert, int after, int *type, const unsigned char **data, int *length)
{
	if (!vs_is_cert(cert))
		return 0;
	char *text = after ? cert->not_after : cert->not_before;
	int tag = date_text(after ? &cert->crt->valid_to : &cert->crt->valid_from, text);
	if (type != NULL)
		*type = tag;
	if (data != NULL)
		*data = (const unsigned char *)text;
	if (length != NULL)
		*length = (int)strlen(text);
	return 1;
}

/* SSLCERT_get_notBefore and SSLCERT_get_notAfter (0x3222c, 0x32290): the date's ASN.1 tag (23
 * UTCTime, 24 GeneralizedTime) and text ("250101000000Z"), which last as long as the certificate,
 * for R_time_import. 1, or 0 without a certificate */
int SSLCERT_get_notBefore(void *cert, int *type, const unsigned char **data, int *length)
{
	return date_of(cert, 0, type, data, length);
}

int SSLCERT_get_notAfter(void *cert, int *type, const unsigned char **data, int *length)
{
	return date_of(cert, 1, type, data, length);
}

/* ---- extensions ---- */

/* The extension with the OID among the certificate's: the DER in its extnValue, which points into
 * the certificate, and whether it's critical. 0, or -1 when there's none */
static int find_extension(const mbedtls_x509_crt *crt, const unsigned char *oid, size_t oid_length, int *critical,
                          const unsigned char **value, size_t *value_length)
{
	if (crt->v3_ext.p == NULL)
		return -1;
	unsigned char *p = crt->v3_ext.p, *end = p + crt->v3_ext.len;
	size_t length = 0;
	if (mbedtls_asn1_get_tag(&p, end, &length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
		return -1;
	end = p + length;
	while (p < end) {
		if (mbedtls_asn1_get_tag(&p, end, &length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
			return -1;
		unsigned char *next = p + length;
		size_t id_length = 0;
		int is_critical = 0;
		if (mbedtls_asn1_get_tag(&p, next, &id_length, MBEDTLS_ASN1_OID) != 0)
			return -1;
		unsigned char *id = p;
		p += id_length;
		if (p < next && *p == MBEDTLS_ASN1_BOOLEAN && mbedtls_asn1_get_bool(&p, next, &is_critical) != 0)
			return -1;
		if (mbedtls_asn1_get_tag(&p, next, &length, MBEDTLS_ASN1_OCTET_STRING) != 0 || p + length != next)
			return -1;
		if (id_length == oid_length && memcmp(id, oid, oid_length) == 0) {
			*critical = is_critical != 0;
			*value = p;
			*value_length = length;
			return 0;
		}
		p = next;
	}
	return -1;
}

/* SSLCERT_get_extension (0x1ef60): the extension with the OID, given as its bytes up to a NUL (Sony's
 * takes their length with strlen), libhttp's subjectAltName "\x55\x1d\x11": whether it's critical
 * and the DER in its OCTET STRING, which lasts as long as the certificate. 1, or 0 without it */
int SSLCERT_get_extension(void *cert, const char *oid, int *critical, const unsigned char **value, int *length)
{
	const mbedtls_x509_crt *crt = vs_cert_crt(cert);
	if (crt == NULL || oid == NULL)
		return 0;
	int is_critical = 0;
	const unsigned char *data = NULL;
	size_t data_length = 0;
	if (find_extension(crt, (const unsigned char *)oid, strlen(oid), &is_critical, &data, &data_length) != 0)
		return 0;
	if (critical != NULL)
		*critical = is_critical;
	if (value != NULL)
		*value = data;
	if (length != NULL)
		*length = (int)data_length;
	return 1;
}

/* SSLCERT_get_basic_constraints_int (0x313ec): basicConstraints' critical flag, its cA as Sony's
 * gives it (0, set as soon as the SEQUENCE is read, then the BOOLEAN's own byte, 0xFF for TRUE) and
 * its pathLenConstraint, set only when there is one (libhttp starts it at 10). 1, or 0 without the
 * extension or when it can't be read */
int SSLCERT_get_basic_constraints_int(void *cert, int *critical, int *path_length, int *is_ca)
{
	static const unsigned char basic_constraints[] = {0x55, 0x1d, 0x13};
	const mbedtls_x509_crt *crt = vs_cert_crt(cert);
	int is_critical = 0;
	const unsigned char *data = NULL;
	size_t length = 0;
	if (crt == NULL ||
	    find_extension(crt, basic_constraints, sizeof(basic_constraints), &is_critical, &data, &length) != 0)
		return 0;
	unsigned char *p = (unsigned char *)data, *end = p + length;
	size_t inner = 0;
	if (mbedtls_asn1_get_tag(&p, end, &inner, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0 || p + inner != end)
		return 0;
	if (critical != NULL)
		*critical = is_critical;
	if (is_ca != NULL)
		*is_ca = 0;
	if (p < end && *p == MBEDTLS_ASN1_BOOLEAN) {
		if (end - p < 3 || p[1] != 1)
			return 0;
		if (is_ca != NULL)
			*is_ca = p[2];
		p += 3;
	}
	if (p < end) {
		int path = 0;
		if (mbedtls_asn1_get_int(&p, end, &path) != 0)
			return 0;
		if (path_length != NULL)
			*path_length = path;
	}
	return 1;
}

/* ---- keys ---- */

int vs_is_key(const void *handle)
{
	const VsKey *key = handle;
	return key != NULL && key->magic == VS_KEY_MAGIC;
}

mbedtls_pk_context *vs_key_pk(void *handle)
{
	return vs_is_key(handle) ? &((VsKey *)handle)->pk : NULL;
}

/* SSLCERT_get_pubkey (0x1d348): the certificate's public key, which lasts as long as it does (Sony's
 * caches it in the certificate too); NULL without one */
void *SSLCERT_get_pubkey(void *handle)
{
	VsCert *cert = handle;
	if (!vs_is_cert(cert))
		return NULL;
	if (cert->public_key == NULL) {
		VsKey *key = VS_CALLOC(1, sizeof(*key));
		if (key == NULL)
			return NULL;
		mbedtls_pk_init(&key->pk);
		if (mbedtls_pk_parse_public_key(&key->pk, cert->crt->pk_raw.p, cert->crt->pk_raw.len) != 0) {
			mbedtls_pk_free(&key->pk);
			VS_FREE(key);
			return NULL;
		}
		key->magic = VS_KEY_MAGIC;
		key->owned_by_cert = 1;
		cert->public_key = key;
	}
	return cert->public_key;
}

/* EVP_PKEY_free: a key _cellSslPemReadPrivateKey made; a certificate's public key stays the
 * certificate's */
void EVP_PKEY_free(void *handle)
{
	VsKey *key = handle;
	if (!vs_is_key(key) || key->owned_by_cert)
		return;
	mbedtls_pk_free(&key->pk);
	key->magic = 0;
	VS_FREE(key);
}

/* SSLCERT_verify (0x1c980, X509_verify): 1 when the key made the certificate's signature, 0 when it
 * didn't, -1 without both */
int SSLCERT_verify(void *cert, void *key)
{
	const mbedtls_x509_crt *crt = vs_cert_crt(cert);
	mbedtls_pk_context *pk = vs_key_pk(key);
	if (crt == NULL || pk == NULL)
		return -1;
	unsigned char hash[MBEDTLS_MD_MAX_SIZE];
	size_t hash_length;
	/* As Mbed TLS checks a chain: the signed part's hash, then the key's verification of it */
	if (psa_hash_compute(mbedtls_md_psa_alg_from_type(crt->MBEDTLS_PRIVATE(sig_md)), crt->tbs.p, crt->tbs.len, hash,
	                     sizeof(hash), &hash_length) != PSA_SUCCESS)
		return 0;
	return mbedtls_pk_verify_ext(crt->MBEDTLS_PRIVATE(sig_pk), pk, crt->MBEDTLS_PRIVATE(sig_md), hash, hash_length,
	                             crt->MBEDTLS_PRIVATE(sig).p, crt->MBEDTLS_PRIVATE(sig).len) == 0;
}

/* SSLCERT_check_private_key (0x1d488): 1 when the private key is the certificate's, 0 when it isn't */
int SSLCERT_check_private_key(void *cert, void *key)
{
	const mbedtls_x509_crt *crt = vs_cert_crt(cert);
	mbedtls_pk_context *pk = vs_key_pk(key);
	if (crt == NULL || pk == NULL)
		return 0;
	return mbedtls_pk_check_pair(&crt->pk, pk) == 0;
}

/* A private key from PEM or DER (the client certificate's, which libhttp writes into a memory BIO);
 * NULL when it isn't one */
void *vs_key_parse(const unsigned char *data, size_t length)
{
	if (data == NULL || length == 0)
		return NULL;
	VsKey *key = VS_CALLOC(1, sizeof(*key));
	unsigned char *text = VS_CALLOC(1, length + 1);
	if (key == NULL || text == NULL) {
		VS_FREE(key);
		VS_FREE(text);
		return NULL;
	}
	memcpy(text, data, length);
	mbedtls_pk_init(&key->pk);
	/* With its NUL for PEM */
	int result = mbedtls_pk_parse_key(&key->pk, text, length + (is_pem(text, length) ? 1 : 0), NULL, 0);
	mbedtls_platform_zeroize(text, length);
	VS_FREE(text);
	if (result != 0) {
		mbedtls_pk_free(&key->pk);
		VS_FREE(key);
		return NULL;
	}
	key->magic = VS_KEY_MAGIC;
	return key;
}

/* ---- PEM ---- */

/* Where the PEM block at start ends: just past its "-----END " line's last character (before the
 * newline or NUL after it), as Sony's finds it; 0 when there's no such line */
static size_t pem_block_end(const unsigned char *start, size_t length)
{
	static const char marker[] = "-----END ";
	int line_start = 1, found = 0;
	size_t at = 0;
	for (; at < length; ++at) {
		if (found && (start[at] == '\n' || start[at] == '\0'))
			break;
		if (!found && line_start && length - at > sizeof(marker) - 1 &&
		    memcmp(start + at, marker, sizeof(marker) - 1) == 0) {
			found = 1;
			at += sizeof(marker) - 2;
			continue;
		}
		line_start = start[at] == '\n';
	}
	return found ? at : 0;
}

/* NID 0x9447404F, Sony 0x36054: the PEM certificate at start, as libhttp reads a game's CA list, up
 * to the end of its "-----END " line (a newline or a NUL after it), which *used says; NULL when
 * there's no such line, with PEM's "no start line" queued (reason 108), which libhttp takes as the
 * list's end. A block Mbed TLS can't read is stepped over, and the next one given, *used counting
 * both: Sony's SSL-C reads the MD2-signed roots among its CAs (CA09, CA12, CA27), which Mbed TLS
 * refuses, and libhttp gives up on the whole list at a certificate it's refused (0x80710A01) */
void *cellSsl_9447404F(const unsigned char *start, const unsigned char *end, int *used)
{
	if (start == NULL || end == NULL || end <= start) {
		vs_error_push(VS_ERR_PACK(9, 109, 108));
		return NULL;
	}
	size_t length = (size_t)(end - start), offset = 0;
	for (;;) {
		size_t at = pem_block_end(start + offset, length - offset);
		if (at == 0) {
			vs_error_push(VS_ERR_PACK(9, 109, 108));
			return NULL;
		}
		VsCert *cert = vs_cert_parse(start + offset, at);
		if (cert != NULL) {
			if (used != NULL)
				*used = (int)(offset + at);
			return cert;
		}
		VS_LOG("ca list: a certificate Mbed TLS can't read, %u bytes in, stepped over", (unsigned)offset);
		offset += at;
	}
}

/* ---- BER items ---- */

/* SSL-C's BER item, as libhttp reads it after BER_read_item: the content's length and bytes, and
 * the header's length */
typedef struct VsBerItem {
	uint32_t length;           /* 0 */
	const unsigned char *data; /* 4: the content */
	unsigned char unused;      /* 8 */
	unsigned char header[23];  /* 9: a copy of the header */
	uint32_t tag;              /* 32: its number */
	unsigned char flags;       /* 36: the class and constructed bits, 2 for an indefinite length */
	unsigned char header_length; /* 37 */
	unsigned char more_flags;  /* 38: 8 for an indefinite length that's primitive */
	unsigned char reserved;
} VsBerItem;

_Static_assert(sizeof(void *) != 4 || __builtin_offsetof(VsBerItem, tag) == 32, "SSL-C's BER item layout");
_Static_assert(sizeof(void *) != 4 || __builtin_offsetof(VsBerItem, header_length) == 37, "SSL-C's BER item layout");

/* BER_read_item (0xba4c): the header at data, as Sony's reads it. 0, 1 for a tag of more than 5
 * bytes, 2 for data that runs out, 3 for a length of more than 4 bytes; as Sony's, it doesn't check
 * that the content fits (libhttp gives it a parsed certificate's DER) */
int BER_read_item(void *handle, const unsigned char *data, unsigned int length)
{
	VsBerItem *item = handle;
	if (item == NULL || data == NULL || length <= 1)
		return 2;
	unsigned int at = 1;
	uint32_t tag = data[0] & 0x1Fu;
	item->flags = data[0] & 0xE0u;
	if (tag == 0x1F) {
		tag = 0;
		for (int bytes = 0;; ++bytes) {
			if (bytes == 5)
				return 1;
			if (at == length)
				return 2;
			unsigned char byte = data[at++];
			tag = tag << 7 | (byte & 0x7Fu);
			if ((byte & 0x80u) == 0)
				break;
		}
	}
	item->tag = tag;
	if (at >= length)
		return 2;
	unsigned char first = data[at++];
	uint32_t content = first;
	if (first & 0x80u) {
		unsigned int bytes = first & 0x7Fu;
		if (bytes == 0) {
			/* Indefinite */
			content = 0;
			item->flags |= 2;
			if ((data[0] & 0x20u) == 0)
				item->more_flags |= 8;
		} else {
			if (bytes > 4)
				return 3;
			if (at + bytes >= length)
				return 2;
			content = 0;
			for (unsigned int i = 0; i < bytes; ++i)
				content = content << 8 | data[at++];
		}
	}
	item->length = content;
	item->data = data + at;
	item->header_length = (unsigned char)at;
	memcpy(item->header, data, at <= sizeof(item->header) ? at : sizeof(item->header));
	return 0;
}

/* ---- times ---- */

/* SSL-C's R_TIME: seconds since 1970, then a word Sony leaves 0 (12 bytes) */
typedef struct VsTime {
	int64_t seconds;
	uint32_t zero;
} VsTime;

/* R_time (Sony's provider, 0x17e4): the time now into time; time, or NULL without one or the date */
void *R_time(void *handle)
{
	VsTime *time = handle;
	if (time == NULL)
		return NULL;
	int64_t now = vitals_crypto_time(NULL);
	if (now < 0)
		return NULL;
	time->seconds = now;
	time->zero = 0;
	return time;
}

/* R_time_new (0x13fcc): a time, set to now; NULL without memory or the date */
void *R_time_new(void)
{
	VsTime *time = VS_CALLOC(1, sizeof(*time));
	if (time != NULL && R_time(time) == NULL) {
		VS_FREE(time);
		time = NULL;
	}
	return time;
}

/* R_time_free (0x14030) */
void R_time_free(void *time)
{
	VS_FREE(time);
}

/* R_time_cmp (SSL-C's 0x14810): -1, 0 or 1 as the first is before, at or after the second; no time
 * counts as 0 seconds, as Sony's compares zeros for it */
int R_time_cmp(const void *first, const void *second)
{
	int64_t a = first != NULL ? ((const VsTime *)first)->seconds : 0;
	int64_t b = second != NULL ? ((const VsTime *)second)->seconds : 0;
	return a < b ? -1 : a > b ? 1 : 0;
}

static int digits(const unsigned char *text, int count, int *value)
{
	*value = 0;
	for (int i = 0; i < count; ++i) {
		if (text[i] < '0' || text[i] > '9')
			return -1;
		*value = *value * 10 + (text[i] - '0');
	}
	return 0;
}

/* Seconds since 1970 for a date (Howard Hinnant's days_from_civil) */
static int64_t epoch_seconds(int64_t year, int month, int day, int hour, int minute, int second)
{
	year -= month <= 2;
	int64_t era = (year >= 0 ? year : year - 399) / 400;
	int64_t of_era = year - era * 400;
	int64_t of_year = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1;
	int64_t days = era * 146097 + of_era * 365 + of_era / 4 - of_era / 100 + of_year - 719468;
	return days * 86400 + hour * 3600 + minute * 60 + second;
}

/* R_time_import (SSL-C's 0x163a0): ASN.1 time text into time, format 23 UTCTime (YYMMDDHHMM[SS]Z,
 * years 50 to 99 being 19xx) or 24 GeneralizedTime (YYYYMMDDHHMM[SS]Z); 0, 10017 without a time
 * (R_NULL_ARG), 10001 for text it can't read */
int R_time_import(const unsigned char *data, int length, int format, void *handle)
{
	VsTime *time = handle;
	if (time == NULL)
		return R_NULL_ARG;
	if (data == NULL || (format != VS_UTC_TIME && format != VS_GENERALIZED_TIME))
		return R_FAILED;
	int year_digits = format == VS_UTC_TIME ? 2 : 4;
	int year, month, day, hour, minute, second = 0;
	if (length < year_digits + 8 || digits(data, year_digits, &year) != 0 ||
	    digits(data + year_digits, 2, &month) != 0 || digits(data + year_digits + 2, 2, &day) != 0 ||
	    digits(data + year_digits + 4, 2, &hour) != 0 || digits(data + year_digits + 6, 2, &minute) != 0)
		return R_FAILED;
	int at = year_digits + 8;
	if (length >= at + 2 && data[at] >= '0' && data[at] <= '9') {
		if (digits(data + at, 2, &second) != 0)
			return R_FAILED;
		at += 2;
	}
	if (at >= length || data[at] != 'Z' || month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 ||
	    minute > 59 || second > 60)
		return R_FAILED;
	if (format == VS_UTC_TIME)
		year += year < 50 ? 2000 : 1900;
	time->seconds = epoch_seconds(year, month, day, hour, minute, second);
	time->zero = 0;
	return 0;
}

/* R_time_export (SSL-C's 0x16cfc): time as ASN.1 text into buffer, NUL-terminated, format 23 or 24;
 * 0, 10017 without a time or buffer, 10006 when it doesn't fit, 10001 for another format */
int R_time_export(const void *handle, int format, unsigned char *buffer, int size)
{
	const VsTime *time = handle;
	if (time == NULL || buffer == NULL)
		return R_NULL_ARG;
	if (format != VS_UTC_TIME && format != VS_GENERALIZED_TIME)
		return R_FAILED;
	mbedtls_time_t seconds = time->seconds;
	struct tm date;
	if (mbedtls_platform_gmtime_r(&seconds, &date) == NULL)
		return R_FAILED;
	char text[64];
	int year = date.tm_year + 1900;
	if (format == VS_UTC_TIME)
		snprintf(text, sizeof(text), "%02d%02d%02d%02d%02d%02dZ", year % 100, date.tm_mon + 1, date.tm_mday,
		         date.tm_hour, date.tm_min, date.tm_sec);
	else
		snprintf(text, sizeof(text), "%04d%02d%02d%02d%02d%02dZ", year, date.tm_mon + 1, date.tm_mday,
		         date.tm_hour, date.tm_min, date.tm_sec);
	size_t length = strlen(text);
	if (size < 0 || (size_t)size <= length)
		return R_BUFFER_TOO_SMALL;
	memcpy(buffer, text, length + 1);
	return 0;
}

/* SSLCERT_from_binary (0x398cc, d2i_X509): a certificate from the DER at *data, length bytes at most,
 * *data moved past it; into *out too when out is given (its old certificate freed). NULL when it
 * isn't one */
void *SSLCERT_from_binary(void **out, const unsigned char **data, long length)
{
	if (data == NULL || *data == NULL || length <= 0)
		return NULL;
	VsCert *cert = vs_cert_parse(*data, (size_t)length);
	if (cert == NULL)
		return NULL;
	*data += cert->own.raw.len;
	if (out != NULL) {
		SSLCERT_free(*out);
		*out = cert;
	}
	return cert;
}

/* SSLCERT_NAME_oneline (X509_NAME_oneline): the name as "/C=GB/O=vitals-ssl/CN=chain.test" with
 * SSLCERT_OID_to_string's short names (an OID it doesn't name as its dotted form) into buffer,
 * size bytes at most; buffer, or NULL without one */
char *SSLCERT_NAME_oneline(const void *handle, char *buffer, int size)
{
	const VsName *name = is_name(handle);
	if (buffer == NULL || size <= 0)
		return NULL;
	int used = 0;
	buffer[0] = '\0';
	for (const mbedtls_x509_name *entry = name != NULL ? name->head : NULL;
	     entry != NULL && entry->oid.p != NULL && used < size - 1; entry = entry->next) {
		const char *type = SSLCERT_OID_to_string(entry->oid.p, (int)entry->oid.len, 1);
		char dotted[64];
		if (type == NULL) {
			if (mbedtls_oid_get_numeric_string(dotted, sizeof(dotted), &entry->oid) < 0) {
				dotted[0] = '?';
				dotted[1] = '\0';
			}
			type = dotted;
		}
		int wrote = snprintf(buffer + used, (size_t)(size - used), "/%s=%.*s", type, (int)entry->val.len,
		                     (const char *)entry->val.p);
		if (wrote < 0)
			break;
		used += wrote;
	}
	return buffer;
}

/* NID 0xC132E990, Sony 0x0: the certificate's signature algorithm, as SSL-C numbers it (its NID, from
 * its table of 159 objects at 0x58f04: OpenSSL 0.9.8's numbers, and its own for SHA-2 with RSA),
 * which np_oauth compares with 65 (sha1WithRSAEncryption); 0 for one the table doesn't have
 * (ECDSA with SHA-2, RSA-PSS) */
int cellSsl_C132E990(void *cert)
{
	const mbedtls_x509_crt *crt = vs_cert_crt(cert);
	if (crt == NULL)
		return 0;
	int rsa = crt->MBEDTLS_PRIVATE(sig_pk) == MBEDTLS_PK_SIGALG_RSA_PKCS1V15;
	int ecdsa = crt->MBEDTLS_PRIVATE(sig_pk) == MBEDTLS_PK_SIGALG_ECDSA;
	switch (crt->MBEDTLS_PRIVATE(sig_md)) {
	case MBEDTLS_MD_MD5:
		return rsa ? 8 : 0;
	case MBEDTLS_MD_SHA1:
		/* ecdsa-with-SHA1 is in the table twice (179 and 193): Sony's search finds 179 */
		return rsa ? 65 : ecdsa ? 179 : 0;
	case MBEDTLS_MD_SHA224:
		return rsa ? 133 : 0;
	case MBEDTLS_MD_SHA256:
		return rsa ? 130 : 0;
	case MBEDTLS_MD_SHA384:
		return rsa ? 131 : 0;
	case MBEDTLS_MD_SHA512:
		return rsa ? 132 : 0;
	default:
		return 0;
	}
}

/* NID 0x597BE64A (0x2f91c, then 0x65a0): whether the RSA key signed the data, a PKCS #1 v1.5
 * signature with the hash of the signature algorithm (SSL-C's NID, as C132E990 gives it: 8 MD5, 65
 * SHA-1, 130 SHA-256, 131 SHA-384, 132 SHA-512, 133 SHA-224; 7, MD2, is Sony's too, but Mbed TLS has
 * no MD2). The data is hashed here, and the signature must be the key's size. 1, or 0 */
int cellSsl_597BE64A(int nid, const void *data, uint32_t length, const unsigned char *signature,
                     uint32_t signature_length, void *key)
{
	mbedtls_md_type_t md;
	switch (nid) {
	case 8:
		md = MBEDTLS_MD_MD5;
		break;
	case 65:
		md = MBEDTLS_MD_SHA1;
		break;
	case 130:
		md = MBEDTLS_MD_SHA256;
		break;
	case 131:
		md = MBEDTLS_MD_SHA384;
		break;
	case 132:
		md = MBEDTLS_MD_SHA512;
		break;
	case 133:
		md = MBEDTLS_MD_SHA224;
		break;
	default:
		return 0;
	}
	mbedtls_pk_context *pk = vs_key_pk(key);
	if (pk == NULL || (data == NULL && length != 0) || signature == NULL ||
	    !PSA_KEY_TYPE_IS_RSA(mbedtls_pk_get_key_type(pk)) ||
	    signature_length != (mbedtls_pk_get_bitlen(pk) + 7) / 8)
		return 0;
	unsigned char hash[MBEDTLS_MD_MAX_SIZE];
	size_t hash_length;
	if (psa_hash_compute(mbedtls_md_psa_alg_from_type(md), data, length, hash, sizeof(hash), &hash_length) !=
	    PSA_SUCCESS)
		return 0;
	return mbedtls_pk_verify_ext(MBEDTLS_PK_SIGALG_RSA_PKCS1V15, pk, md, hash, hash_length, signature,
	                             signature_length) == 0;
}

/* ---- the certificates of March 2011 ---- */

/* NID 0x2E8CC56D, Sony 0xbe4: whether the certificate is one of the nine fraudulently issued
 * through Comodo in March 2011, by its issuer (UTN-USERFirst-Hardware) and serial number: 1 when it
 * is, 0 when it isn't. Sony's compares each serial with strlen, which stops at the leading 0x00 of
 * seven of them, so only two can match there; these compare every byte. 0x80740001 before
 * cellSslInit, 0x80740006 for a certificate without an issuer */
int cellSsl_2E8CC56D(void *cert)
{
	static const unsigned char serials[9][17] = {
	    {0x04, 0x7e, 0xcb, 0xe9, 0xfc, 0xa5, 0x5f, 0x7b, 0xd0, 0x9e, 0xae, 0x36, 0xe1, 0x0c, 0xae, 0x1e},
	    {0x00, 0xf5, 0xc8, 0x6a, 0xf3, 0x61, 0x62, 0xf1, 0x3a, 0x64, 0xf5, 0x4f, 0x6d, 0xc9, 0x58, 0x7c, 0x06},
	    {0x00, 0xd7, 0x55, 0x8f, 0xda, 0xf5, 0xf1, 0x10, 0x5b, 0xb2, 0x13, 0x28, 0x2b, 0x70, 0x77, 0x29, 0xa3},
	    {0x39, 0x2a, 0x43, 0x4f, 0x0e, 0x07, 0xdf, 0x1f, 0x8a, 0xa3, 0x05, 0xde, 0x34, 0xe0, 0xc2, 0x29},
	    {0x3e, 0x75, 0xce, 0xd4, 0x6b, 0x69, 0x30, 0x21, 0x21, 0x88, 0x30, 0xae, 0x86, 0xa8, 0x2a, 0x71},
	    {0x00, 0xe9, 0x02, 0x8b, 0x95, 0x78, 0xe4, 0x15, 0xdc, 0x1a, 0x71, 0x0a, 0x2b, 0x88, 0x15, 0x44, 0x47},
	    {0x00, 0x92, 0x39, 0xd5, 0x34, 0x8f, 0x40, 0xd1, 0x69, 0x5a, 0x74, 0x54, 0x70, 0xe1, 0xf2, 0x3f, 0x43},
	    {0x00, 0xb0, 0xb7, 0x13, 0x3e, 0xd0, 0x96, 0xf9, 0xb5, 0x6f, 0xae, 0x91, 0xc8, 0x74, 0xbd, 0x3a, 0xc0},
	    {0x00, 0xd8, 0xf3, 0x5f, 0x4e, 0xb7, 0x87, 0x2b, 0x2d, 0xab, 0x06, 0x92, 0xe3, 0x15, 0x38, 0x2f, 0xb0}};
	static const char issuer[] = "UTN-USERFirst-Hardware";
	static const unsigned char common_name[] = {0x55, 0x04, 0x03};
	if (!vs_initialized())
		return VITALS_SSL_ERROR_NOT_INITIALIZED;
	const mbedtls_x509_crt *crt = vs_cert_crt(cert);
	if (crt == NULL || crt->issuer.oid.p == NULL)
		return (int)0x80740006;
	int from_utn = 0;
	for (const mbedtls_x509_name *entry = &crt->issuer; entry != NULL && entry->oid.p != NULL; entry = entry->next)
		if (entry->oid.len == sizeof(common_name) && memcmp(entry->oid.p, common_name, sizeof(common_name)) == 0 &&
		    entry->val.len == sizeof(issuer) - 1 &&
		    memcmp(entry->val.p, issuer, sizeof(issuer) - 1) == 0)
			from_utn = 1;
	if (!from_utn)
		return 0;
	for (size_t i = 0; i < sizeof(serials) / sizeof(serials[0]); ++i) {
		size_t length = serials[i][0] == 0x00 ? 17 : 16;
		if (crt->serial.len == length && memcmp(crt->serial.p, serials[i], length) == 0)
			return 1;
	}
	return 0;
}
