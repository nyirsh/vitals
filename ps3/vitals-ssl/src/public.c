/* The public cellSsl certificate functions games and np_oauth call (cellSslCertGet*), and
 * cellSslGetMemoryInfo, over certificate.c's objects. As Sony's (ps3-dumps/libssl.prx 0x30 to
 * 0x1408), each checks, in order: cellSslInit (0x80740001), that its object can be read
 * (0x80740005; Sony's asks the kernel, syscall 351), that its out pointers aren't NULL
 * (0x80740004), then what it reads (0x80740006 and on) */

#include "certificate.h"
#include "core.h"
#include "pool.h"
#include "ssl_api.h"
#include "vs.h"

#include <mbedtls/asn1.h>
#include <psa/crypto.h>

#include <string.h>

#define VS_ERROR_INVALID_CERTIFICATE ((int)0x80740005)
#define VS_ERROR_UNRETRIEVABLE ((int)0x80740006)
#define VS_ERROR_INVALID_FORMAT ((int)0x80740007)
#define VS_ERROR_NOT_FOUND ((int)0x80740008)
#define VS_ERROR_INCORRECT_TIME ((int)0x80740033)
#define VS_ERROR_UNDEFINED_TIME_TYPE ((int)0x80740034)
#define VS_ERROR_NO_MEMORY ((int)0x80740035)
#define VS_ERROR_NO_STRING ((int)0x80740036)

/* 1970-01-01 in CellRtcTick's microseconds since 0001-01-01, as Sony's adds it */
#define VS_RTC_EPOCH UINT64_C(0x00DCBFFEFF2BC000)

/* The checks every one starts with: 0, or Sony's error */
static int check(const void *object)
{
	if (!vs_initialized())
		return VITALS_SSL_ERROR_NOT_INITIALIZED;
	return vs_platform_readable(object) ? 0 : VS_ERROR_INVALID_CERTIFICATE;
}

/* cellSslCertGetSerialNumber (0x4e0): the serial number's bytes (the INTEGER's, as the certificate
 * has them) and length, which last as long as the certificate; 0x80740008 for an empty one */
int cellSslCertGetSerialNumber(void *cert, const unsigned char **data, size_t *length)
{
	int result = check(cert);
	if (result != 0)
		return result;
	if (data == NULL || length == NULL)
		return VITALS_SSL_ERROR_NO_BUFFER;
	const mbedtls_x509_crt *crt = vs_cert_crt(cert);
	if (crt == NULL)
		return VS_ERROR_INVALID_FORMAT;
	if (crt->serial.len == 0)
		return VS_ERROR_NOT_FOUND;
	*data = crt->serial.p;
	*length = crt->serial.len;
	return 0;
}

/* cellSslCertGetPublicKey (0x604): the public key's DER, which lasts as long as the certificate.
 * Sony's reads SSL-C's item 9 of the certificate; here it's the SubjectPublicKeyInfo, which isn't
 * checked against Sony's own output yet */
int cellSslCertGetPublicKey(void *cert, const unsigned char **data, size_t *length)
{
	int result = check(cert);
	if (result != 0)
		return result;
	if (data == NULL || length == NULL)
		return VITALS_SSL_ERROR_NO_BUFFER;
	const mbedtls_x509_crt *crt = vs_cert_crt(cert);
	if (crt == NULL || crt->pk_raw.p == NULL)
		return VS_ERROR_UNRETRIEVABLE;
	*data = crt->pk_raw.p;
	*length = crt->pk_raw.len;
	return 0;
}

/* An RSA public key's modulus (0) or exponent (1), the INTEGER's bytes in the certificate's
 * SubjectPublicKeyInfo: 0, or -1 for a key that isn't RSA */
static int rsa_part(const mbedtls_x509_crt *crt, int which, const unsigned char **data, size_t *length)
{
	static const unsigned char rsa[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};
	unsigned char *p = crt->pk_raw.p, *end = p + crt->pk_raw.len;
	size_t size = 0;
	if (p == NULL || mbedtls_asn1_get_tag(&p, end, &size, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
		return -1;
	unsigned char *algorithm_end;
	if (mbedtls_asn1_get_tag(&p, end, &size, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
		return -1;
	algorithm_end = p + size;
	if (mbedtls_asn1_get_tag(&p, algorithm_end, &size, MBEDTLS_ASN1_OID) != 0 || size != sizeof(rsa) ||
	    memcmp(p, rsa, sizeof(rsa)) != 0)
		return -1;
	p = algorithm_end;
	if (mbedtls_asn1_get_bitstring_null(&p, end, &size) != 0 ||
	    mbedtls_asn1_get_tag(&p, end, &size, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
		return -1;
	for (int part = 0; part <= which; ++part) {
		if (mbedtls_asn1_get_tag(&p, end, &size, MBEDTLS_ASN1_INTEGER) != 0)
			return -1;
		if (part == which) {
			*data = p;
			*length = size;
			return 0;
		}
		p += size;
	}
	return -1;
}

static int get_rsa_part(void *cert, int which, const unsigned char **data, size_t *length)
{
	int result = check(cert);
	if (result != 0)
		return result;
	if (data == NULL || length == NULL)
		return VITALS_SSL_ERROR_NO_BUFFER;
	const mbedtls_x509_crt *crt = vs_cert_crt(cert);
	if (crt == NULL || rsa_part(crt, which, data, length) != 0)
		return VS_ERROR_UNRETRIEVABLE;
	return 0;
}

/* cellSslCertGetRsaPublicKeyModulus and cellSslCertGetRsaPublicKeyExponent (0x3c8, 0xacc): the
 * INTEGER's bytes as the certificate has them (a modulus may start with 0x00), which last as long
 * as the certificate; 0x80740006 for a key that isn't RSA */
int cellSslCertGetRsaPublicKeyModulus(void *cert, const unsigned char **data, size_t *length)
{
	return get_rsa_part(cert, 0, data, length);
}

int cellSslCertGetRsaPublicKeyExponent(void *cert, const unsigned char **data, size_t *length)
{
	return get_rsa_part(cert, 1, data, length);
}

/* A date as a CellRtcTick (cellSslCertGetNotBefore 0x8c4, cellSslCertGetNotAfter 0xf0c): microseconds since 0001-01-01. 0x80740036 without its text,
 * 0x80740034 for a tag that isn't a time, 0x80740033 for text Sony's wouldn't read (UTCTime longer
 * than 13 characters, GeneralizedTime than 20, or not a date), 0x80740035 without memory */
static int date_tick(void *cert, int after, uint64_t *tick)
{
	int result = check(cert);
	if (result != 0)
		return result;
	if (tick == NULL)
		return VITALS_SSL_ERROR_NO_BUFFER;
	int type = 0, length = 0;
	const unsigned char *text = NULL;
	if ((after ? SSLCERT_get_notAfter(cert, &type, &text, &length) : SSLCERT_get_notBefore(cert, &type, &text, &length)) == 0)
		return VS_ERROR_UNRETRIEVABLE;
	if (text == NULL || length == 0)
		return VS_ERROR_NO_STRING;
	*tick = 0;
	if (type != 23 && type != 24)
		return VS_ERROR_UNDEFINED_TIME_TYPE;
	if (length > (type == 23 ? 13 : 20))
		return VS_ERROR_INCORRECT_TIME;
	void *time = R_time_new();
	if (time == NULL)
		return VS_ERROR_NO_MEMORY;
	result = R_time_import(text, length, type, time) == 0 ? 0 : VS_ERROR_INCORRECT_TIME;
	if (result == 0)
		*tick = (uint64_t)(*(const int64_t *)time) * UINT64_C(1000000) + VS_RTC_EPOCH;
	R_time_free(time);
	return result;
}

int cellSslCertGetNotBefore(void *cert, uint64_t *tick)
{
	return date_tick(cert, 0, tick);
}

int cellSslCertGetNotAfter(void *cert, uint64_t *tick)
{
	return date_tick(cert, 1, tick);
}

/* cellSslCertGetSubjectName and cellSslCertGetIssuerName (0x7f8, 0x2fc): the name, for the two functions
 * after; 0x80740006 without one */
static int get_name(void *cert, int subject, void **name)
{
	int result = check(cert);
	if (result != 0)
		return result;
	if (name == NULL)
		return VITALS_SSL_ERROR_NO_BUFFER;
	void *found = subject ? SSLCERT_get_subject_name(cert) : SSLCERT_get_issuer_name(cert);
	if (found == NULL)
		return VS_ERROR_UNRETRIEVABLE;
	*name = found;
	return 0;
}

int cellSslCertGetSubjectName(void *cert, void **name)
{
	return get_name(cert, 1, name);
}

int cellSslCertGetIssuerName(void *cert, void **name)
{
	return get_name(cert, 0, name);
}

/* cellSslCertGetNameEntryCount (0x230): 0x80740006 for a name without entries */
int cellSslCertGetNameEntryCount(const void *name, uint32_t *count)
{
	int result = check(name);
	if (result != 0)
		return result;
	if (count == NULL)
		return VITALS_SSL_ERROR_NO_BUFFER;
	int entries = SSLCERT_NAME_get_entry_count(name);
	if (entries <= 0)
		return VS_ERROR_UNRETRIEVABLE;
	*count = (uint32_t)entries;
	return 0;
}

/* cellSslCertGetNameEntryInfo (0x30): an entry's attribute name, long or (short_names) short, and
 * its value's bytes and length, which last as long as the certificate. A type SSLCERT_OID_to_string
 * doesn't name is "emailAddress" ("E") for PKCS#9's email address and "{UNKNOWN}" ("-") for any
 * other, as Sony's. 0x80740006 for an entry the name hasn't */
int cellSslCertGetNameEntryInfo(const void *name, uint32_t index, const char **oid_name, const unsigned char **value,
                                size_t *value_length, int short_names)
{
	static const unsigned char email[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01};
	int result = check(name);
	if (result != 0)
		return result;
	if (oid_name == NULL || value == NULL || value_length == NULL)
		return VITALS_SSL_ERROR_NO_BUFFER;
	void *entry = SSLCERT_NAME_get_entry(name, (int)index);
	if (entry == NULL)
		return VS_ERROR_UNRETRIEVABLE;
	const unsigned char *oid = NULL, *data = NULL;
	int oid_length = 0, length = 0;
	if (SSLCERT_NAME_ENTRY_get_info(entry, NULL, &oid, &oid_length, NULL, &data, &length) == 0)
		return VS_ERROR_INVALID_FORMAT;
	*value = data;
	*value_length = (size_t)length;
	const char *text = SSLCERT_OID_to_string(oid, oid_length, short_names);
	if (text == NULL) {
		int is_email = oid_length == (int)sizeof(email) && memcmp(oid, email, sizeof(email)) == 0;
		text = is_email ? (short_names ? "E" : "emailAddress") : (short_names ? "-" : "{UNKNOWN}");
	}
	*oid_name = text;
	return 0;
}

/* cellSslCertGetMd5Fingerprint (0x704): the MD5 of the certificate's DER into buffer (16 bytes),
 * and its length */
int cellSslCertGetMd5Fingerprint(void *cert, unsigned char *buffer, uint32_t *length)
{
	int result = check(cert);
	if (result != 0)
		return result;
	if (buffer == NULL || length == NULL)
		return VITALS_SSL_ERROR_NO_BUFFER;
	const mbedtls_x509_crt *crt = vs_cert_crt(cert);
	size_t digest_length = 0;
	if (crt == NULL ||
	    psa_hash_compute(PSA_ALG_MD5, crt->raw.p, crt->raw.len, buffer, 16, &digest_length) != PSA_SUCCESS)
		return VS_ERROR_UNRETRIEVABLE;
	*length = (uint32_t)digest_length;
	return 0;
}

/* cellSslGetMemoryInfo (0x1408): the pool's free size, the first word of its mallinfo and the whole
 * mallinfo (10 words), each where its pointer isn't NULL. 0, as Sony's, which doesn't check
 * cellSslInit (without a pool, these are 0) */
int cellSslGetMemoryInfo(uint32_t *free_size, uint32_t *arena, uint32_t *mallinfo)
{
	uint32_t free_now = 0, info[10] = {0};
	(void)vitals_pool_stats(&free_now, info);
	if (free_size != NULL)
		*free_size = free_now;
	if (arena != NULL)
		*arena = info[0];
	if (mallinfo != NULL)
		memcpy(mallinfo, info, sizeof(info));
	return 0;
}
