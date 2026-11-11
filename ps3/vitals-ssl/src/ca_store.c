/* The CA store: Sony's CA certificates in flash, as Sony's libssl gives them to games and libhttp
 * (dumps/ps3/4.93-cex/libssl.prx: its table at 0x54f18, cellSslCertificateLoader at 0x245c and 0x21ec,
 * 205B060C at 0x1d10, 68D3409E at 0x2028, the file reader at 0x1e00, CC6A0CB5 at 0x2464), and
 * behind them Mozilla's certificates Sony's lack, for the servers Sony's CAs no longer sign, and the
 * user's own (custom-certs.pem, as they wrote it). Sony's CAs are read from flash when asked for and
 * checked against the SHA-1s in the table (common/sony_cas.h), as Sony's are; the other two files
 * are indexed on first use (their roots' subject hashes and places in the files) and only the root
 * asked for is read. As on the Vita, Mozilla's file holds only what Sony's lack (the app leaves
 * Sony's out), and the user's is read as it is, so an edit applies to the next game */

#include "ca_store.h"
#include "sony_cas.h"
#include "vitals/ca_scan.h"

#include "certificate.h"
#include "core.h"
#include "sha1.h"
#include "ssl_api.h"
#include "vs.h"

#include <mbedtls/platform.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>

#include <string.h>

#define VS_CALLOC mbedtls_calloc
#define VS_FREE mbedtls_free

/* Sony's: a CA that isn't there, or isn't allowed, or whose file isn't what the table says */
#define VS_ERROR_UNKNOWN_LOAD_CERT ((int)0x80740037)
/* Sony's for a buffer too small for a CA */
#define VS_ERROR_BUFFER_TOO_SMALL VITALS_SSL_ERROR_NO_MEMORY

/* The mask bits 68D3409E treats apart, CA01 to CA05's: a caller with none but these gets only them */
#define VS_LOW_MASK UINT64_C(0x1F)

/* ---- Sony's CAs ---- */


/* The 21 games the loader gives CA05 alone, whatever their flags, and whose mask CC6A0CB5 replaces
 * with those flags (0x52bf8) */
static const char k_titles[][10] = {
	"BLUS31193", "NPUB31246", "BLUS31483", "BLES01882", "BLES01883", "BLES01884", "NPEB01396",
	"BLES02085", "BLJM61056", "NPJB00408", "NPJB00586", "BCUS98242", "NPUA80661", "NPUA70139",
	"NPUA70144", "BCES00484", "BCES01104", "NPEA00315", "NPHA80150", "NPHA80165", "BCAS20160",
};

/* The flags the loader was last given (0x5c350) */
static uint64_t g_loader_flags;

static uint64_t mask_of(const SonyCa *ca)
{
	return ca->number != 0 ? UINT64_C(1) << (ca->number - 1) : 0;
}

static int listed_title(void)
{
	char id[10];
	vs_platform_title_id(id);
	for (size_t i = 0; i < sizeof(k_titles) / sizeof(k_titles[0]); ++i)
		if (memcmp(id, k_titles[i], 10) == 0)
			return 1;
	return 0;
}

static uint32_t hash_of(const void *name)
{
	return (uint32_t)SSLCERT_NAME_hash(name);
}

/* Sony's reader (0x1e00): the CA's size added to *required (when there is one), then, when
 * writing, the CA into buffer (size bytes) with its SHA-1 checked. 0, or Sony's error; a file that
 * can't be read is 0x80740037 here, where Sony's gives cellFs's error */
/* The CA's file: CAnn.cer, or CA_LIST.cer for the parts of it; 0, or -1 */
static int sony_ca_path(const SonyCa *ca, char path[256], char file[16])
{
	memcpy(file, "CA_LIST.cer", sizeof("CA_LIST.cer"));
	if (ca->number != 0) {
		memcpy(file, "CA00.cer", sizeof("CA00.cer"));
		file[2] = (char)('0' + ca->number / 10);
		file[3] = (char)('0' + ca->number % 10);
	}
	return vs_platform_sony_cert_path(path, 256, file) != 0 ? -1 : 0;
}

static int read_sony_ca(const SonyCa *ca, char *buffer, size_t size, uint32_t *required, int writing)
{
	char path[256], file[16];
	if (sony_ca_path(ca, path, file) != 0)
		return VS_ERROR_UNKNOWN_LOAD_CERT;
	int fd = vs_platform_file_open(path);
	if (fd < 0)
		return VS_ERROR_UNKNOWN_LOAD_CERT;
	int result = 0;
	uint32_t length = ca->length;
	if (length == 0) {
		int64_t file_size = vs_platform_file_size(fd);
		if (file_size < 0 || file_size > UINT32_MAX)
			result = VS_ERROR_UNKNOWN_LOAD_CERT;
		length = (uint32_t)file_size;
	}
	if (result == 0 && required != NULL)
		*required += length;
	if (result == 0 && writing) {
		if (length > size)
			result = VS_ERROR_BUFFER_TOO_SMALL;
		else if (ca->offset != 0 && vs_platform_file_seek(fd, ca->offset) != 0)
			result = VS_ERROR_UNKNOWN_LOAD_CERT;
	}
	if (result == 0 && writing) {
		/* Not PSA's hash: the XMB loads its CAs outside cellSslInit and cellSslEnd */
		VsSha1 sha1;
		unsigned char digest[20];
		size_t done = 0;
		vs_sha1_start(&sha1);
		while (done < length) {
			int count = vs_platform_file_read(fd, buffer + done, length - done);
			if (count <= 0)
				break;
			vs_sha1_update(&sha1, buffer + done, (size_t)count);
			done += (size_t)count;
		}
		vs_sha1_finish(&sha1, digest);
		if (done != length || memcmp(digest, ca->sha1, sizeof(digest)) != 0)
			result = VS_ERROR_UNKNOWN_LOAD_CERT;
	}
	vs_platform_file_close(fd);
	VITALS_VERBOSE("ca store: %s %u bytes, %d", file, (unsigned)length, result);
	return result;
}

/* NID 0x571AFACA (0x245c, then 0x21ec): the CAs whose mask bits are in flags, each the first entry
 * with its bit, in the table's order, one after another into buffer (size bytes, zeroed first); the
 * size they take into *required, which is enough without a buffer. Flags are kept for CC6A0CB5, and
 * the games it knows get CA05 alone. 0; 0x80740004 with neither buffer nor required; 0x80740035 for
 * a buffer too small; 0x80740037 for a bit no CA has or a file that isn't the table's, *required
 * then the size so far */
static int load_cas(uint64_t flags, char *buffer, size_t size, size_t *required, const char *name)
{
	(void)name;
	if (buffer == NULL && required == NULL)
		return VITALS_SSL_ERROR_NO_BUFFER;
	int writing = buffer != NULL;
	if (writing)
		memset(buffer, 0, size);
	uint32_t total = 0;
	int result = 0;
	if (flags != 0) {
		size_t i = 0;
		for (; i < VS_SONY_CAS; ++i) {
			const SonyCa *ca = &k_sony_cas[i];
			if ((flags & mask_of(ca)) == 0)
				continue;
			result = read_sony_ca(ca, writing ? buffer + total : NULL, writing ? size - total : 0, &total,
			                      writing);
			if (result < 0)
				break;
			flags &= ~mask_of(ca);
			if (flags == 0)
				break;
		}
		if (i == VS_SONY_CAS)
			result = VS_ERROR_UNKNOWN_LOAD_CERT;
	}
	if (required != NULL)
		*required = total;
	VITALS_LOG("%s: %u bytes, 0x%08X", name, (unsigned)total, (unsigned)result);
	return result;
}

int cellSslCertificateLoader(uint64_t flags, char *buffer, size_t size, size_t *required)
{
	g_loader_flags = flags;
	if (listed_title())
		flags = 16;
	return load_cas(flags, buffer, size, required, "cellSslCertificateLoader");
}

/* NID 0x06B1E9BF (0x2454): cellSslCertificateLoader's own loader, without what it does first: the
 * flags aren't kept for CC6A0CB5, and no game gets CA05 in their place */
int cellSsl_06B1E9BF(uint64_t flags, char *buffer, size_t size, size_t *required)
{
	return load_cas(flags, buffer, size, required, "cellSsl_06B1E9BF");
}

/* NID 0x404136C1 (0x1a68): whether each of the flags' bits is a CA's: 0 when they all are (or
 * there are none), 0x80740037 when one isn't (CA01 to CA59 are bits 0 to 58) */
int cellSsl_404136C1(uint64_t flags)
{
	for (size_t i = 0; i < VS_SONY_CAS && flags != 0; ++i)
		flags &= ~mask_of(&k_sony_cas[i]);
	return flags == 0 ? 0 : VS_ERROR_UNKNOWN_LOAD_CERT;
}

/* NID 0x86C38810 (0x1ad8): the first CA (in the table's order) with one of *flags' bits, its whole
 * file written into the BIO through buffer (size bytes at a time), and its bit taken out of *flags.
 * 0, also when no CA has a bit (*flags as it was); 0x80740037 when the file can't be read;
 * 0x80740035 when the BIO can't take it (*flags then as it was). Sony's leaves the file open when it
 * succeeds, loops forever on a file shorter than its size, ignores BIO_write's failures and has no
 * check for a NULL flags pointer, buffer or size; vitals' closes it and gives 0x80740004 for those */
int cellSsl_86C38810(uint64_t *flags, void *bio, char *buffer, uint32_t size)
{
	if (flags == NULL || buffer == NULL || size == 0)
		return VITALS_SSL_ERROR_NO_BUFFER;
	const SonyCa *ca = NULL;
	for (size_t i = 0; i < VS_SONY_CAS && ca == NULL; ++i)
		if ((*flags & mask_of(&k_sony_cas[i])) != 0)
			ca = &k_sony_cas[i];
	if (ca == NULL)
		return 0;
	char path[256], file[16];
	int fd = sony_ca_path(ca, path, file) == 0 ? vs_platform_file_open(path) : -1;
	if (fd < 0)
		return VS_ERROR_UNKNOWN_LOAD_CERT;
	int64_t length = vs_platform_file_size(fd);
	int result = length < 0 ? VS_ERROR_UNKNOWN_LOAD_CERT : 0;
	for (int64_t done = 0; result == 0 && done < length;) {
		int count = vs_platform_file_read(fd, buffer, size);
		if (count <= 0)
			result = VS_ERROR_UNKNOWN_LOAD_CERT;
		else if (vs_bio_write(bio, buffer, (size_t)count) != count)
			result = VS_ERROR_BUFFER_TOO_SMALL;
		else
			done += count;
	}
	vs_platform_file_close(fd);
	VITALS_LOG("cellSsl_86C38810: %s %d bytes, 0x%08X", file, (int)length, (unsigned)result);
	if (result == 0)
		*flags &= ~mask_of(ca);
	return result;
}

/* NID 0x205B060C (0x1d10): the mask and flag of the name's CA among Sony's, the last entry with its
 * hash; 0 and 0 for any other, Mozilla's roots included, which libhttp's check accepts. 0, or
 * 0x80740004 without mask or flag */
int cellSsl_205B060C(const void *name, uint64_t *mask, int *flag)
{
	if (mask == NULL || flag == NULL)
		return VITALS_SSL_ERROR_NO_BUFFER;
	*flag = 0;
	*mask = 0;
	uint32_t hash = hash_of(name);
	for (size_t i = 0; i < VS_SONY_CAS; ++i) {
		if (k_sony_cas[i].hash == hash) {
			*flag = k_sony_cas[i].flag;
			*mask = mask_of(&k_sony_cas[i]);
		}
	}
	return 0;
}

/* NID 0xCC6A0CB5 (0x2464): for the games the loader knows, libhttp's mask becomes the flags the
 * loader was last given; others' stays. 0 */
int cellSsl_CC6A0CB5(uint64_t *mask)
{
	if (listed_title() && mask != NULL)
		*mask = g_loader_flags;
	return 0;
}

/* ---- Mozilla's bundle ---- */

#define VS_BUNDLE_BLOCK VITALS_CA_SCAN_BLOCK
/* A read of a file at a time, from the game's pool */
#define VS_BUNDLE_CHUNK 512u
#define VS_BUNDLE_GROWTH 64u

/* A root: its subject's hash (SSLCERT_NAME_hash's), the file it's in (vs_platform_store_path's
 * part: Mozilla's, or the user's custom-certs.pem) and its PEM block's place there */
typedef struct BundleRoot {
	uint32_t hash;
	uint32_t offset, length;
	unsigned part;
} BundleRoot;

/* Built on first use, until cellSslEnd: 0 not yet, 1 built, -1 no bundle */
static int g_bundle_state;
static BundleRoot *g_roots;
static size_t g_root_count, g_root_capacity;

/* A block of the part being indexed (vitals/ca_scan.h): a root when it's a certificate. 0, or -1
 * when the index can't grow */
static int add_root(void *context, const unsigned char *block, size_t length, uint32_t offset, uint32_t end)
{
	unsigned part = *(const unsigned *)context;
	++length; /* with its NUL, as Mbed TLS takes PEM */
	mbedtls_x509_crt crt;
	mbedtls_x509_crt_init(&crt);
	int result = 0;
	if (mbedtls_x509_crt_parse(&crt, block, length) == 0 && crt.raw.p != NULL) {
		if (g_root_count == g_root_capacity) {
			BundleRoot *roots = VS_CALLOC(g_root_capacity + VS_BUNDLE_GROWTH, sizeof(*roots));
			if (roots == NULL) {
				result = -1;
			} else {
				if (g_roots != NULL)
					memcpy(roots, g_roots, g_root_count * sizeof(*roots));
				VS_FREE(g_roots);
				g_roots = roots;
				g_root_capacity += VS_BUNDLE_GROWTH;
			}
		}
		if (result == 0) {
			BundleRoot *root = &g_roots[g_root_count++];
			root->hash = vs_name_hash_raw(crt.subject_raw.p, crt.subject_raw.len);
			root->offset = offset;
			root->length = end - offset;
			root->part = part;
		}
	}
	mbedtls_x509_crt_free(&crt);
	return result;
}

/* The part's file, read in order from its start (vitals/ca_scan.h's read) */
static int read_part(void *context, uint32_t offset, void *buffer, uint32_t size)
{
	(void)offset;
	return vs_platform_file_read(*(const int *)context, buffer, size);
}

/* A part's roots, through the scanner both consoles' libssl use (../../shared/src/ca_scan.c): what
 * isn't a whole certificate is skipped. 0 (also for a part that isn't there), or -1 when it can't be
 * read or the index can't grow */
static int index_part(unsigned part, VitalsCaScanner *scanner)
{
	int fd = vs_platform_file_open(vs_platform_store_path(part));
	if (fd < 0)
		return 0;
	int result = vitals_ca_scan(scanner, UINT32_MAX, read_part, &fd, add_root, &part) == 0 ? 0 : -1;
	vs_platform_file_close(fd);
	return result;
}

/* The store's roots past Sony's: Mozilla's file, then the user's custom-certs.pem, either of which
 * may be missing. 0, or -1 when a part can't be read or there's no root in them */
static int index_bundle(void)
{
	VitalsCaScanner *scanner = VS_CALLOC(1, VITALS_CA_SCANNER_SIZE(VS_BUNDLE_CHUNK));
	int result = -1;
	if (scanner != NULL) {
		scanner->chunk_size = VS_BUNDLE_CHUNK;
		result = 0;
		for (unsigned part = 0; result == 0 && vs_platform_store_path(part) != NULL; ++part)
			result = index_part(part, scanner);
		if (result == 0 && g_root_count == 0)
			result = -1;
	}
	VS_FREE(scanner);
	return result;
}

static void forget_bundle(void)
{
	VS_FREE(g_roots);
	g_roots = NULL;
	g_root_count = g_root_capacity = 0;
}

static int bundle_ready(void)
{
	if (g_bundle_state == 0) {
		g_bundle_state = index_bundle() == 0 ? 1 : -1;
		if (g_bundle_state < 0)
			forget_bundle();
		VITALS_LOG("ca store: %u roots in Mozilla's file and custom-certs.pem", (unsigned)g_root_count);
	}
	return g_bundle_state > 0;
}

/* The root's PEM block, read into block (VS_BUNDLE_BLOCK + 1 bytes, NUL-terminated); 1 when its
 * subject is the name's DER */
static int read_root(const BundleRoot *root, int fd, unsigned char *block, const mbedtls_x509_buf *name)
{
	size_t done = 0;
	if (root->length > VS_BUNDLE_BLOCK || vs_platform_file_seek(fd, root->offset) != 0)
		return 0;
	while (done < root->length) {
		int count = vs_platform_file_read(fd, block + done, root->length - done);
		if (count <= 0)
			return 0;
		done += (size_t)count;
	}
	block[done] = '\0';
	mbedtls_x509_crt crt;
	mbedtls_x509_crt_init(&crt);
	int same = mbedtls_x509_crt_parse(&crt, block, done + 1) == 0 && crt.subject_raw.len == name->len &&
	           memcmp(crt.subject_raw.p, name->p, name->len) == 0;
	mbedtls_x509_crt_free(&crt);
	return same;
}

/* The bundle's root whose subject is the name, its PEM block as in the file, as Sony's CAs are
 * given: its size added to *required, and when writing, the block into buffer. 0, 0x80740035 for a
 * buffer too small, 0x80740037 without such a root */
static int bundle_root(const void *handle, uint32_t hash, char *buffer, size_t size, size_t *required, int writing)
{
	const VsName *name = handle;
	if (!vs_initialized() || name == NULL || name->magic != VS_NAME_MAGIC || name->raw.p == NULL)
		return VS_ERROR_UNKNOWN_LOAD_CERT;
	int result = VS_ERROR_UNKNOWN_LOAD_CERT;
	vs_lock();
	unsigned char *block = NULL;
	int fd = -1;
	unsigned open_part = 0;
	if (!bundle_ready())
		goto done;
	for (size_t i = 0; i < g_root_count; ++i) {
		const BundleRoot *root = &g_roots[i];
		if (root->hash != hash)
			continue;
		if (block == NULL && (block = VS_CALLOC(1, VS_BUNDLE_BLOCK + 1)) == NULL)
			break;
		/* The root's file: Mozilla's, or the user's */
		if (fd < 0 || open_part != root->part) {
			if (fd >= 0)
				vs_platform_file_close(fd);
			open_part = root->part;
			fd = vs_platform_file_open(vs_platform_store_path(root->part));
			if (fd < 0)
				continue;
		}
		if (!read_root(root, fd, block, &name->raw))
			continue;
		if (required != NULL)
			*required += root->length;
		result = 0;
		if (writing && root->length > size)
			result = VS_ERROR_BUFFER_TOO_SMALL;
		else if (writing)
			memcpy(buffer, block, root->length);
		break;
	}
done:
	if (fd >= 0)
		vs_platform_file_close(fd);
	VS_FREE(block);
	vs_unlock();
	VITALS_VERBOSE("ca store: bundle root %08X, 0x%08X", (unsigned)hash, (unsigned)result);
	return result;
}

#if VITALS_DEBUG >= 1
const char *vs_ca_store_source(const unsigned char *der, size_t length, char text[24])
{
	uint32_t hash = vs_name_hash_raw(der, length);
	for (size_t i = 0; i < VS_SONY_CAS; ++i) {
		if (k_sony_cas[i].hash != hash)
			continue;
		if (k_sony_cas[i].number == 0)
			return "Sony's CA_LIST.cer";
		memcpy(text, "Sony's CA00", sizeof("Sony's CA00"));
		text[9] = (char)('0' + k_sony_cas[i].number / 10);
		text[10] = (char)('0' + k_sony_cas[i].number % 10);
		return text;
	}
	VsName name = {VS_NAME_MAGIC, NULL, {0, length, (unsigned char *)der}};
	size_t required = 0;
	return bundle_root(&name, hash, NULL, 0, &required, 0) == 0 ? "Mozilla's or custom" : NULL;
}
#endif

void vs_ca_store_end(void)
{
	forget_bundle();
	g_bundle_state = 0;
}

/* NID 0x68D3409E (0x2028): the PEM of the CA whose subject is the name, into buffer (size bytes,
 * zeroed first), and its size into *required, which is enough without a buffer. Sony's CAs first,
 * the first entry with the name's hash: one with a flag must have a bit of the mask, and a mask
 * with only CA01 to CA05's bits gets only those. A name Sony's table doesn't have is looked for in
 * Mozilla's bundle (once cellSslInit has run), whatever the mask. 0; 0x80740004 with neither buffer
 * nor required; 0x80740035 for a buffer too small; 0x80740037 for a CA that isn't there or isn't
 * allowed */
int cellSsl_68D3409E(const void *name, char *buffer, size_t size, size_t *required, uint64_t mask)
{
	if (buffer == NULL && required == NULL)
		return VITALS_SSL_ERROR_NO_BUFFER;
	int writing = buffer != NULL;
	if (writing)
		memset(buffer, 0, size);
	if (required != NULL)
		*required = 0;
	uint32_t hash = hash_of(name);
	const SonyCa *ca = NULL;
	for (size_t i = 0; i < VS_SONY_CAS && ca == NULL; ++i)
		if (k_sony_cas[i].hash == hash)
			ca = &k_sony_cas[i];
	if (ca == NULL)
		return bundle_root(name, hash, buffer, size, required, writing);
	if (ca->flag != 0 && (mask & mask_of(ca)) == 0)
		return VS_ERROR_UNKNOWN_LOAD_CERT;
	if ((mask & VS_LOW_MASK) == mask && (mask_of(ca) & VS_LOW_MASK) == 0)
		return VS_ERROR_UNKNOWN_LOAD_CERT;
	uint32_t total = 0;
	int result = read_sony_ca(ca, buffer, size, &total, writing);
	if (required != NULL)
		*required = total;
	return result;
}
