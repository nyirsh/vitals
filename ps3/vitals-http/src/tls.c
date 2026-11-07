/* https: cellHttpsInit's CA list, each client's SSL context, a connection's handshake through libssl
 * (vitals' with vitals installed), and the certificate check Sony's libhttp makes in its verify
 * callback (0x25088), as the probe sees it (tests/http-probe/sony-4.93.txt):
 * - the flags are CELL_HTTPS_VERIFY_ERROR_*: 0x8 a chain not reaching a trusted CA, 0x80 one of the
 *   Comodo certificates of 2011, 0x400 a host name the certificate isn't for (DNS names in its
 *   subjectAltName, or its CN; not IP addresses), 0x800 expired, 0x1000 not yet valid;
 * - the game's SSL callback gets them for every handshake, flags or not, and 0 from it accepts the
 *   server, anything else refuses it; without one, any flag refuses it;
 * - a refused server's request fails with 0x80710a06, and so does any handshake that fails: a server
 *   offering only TLS 1.0 or 1.1, RC4, 3DES or a 512-bit DH (the vitals app's test in RPCS3, Sony's
 *   libhttp over vitals' libssl); vitals' libssl logs why */

#include "vh.h"

#include "ssl_imports.h"

#include <cell/http.h>
#include <stdio.h>
#include <string.h>

#define VERIFY_UNKNOWN_CA 0x00000008u
#define VERIFY_NO_MEMORY 0x00000020u
#define VERIFY_INVALID_CERT 0x00000080u
#define VERIFY_COMMON_NAME 0x00000400u
#define VERIFY_EXPIRED 0x00000800u
#define VERIFY_NOT_YET_VALID 0x00001000u

#define MAX_CAS 256
#define MAX_DEPTH 10

static int g_https;
static void *g_cas[MAX_CAS];
static unsigned g_ca_count;
static uint64_t g_mask;

int vh_tls_initialized(void)
{
	return g_https;
}

/* Every PEM certificate in a block, as Sony's libhttp reads a game's list (0x25dcc): one after
 * another until the block runs out; the first that can't be read fails it with 0x80710a01 */
static int read_block(const unsigned char *start, size_t size)
{
	const unsigned char *at = start, *end = start + size;
	int read = 0;
	while (at < end && g_ca_count < MAX_CAS) {
		int used = 0;
		void *cert = cellSsl_9447404F(at, end, &used);
		if (cert == NULL)
			break;
		uint64_t mask = 0;
		int flag = 0;
		(void)cellSsl_205B060C(SSLCERT_get_subject_name(cert), &mask, &flag);
		g_mask |= mask;
		g_cas[g_ca_count++] = cert;
		++read;
		if (used <= 0)
			break;
		at += used;
	}
	ERR_clear_error();
	return read > 0 ? 0 : VH_ERROR_BAD_CA;
}

/* 0x80710002 before cellHttpInit, 0x80710001 a second time. Sony's returns 0 for no list too, and
 * then waits forever on a lock it never made at the next https request (the probe); this one takes
 * that as a list with no CAs */
int cellHttpsInit(size_t count, const CellHttpsData *list)
{
	VH_LOG("cellHttpsInit %u blocks%s", (unsigned)count, g_https ? ": already" : "");
	if (!vh_initialized())
		return VH_ERROR_NOT_INITIALIZED;
	if (g_https)
		return VH_ERROR_ALREADY_INITIALIZED;
	g_ca_count = 0;
	g_mask = 0;
	for (size_t i = 0; list != NULL && i < count; ++i) {
		if (list[i].ptr == NULL || list[i].size == 0)
			continue;
		int rc = read_block((const unsigned char *)list[i].ptr, list[i].size);
		if (rc != 0) {
			VH_LOG("cellHttpsInit: block %u of %u bytes has no certificate it can read", (unsigned)i,
			       (unsigned)list[i].size);
			while (g_ca_count > 0)
				SSLCERT_free(g_cas[--g_ca_count]);
			return rc;
		}
	}
	(void)cellSsl_CC6A0CB5(&g_mask);
	VH_LOG("cellHttpsInit: %u CAs", g_ca_count);
	g_https = 1;
	return 0;
}

int cellHttpsEnd(void)
{
	VH_LOG("cellHttpsEnd%s", g_https ? "" : ": not initialized");
	if (!g_https)
		return VH_ERROR_NOT_INITIALIZED;
	while (g_ca_count > 0)
		SSLCERT_free(g_cas[--g_ca_count]);
	g_https = 0;
	return 0;
}

/* ---- the certificate check ---- */

static int lower(int c)
{
	return c >= 'A' && c <= 'Z' ? c + 32 : c;
}

/* host against a certificate's name: the same, ignoring case, or "*." for one label */
static int name_matches(const char *host, const unsigned char *name, int length)
{
	if (length >= 2 && name[0] == '*' && name[1] == '.') {
		const char *dot = strchr(host, '.');
		if (dot == NULL)
			return 0;
		host = dot;
		name += 1;
		length -= 1;
	}
	if ((int)strlen(host) != length)
		return 0;
	for (int i = 0; i < length; ++i)
		if (lower((unsigned char)host[i]) != lower(name[i]))
			return 0;
	return 1;
}

/* A DER length at data (size bytes): the length, *used its bytes; -1 when it isn't one */
static long der_length(const unsigned char *data, int size, int *used)
{
	if (size < 1)
		return -1;
	if (data[0] < 0x80) {
		*used = 1;
		return data[0];
	}
	int bytes = data[0] & 0x7f;
	if (bytes == 0 || bytes > 3 || bytes >= size)
		return -1;
	long value = 0;
	for (int i = 1; i <= bytes; ++i)
		value = value << 8 | data[i];
	*used = 1 + bytes;
	return value;
}

/* The subjectAltName's DNS names (tag [2]), then the CN */
static int host_matches(void *cert, const char *host)
{
	int critical = 0, length = 0;
	const unsigned char *value = NULL;
	if (SSLCERT_get_extension(cert, "\x55\x1d\x11", &critical, &value, &length) == 1 && value != NULL && length > 2 &&
	    value[0] == 0x30) {
		int used = 0;
		long total = der_length(value + 1, length - 1, &used);
		const unsigned char *at = value + 1 + used, *end = total >= 0 ? at + total : at;
		if (end > value + length)
			end = value + length;
		while (at + 2 <= end) {
			unsigned char tag = at[0];
			long item = der_length(at + 1, (int)(end - at - 1), &used);
			if (item < 0 || at + 1 + used + item > end)
				break;
			if (tag == 0x82 && name_matches(host, at + 1 + used, (int)item))
				return 1;
			at += 1 + used + item;
		}
	}
	void *subject = SSLCERT_get_subject_name(cert);
	int count = SSLCERT_NAME_get_entry_count(subject);
	for (int i = 0; i < count; ++i) {
		int tag = 0, oid_length = 0, type = 0, text_length = 0;
		const unsigned char *oid = NULL, *text = NULL;
		if (SSLCERT_NAME_ENTRY_get_info(SSLCERT_NAME_get_entry(subject, i), &tag, &oid, &oid_length, &type, &text,
		                                &text_length) != 1)
			continue;
		if (oid_length == 3 && oid[0] == 0x55 && oid[1] == 0x04 && oid[2] == 0x03 && name_matches(host, text, text_length))
			return 1;
	}
	return 0;
}

/* The flags for a certificate's dates against now */
static uint32_t dates(void *cert, void *now)
{
	uint32_t flags = 0;
	int type = 0, length = 0;
	const unsigned char *data = NULL;
	void *when = R_time_new();
	if (when == NULL)
		return VERIFY_NO_MEMORY;
	if (SSLCERT_get_notAfter(cert, &type, &data, &length) == 1 && R_time_import(data, length, type, when) == 0 &&
	    R_time_cmp(now, when) > 0)
		flags |= VERIFY_EXPIRED;
	if (SSLCERT_get_notBefore(cert, &type, &data, &length) == 1 && R_time_import(data, length, type, when) == 0 &&
	    R_time_cmp(now, when) < 0)
		flags |= VERIFY_NOT_YET_VALID;
	R_time_free(when);
	return flags;
}

/* The certificate whose subject is name and whose key signed cert, among list */
static void *signer(void *cert, void *const *list, unsigned count)
{
	void *issuer = SSLCERT_get_issuer_name(cert);
	for (unsigned i = 0; i < count; ++i)
		if (list[i] != NULL && SSLCERT_NAME_cmp(SSLCERT_get_subject_name(list[i]), issuer) == 0 &&
		    SSLCERT_verify(cert, SSLCERT_get_pubkey(list[i])) == 1)
			return list[i];
	return NULL;
}

/* One of Sony's own CAs for the issuer, as libhttp asks libssl for it (68D3409E with its mask) */
static int sony_ca_signed(void *cert)
{
	void *issuer = SSLCERT_get_issuer_name(cert);
	size_t size = 0;
	if (cellSsl_68D3409E(issuer, NULL, 0, &size, g_mask) != 0 || size == 0)
		return 0;
	char *pem = vh_alloc(size + 1);
	if (pem == NULL)
		return 0;
	int trusted = 0;
	if (cellSsl_68D3409E(issuer, pem, size + 1, &size, g_mask) == 0) {
		int used = 0;
		void *ca = cellSsl_9447404F((const unsigned char *)pem, (const unsigned char *)pem + size, &used);
		if (ca != NULL) {
			trusted = SSLCERT_verify(cert, SSLCERT_get_pubkey(ca)) == 1;
			SSLCERT_free(ca);
		}
		ERR_clear_error();
	}
	vh_free(pem);
	return trusted;
}

/* Up the chain as the server sent it, to a CA of the game's list or one of Sony's */
static int chain_trusted(void *certificates[], int count)
{
	void *cert = certificates[0];
	for (int depth = 0; cert != NULL && depth < MAX_DEPTH; ++depth) {
		if (signer(cert, g_cas, g_ca_count) != NULL || sony_ca_signed(cert))
			return 1;
		void *next = signer(cert, certificates, (unsigned)count);
		if (next == NULL || next == cert)
			return 0;
		cert = next;
	}
	return 0;
}

static int check(void *ssl, void *certificates[], int count, void *argument, int *reason)
{
	(void)argument;
	VhTransaction *t = BIO_get_cb_arg(SSL_get_rbio(ssl));
	uint32_t flags = 0;
	void *now = R_time_new();
	if (now == NULL || R_time(now) == NULL)
		flags |= VERIFY_NO_MEMORY;
	for (int i = 0; i < count && now != NULL; ++i) {
		flags |= dates(certificates[i], now);
		if (cellSsl_2E8CC56D(certificates[i]))
			flags |= VERIFY_INVALID_CERT;
	}
	if (now != NULL)
		R_time_free(now);
	if (count < 1 || !chain_trusted(certificates, count))
		flags |= VERIFY_UNKNOWN_CA;
	if (t != NULL && count > 0 && !host_matches(certificates[0], t->host))
		flags |= VERIFY_COMMON_NAME;
	if (reason != NULL)
		*reason = flags & VERIFY_NO_MEMORY ? 17 : flags & VERIFY_NOT_YET_VALID ? 9 : flags & VERIFY_EXPIRED ? 10 : 0;
	int accept = flags == 0;
	VhClient *client = t != NULL ? t->client : NULL;
	VH_LOG("transaction %p: %s's chain of %d, flags 0x%08x", (void *)t, t != NULL ? t->host : "-", count,
	       (unsigned)flags);
	if (client != NULL && client->callbacks[VH_CALLBACK_SSL] != NULL) {
		CellHttpsSslCallback callback = (CellHttpsSslCallback)client->callbacks[VH_CALLBACK_SSL];
		int answer = callback(flags, (CellSslCert const *)certificates, count, t->host, (CellHttpSslId)ssl,
		                      client->callback_arguments[VH_CALLBACK_SSL]);
		accept = answer == 0;
		VH_LOG("transaction %p: the game's SSL callback says %d", (void *)t, answer);
	}
	return accept;
}

/* ---- connections ---- */

static void *client_context(VhClient *client)
{
	if (client->ssl_context == NULL) {
		void *context = SSL_CTX_new(TLSv1_client_method());
		if (context == NULL)
			return NULL;
		SSL_CTX_set_verify_mode(context, 1);
		SSL_CTX_set_app_verify_cb(context, check, NULL);
		client->ssl_context = context;
	}
	return client->ssl_context;
}

void vh_tls_client_free(VhClient *client)
{
	if (client->ssl_context != NULL)
		SSL_CTX_free(client->ssl_context);
	client->ssl_context = NULL;
}

/* What libhttp's getters give, kept from the handshake: the connection may go back to the client */
static void snapshot(VhTransaction *t)
{
	const void *cipher = SSL_get_current_cipher(t->ssl);
	const char *name = cipher != NULL ? SSL_CIPHER_get_name(cipher) : NULL;
	const char *version = cipher != NULL ? SSL_CIPHER_get_version(cipher) : NULL;
	snprintf(t->cipher_name, sizeof(t->cipher_name), "%s", name != NULL ? name : "");
	snprintf(t->cipher_version, sizeof(t->cipher_version), "%s", version != NULL ? version : "");
	t->cipher_description[0] = '\0';
	if (cipher != NULL)
		(void)SSL_CIPHER_description(cipher, t->cipher_description, (int)sizeof(t->cipher_description));
	t->bits_algorithm = 0;
	t->bits_effective = cipher != NULL ? SSL_CIPHER_get_bits(cipher, &t->bits_algorithm) : 0;
	t->cipher_id = -1;
	if (cipher != NULL)
		(void)_cellSslConvertCipherId(SSL_CIPHER_get_id(cipher), &t->cipher_id);
	t->ssl_version = -1;
	(void)_cellSslConvertSslVersion(SSL_version(t->ssl), &t->ssl_version);
	t->ssl_id = t->ssl;
	t->has_ssl = 1;
}

/* The handshake on t's connected socket: 0, or 0x80710a06 however it failed, as Sony's */
int vh_tls_open(VhTransaction *t)
{
	void *context = client_context(t->client);
	void *ssl = context != NULL ? SSL_new(context) : NULL;
	void *bio = ssl != NULL ? BIO_new_socket(t->fd, 0) : NULL;
	if (bio == NULL) {
		if (ssl != NULL)
			SSL_free(ssl);
		return VH_ERROR_NO_MEMORY;
	}
	(void)BIO_ctrl(bio, 100, 0, t->host);
	int port = (int)t->port;
	(void)BIO_ctrl(bio, 100, 3, &port);
	BIO_set_cb_arg(bio, t);
	SSL_set_bio(ssl, bio, bio);
	SSL_set_connect_state(ssl);
	int rc = SSL_do_handshake(ssl);
	if (rc != 1) {
		VH_LOG("transaction %p: handshake with %s failed (SSL_get_error %d)", (void *)t, t->host, SSL_get_error(ssl, rc));
		SSL_free(ssl);
		return VH_ERROR_SSL_REFUSED;
	}
	t->ssl = ssl;
	snapshot(t);
	VH_LOG("transaction %p: TLS with %s, %s", (void *)t, t->host, t->cipher_name);
	return 0;
}

/* Without a close_notify: the socket goes on, the game's (cellHttpTransactionReleaseConnection) */
void vh_tls_close_quietly(void *ssl)
{
	if (ssl != NULL)
		SSL_free(ssl);
}

void vh_tls_close(void *ssl)
{
	if (ssl == NULL)
		return;
	(void)SSL_shutdown(ssl);
	SSL_free(ssl);
}

/* After a kept connection is taken again: its getters' answers */
void vh_tls_resume(VhTransaction *t)
{
	if (t->ssl != NULL)
		snapshot(t);
}

int vh_tls_send(void *ssl, const void *data, size_t size)
{
	int sent = SSL_write(ssl, data, size > 0x7fffffff ? 0x7fffffff : (int)size);
	if (sent <= 0)
		VH_LOG("ssl %p: SSL_write %d, SSL_get_error %d", ssl, sent, SSL_get_error(ssl, sent));
	return sent > 0 ? sent : VH_NET_ERROR(VH_NET_TLS_SEND, SSL_get_error(ssl, sent));
}

int vh_tls_recv(void *ssl, void *data, size_t size)
{
	int got = SSL_read(ssl, data, size > 0x7fffffff ? 0x7fffffff : (int)size);
	if (got > 0)
		return got;
	int kind = SSL_get_error(ssl, got);
	VH_LOG("ssl %p: SSL_read %d, SSL_get_error %d", ssl, got, kind);
	/* The server's close_notify, or the connection simply ending: the end of a body read until close */
	if (kind == 6 || (got == 0 && kind == 5))
		return 0;
	return VH_NET_ERROR(VH_NET_TLS_RECV, kind);
}

/* ---- the getters ---- */

#define WITH_SSL(id, t)                                  \
	VH_LOG2("%s %p", __func__, (void *)(id));        \
	if (!vh_initialized())                           \
		return VH_ERROR_NOT_INITIALIZED;         \
	VhTransaction *t = vh_transaction((void *)(id)); \
	if (t == NULL)                                   \
		return VH_ERROR_BAD_TRANS;               \
	if (!t->has_ssl)                                 \
		return VH_ERROR_NO_CONNECTION

static int give_text(const char *text, char *out, size_t size, size_t *required)
{
	size_t need = strlen(text) + 1;
	if (required != NULL)
		*required = need;
	if (out == NULL)
		return required != NULL ? 0 : VH_ERROR_NO_BUFFER;
	if (size < need)
		return VH_ERROR_INSUFFICIENT;
	memcpy(out, text, need);
	return 0;
}

int cellHttpTransactionGetSslCipherName(CellHttpTransId id, char *name, size_t size, size_t *required)
{
	WITH_SSL(id, t);
	return give_text(t->cipher_name, name, size, required);
}

int cellHttpTransactionGetSslCipherVersion(CellHttpTransId id, char *version, size_t size, size_t *required)
{
	WITH_SSL(id, t);
	return give_text(t->cipher_version, version, size, required);
}

int cellHttpTransactionGetSslCipherId(CellHttpTransId id, int32_t *cipher)
{
	WITH_SSL(id, t);
	if (cipher == NULL)
		return VH_ERROR_NO_BUFFER;
	*cipher = t->cipher_id;
	return 0;
}

int cellHttpTransactionGetSslCipherBits(CellHttpTransId id, int32_t *effective, int32_t *algorithm)
{
	WITH_SSL(id, t);
	if (effective == NULL || algorithm == NULL)
		return VH_ERROR_NO_BUFFER;
	*effective = t->bits_effective;
	*algorithm = t->bits_algorithm;
	return 0;
}

int cellHttpTransactionGetSslCipherString(CellHttpTransId id, char *buffer, size_t size)
{
	WITH_SSL(id, t);
	if (buffer == NULL || size == 0)
		return VH_ERROR_NO_BUFFER;
	snprintf(buffer, size, "%s", t->cipher_description);
	return 0;
}

int cellHttpTransactionGetSslVersion(CellHttpTransId id, int32_t *version)
{
	WITH_SSL(id, t);
	if (version == NULL)
		return VH_ERROR_NO_BUFFER;
	*version = t->ssl_version;
	return 0;
}

int cellHttpTransactionGetSslId(CellHttpTransId id, CellHttpSslId *ssl)
{
	WITH_SSL(id, t);
	if (ssl == NULL)
		return VH_ERROR_NO_BUFFER;
	*ssl = (CellHttpSslId)t->ssl_id;
	return 0;
}

/* ---- the root CA list (cellHttpsInit's) ---- */

typedef int (*RootCaCallback)(void *certificate, void *argument);

/* With libhttp and libssl initialized (0x80710002, 0x80710a08 without) */
static int root_ca_check(void)
{
	if (!vh_initialized())
		return VH_ERROR_NOT_INITIALIZED;
	if (!_cellSslIsInitd())
		return (int)0x80710a08;
	return 0;
}

int cellHttpsGetRootCaEntryCount(uint32_t *count)
{
	int rc = root_ca_check();
	if (rc != 0)
		return rc;
	if (count == NULL)
		return VH_ERROR_NO_BUFFER;
	*count = g_ca_count;
	return 0;
}

/* The list's index-th CA to callback(certificate, argument); as Sony's, an index one past the
 * last calls it with NULL, and past that 0x80710027 */
int cellHttp_F799F3EF(uint32_t index, RootCaCallback callback, void *argument)
{
	int rc = root_ca_check();
	if (rc != 0)
		return rc;
	if (index > g_ca_count)
		return VH_ERROR_INVALID_VALUE;
	if (callback != NULL)
		(void)callback(index < g_ca_count ? g_cas[index] : NULL, argument);
	return 0;
}
