/* SSL-C's connection API as Sony's libhttp calls it, which is OpenSSL 0.9.8's: client methods,
 * SSL_CTX, SSL and a socket BIO, with TLS 1.2 and 1.3 from Mbed TLS. Ported from the Vita's
 * vitals-ssl/src/connection.c; the PS3's differences, from Sony's code (dumps/ps3/4.93-cex/libssl.prx) and
 * libhttp's calls (dumps/ps3/4.93-cex/libhttp.prx: connecting at 0x2491c, reading at 0x24520, closing at
 * 0x2435c):
 * - the socket BIO is Sony's (0xf990): a failed receive or send returns -1 and leaves sys_net's
 *   errno as it was, which libhttp reads for its own error; only EAGAIN asks for a retry
 * - SSL_get_error is OpenSSL's (0x2ddf4): 2 or 3 for a retry, 5 for any other socket failure and
 *   for the server closing the socket, 6 after its close_notify, 1 when the TLS failed
 * - libhttp makes one context (0x24808), SSL_CTX_new(TLSv1_client_method()), and closes with
 *   SSL_shutdown, SSL_clear, SSL_set_session(NULL), SSL_set_bio(NULL, NULL) and SSL_free; it closes
 *   the socket itself, so the BIO never does, as Sony's (which imports no socketclose) */

#include "ca_store.h"
#include "certificate.h"
#include "core.h"
#include "ssl_api.h"
#include "pool.h"
#include "vs.h"

#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/platform.h>
#include <mbedtls/platform_util.h>

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define VS_CALLOC mbedtls_calloc
#define VS_FREE mbedtls_free

/* The option that lets SSL_shutdown run before the handshake is done (OpenSSL 0.9.8's), which
 * libhttp sets */
#define VS_OPTION_SHUTDOWN_IN_HANDSHAKE 0x40000u
/* SSL_peek's buffer: one record's data at most */
#define VS_PEEK_SIZE 16384
/* The debug log's headers (log_headers): gathered up to this much, logged a line of this at most */
#define VS_HEADER_LOG_SIZE 2048
#define VS_HEADER_LINE 160

/* log_transfer's one-byte reads so far, as one line (VITALS_DEBUG 2) */
static void flush_one_byte_reads(VsSsl *ssl)
{
#if VITALS_DEBUG >= 2
	if (ssl->one_byte_reads > 0)
		VITALS_VERBOSE("ssl %p read %d byte%s, one at a time", (void *)ssl, ssl->one_byte_reads,
		        ssl->one_byte_reads == 1 ? "" : "s");
#endif
	ssl->one_byte_reads = 0;
}

/* Sony's three client methods: TLSv1_client_method and SSLv3_client_method share one (0x204fc),
 * the third builds its own (0x2e20c), which libhttp picks for its connections' other version
 * setting. All three are TLS 1.2 to 1.3 here; SSL_version before a handshake tells them apart, as
 * their templates do: 0x0303 for the first, 0x0300 for the third (as on the Vita) */
static const VsMethod g_tls1_method = {VS_METHOD_MAGIC, 0x0303};
static const VsMethod g_ssl3_method = {VS_METHOD_MAGIC, 0x0303};
static const VsMethod g_any_method = {VS_METHOD_MAGIC, 0x0300};
/* A fourth, built the same way from its own template (0x205d4, 0x5721c), version 0x0301 */
static const VsMethod g_tls1_only_method = {VS_METHOD_MAGIC, 0x0301};

static int is_method(const VsMethod *method)
{
	return method != NULL && method->magic == VS_METHOD_MAGIC;
}

static int is_context(const VsContext *context)
{
	return context != NULL && context->magic == VS_CONTEXT_MAGIC;
}

static int is_ssl(const VsSsl *ssl)
{
	return ssl != NULL && ssl->magic == VS_SSL_MAGIC;
}

static int is_bio(const VsBio *bio)
{
	return bio != NULL && bio->magic == VS_BIO_MAGIC;
}

const void *TLSv1_client_method(void)
{
	return &g_tls1_method;
}

const void *SSLv3_client_method(void)
{
	return &g_ssl3_method;
}

/* NID 0xC5F77319, Sony 0x2e20c: the third client method (OpenSSL's SSLv23_client_method, by what
 * it does) */
const void *cellSsl_C5F77319(void)
{
	return &g_any_method;
}

/* NID 0xF422A5AB, Sony 0x205d4: a fourth client method, TLS 1.0's by its template; nothing seen
 * calls it */
const void *cellSsl_F422A5AB(void)
{
	return &g_tls1_only_method;
}

/* ---- contexts ---- */

/* SSL_CTX_new; NULL without a method (reason 196) or memory (33, as before cellSslInit, when there's
 * no pool), as Sony's (0x2df7c) */
void *SSL_CTX_new(const void *method)
{
	if (!is_method(method)) {
		vs_error_push(VS_ERR_PACK(VS_ERR_LIB_SSL, 168, 196));
		return NULL;
	}
	VsContext *context = vs_initialized() ? VS_CALLOC(1, sizeof(*context)) : NULL;
	if (context == NULL) {
		vs_error_push(VS_ERR_PACK(VS_ERR_LIB_SSL, 168, 33));
		return NULL;
	}
	context->magic = VS_CONTEXT_MAGIC;
	context->method = method;
	context->references = 1;
	/* SSL_SESS_CACHE_SERVER, and OpenSSL's default size */
	context->cache_mode = 2;
	context->cache_size = 20480;
	context->value_55 = context->value_56 = 1;
	VITALS_LOG("SSL_CTX_new %p", (void *)context);
	return context;
}

static void context_release(VsContext *context)
{
	vs_lock();
	unsigned int left = --context->references;
	vs_unlock();
	if (left == 0) {
		if (context->own_certificate != NULL) {
			mbedtls_x509_crt_free(context->own_certificate);
			VS_FREE(context->own_certificate);
		}
		if (context->own_key != NULL) {
			mbedtls_pk_free(context->own_key);
			VS_FREE(context->own_key);
		}
		context->magic = 0;
		VS_FREE(context);
	}
}

/* SSL_CTX_free; the connections made from it keep it until they are freed */
void SSL_CTX_free(void *handle)
{
	if (is_context(handle)) {
		VITALS_LOG("SSL_CTX_free %p", handle);
		context_release(handle);
	}
}

/* SSL_CTX_set_options, which only adds bits; kept, as this TLS has none of SSL-C's options */
long SSL_CTX_set_options(void *handle, long options)
{
	VsContext *context = handle;
	if (!is_context(context))
		return 0;
	context->options |= (uint32_t)options;
	return (long)context->options;
}

/* SSL_CTX_ctrl, as Sony's (0x1f72c): the session cache's mode (44, 45) and size (42, 43) are kept,
 * though there is no session cache, so its statistics (20 to 31) are 0; 55 reads a value of SSL-C's
 * and 56 sets it; the rest are the method's, which has nothing to set here */
long SSL_CTX_ctrl(void *handle, int command, long value, void *pointer)
{
	VsContext *context = handle;
	(void)pointer;
	if (!is_context(context))
		return 0;
	long old;
	switch (command) {
	case 42:
		old = context->cache_size;
		context->cache_size = value;
		return old;
	case 43:
		return context->cache_size;
	case VS_CTRL_SET_SESS_CACHE_MODE:
		old = context->cache_mode;
		context->cache_mode = value;
		return old;
	case VS_CTRL_GET_SESS_CACHE_MODE:
		return context->cache_mode;
	case 55:
		return context->value_55;
	case 56:
		old = context->value_56;
		context->value_56 = value;
		return old;
	default:
		VITALS_VERBOSE("ctx ctrl %d ignored", command);
		return 0;
	}
}

/* SSL_CTX_set_verify_mode: bit 1 checks the server (libhttp gives 5) */
void SSL_CTX_set_verify_mode(void *handle, int mode)
{
	VsContext *context = handle;
	if (is_context(context))
		context->verify_mode = mode;
}

/* SSL_CTX_set_app_verify_cb: libhttp's certificate check and its argument */
void SSL_CTX_set_app_verify_cb(void *handle, VsVerifyCallback callback, void *argument)
{
	VsContext *context = handle;
	if (is_context(context)) {
		context->verify_callback = callback;
		context->verify_argument = argument;
	}
}

/* SSL_CTX_use_certificate (libhttp's client certificate, 0x26394): a copy of it, sent with the key
 * SSL_CTX_use_PrivateKey gives to a server that asks; 1, or 0 */
int SSL_CTX_use_certificate(void *handle, void *cert)
{
	VsContext *context = handle;
	const mbedtls_x509_crt *crt = vs_cert_crt(cert);
	if (!is_context(context) || crt == NULL)
		return 0;
	mbedtls_x509_crt *copy = VS_CALLOC(1, sizeof(*copy));
	if (copy == NULL)
		return 0;
	mbedtls_x509_crt_init(copy);
	if (mbedtls_x509_crt_parse_der(copy, crt->raw.p, crt->raw.len) != 0) {
		mbedtls_x509_crt_free(copy);
		VS_FREE(copy);
		return 0;
	}
	if (context->own_certificate != NULL) {
		mbedtls_x509_crt_free(context->own_certificate);
		VS_FREE(context->own_certificate);
	}
	context->own_certificate = copy;
	return 1;
}

/* SSL_CTX_use_PrivateKey: a copy of the key, as the Vita's; 1, or 0 */
int SSL_CTX_use_PrivateKey(void *handle, void *key_handle)
{
	VsContext *context = handle;
	mbedtls_pk_context *key = vs_key_pk(key_handle);
	if (!is_context(context) || key == NULL)
		return 0;
	unsigned char *der = VS_CALLOC(1, 4096);
	mbedtls_pk_context *copy = VS_CALLOC(1, sizeof(*copy));
	int ok = der != NULL && copy != NULL;
	if (ok) {
		mbedtls_pk_init(copy);
		/* Written from the end of the buffer */
		int length = mbedtls_pk_write_key_der(key, der, 4096);
		ok = length > 0 && mbedtls_pk_parse_key(copy, der + 4096 - length, (size_t)length, NULL, 0) == 0;
		mbedtls_platform_zeroize(der, 4096);
	}
	VS_FREE(der);
	if (!ok) {
		if (copy != NULL)
			mbedtls_pk_free(copy);
		VS_FREE(copy);
		return 0;
	}
	if (context->own_key != NULL) {
		mbedtls_pk_free(context->own_key);
		VS_FREE(context->own_key);
	}
	context->own_key = copy;
	return 1;
}

/* SSL_CTX_set_info_cb: the info callback the context's connections start with */
void SSL_CTX_set_info_cb(void *handle, VsInfoCallback callback)
{
	VsContext *context = handle;
	if (is_context(context))
		context->info_callback = callback;
}

/* ---- socket BIOs ---- */

/* BIO_new_socket. The close flag is kept for BIO_ctrl, and never acted on: Sony's BIO doesn't close
 * its socket (libhttp does) */
void *BIO_new_socket(int fd, int close_flag)
{
	VsBio *bio = VS_CALLOC(1, sizeof(*bio));
	if (bio == NULL)
		return NULL;
	bio->magic = VS_BIO_MAGIC;
	bio->fd = fd;
	bio->close_on_free = close_flag & 1;
	return bio;
}

static void bio_free(VsBio *bio)
{
	if (!is_bio(bio))
		return;
	if (bio->data != NULL) {
		mbedtls_platform_zeroize(bio->data, bio->capacity);
		VS_FREE(bio->data);
	}
	VS_FREE(bio->host);
	VS_FREE(bio->port_text);
	bio->magic = 0;
	VS_FREE(bio);
}

/* A copy of text from the pool, replacing *kept; 0, or -1 without memory */
static int keep_text(char **kept, const char *text)
{
	size_t length = strlen(text);
	char *copy = VS_CALLOC(1, length + 1);
	if (copy == NULL)
		return -1;
	memcpy(copy, text, length);
	VS_FREE(*kept);
	*kept = copy;
	return 0;
}

/* ---- memory BIOs ---- */

/* BIO_new_mem (0xfb64): an empty memory BIO, OpenSSL's, which libhttp writes a client key into;
 * NULL without memory */
void *BIO_new_mem(void)
{
	VsBio *bio = VS_CALLOC(1, sizeof(*bio));
	if (bio == NULL)
		return NULL;
	bio->magic = VS_BIO_MAGIC;
	bio->memory = 1;
	bio->fd = -1;
	return bio;
}

/* Appends to a memory BIO, kept NUL-terminated; what was written, or -1 without memory */
static int memory_write(VsBio *bio, const void *data, size_t length)
{
	size_t wanted = bio->length + length + 1;
	if (wanted > bio->capacity) {
		size_t capacity = bio->capacity > 0 ? bio->capacity : 256;
		while (capacity < wanted)
			capacity *= 2;
		unsigned char *grown = VS_CALLOC(1, capacity);
		if (grown == NULL)
			return -1;
		if (bio->data != NULL) {
			memcpy(grown, bio->data, bio->length);
			mbedtls_platform_zeroize(bio->data, bio->capacity);
			VS_FREE(bio->data);
		}
		bio->data = grown;
		bio->capacity = capacity;
	}
	memcpy(bio->data + bio->length, data, length);
	bio->length += length;
	bio->data[bio->length] = '\0';
	return (int)length;
}

int vs_bio_write(void *handle, const void *data, size_t length)
{
	VsBio *bio = handle;
	if (!is_bio(bio))
		return -2;
	if (length > INT32_MAX)
		return -1;
	if (bio->memory)
		return memory_write(bio, data, length);
	size_t done = 0;
	while (done < length) {
		int sent = vs_platform_send(bio->fd, (const unsigned char *)data + done, length - done);
		if (sent <= 0)
			return done > 0 ? (int)done : -1;
		done += (size_t)sent;
	}
	return (int)length;
}

/* A memory BIO's BIO_ctrl, OpenSSL's: 1 empties it (libhttp's reset), 2 is 1 when it's empty, 3
 * and 10 give how much it holds (3 its data too) */
static long memory_ctrl(VsBio *bio, int command, long value, void *pointer)
{
	switch (command) {
	case 1:
		if (bio->data != NULL)
			mbedtls_platform_zeroize(bio->data, bio->capacity);
		bio->length = 0;
		return 1;
	case 2:
		return bio->length == 0;
	case 3:
		if (pointer != NULL)
			*(unsigned char **)pointer = bio->data;
		return (long)bio->length;
	case 10:
		return (long)bio->length;
	case VS_BIO_CTRL_GET_CLOSE:
		return bio->close_on_free;
	case VS_BIO_CTRL_SET_CLOSE:
		bio->close_on_free = (int)(value & 1);
		return 1;
	case 11:
	case 12:
		return 1;
	default:
		return 0;
	}
}

/* _cellSslPemReadPrivateKey (0x19f0): the private key a memory BIO holds, as libhttp loads a client
 * certificate's; freed with EVP_PKEY_free, NULL when it isn't one */
void *_cellSslPemReadPrivateKey(void *handle)
{
	VsBio *bio = handle;
	if (!is_bio(bio) || !bio->memory)
		return NULL;
	return vs_key_parse(bio->data, bio->length);
}

/* BIO_free: 1, or 0 without a BIO */
int BIO_free(void *handle)
{
	if (!is_bio(handle))
		return 0;
	bio_free(handle);
	return 1;
}

/* BIO_ctrl, as Sony's socket BIO's (0xc104); -2 for a BIO that has none, as OpenSSL's. 100 is
 * OpenSSL's connect BIO's BIO_C_SET_CONNECT, which Sony's socket BIO takes: value 0 copies a host
 * name (libhttp's), 1 a port as text, 2 an address's 4 bytes (as text too, for the host: Sony's
 * prints them as signed numbers, these as the address they are), 3 a port number; 123 reads them
 * back */
long BIO_ctrl(void *handle, int command, long value, void *pointer)
{
	VsBio *bio = handle;
	if (bio == NULL)
		return 0;
	if (!is_bio(bio))
		return -2;
	if (bio->memory)
		return memory_ctrl(bio, command, value, pointer);
	switch (command) {
	case VS_BIO_CTRL_SET_HOST:
		if (pointer == NULL)
			return 1;
		if (value == 0)
			return keep_text(&bio->host, pointer) == 0 ? 1 : 0;
		if (value == 1)
			return keep_text(&bio->port_text, pointer) == 0 ? 1 : 0;
		if (value == 2) {
			const unsigned char *address = pointer;
			char text[16];
			snprintf(text, sizeof(text), "%u.%u.%u.%u", address[0], address[1], address[2], address[3]);
			memcpy(bio->address, address, 4);
			return keep_text(&bio->host, text) == 0 ? 1 : 0;
		}
		if (value == 3)
			bio->port = *(const int *)pointer;
		return 1;
	case VS_BIO_CTRL_GET_HOST:
		if (pointer == NULL)
			return -1;
		if (value == 0)
			*(const char **)pointer = bio->host;
		else if (value == 1)
			*(const char **)pointer = bio->port_text;
		else if (value == 2)
			*(const unsigned char **)pointer = bio->address;
		else if (value == 3)
			*(int *)pointer = bio->port;
		return 1;
	case VS_BIO_C_SET_FD:
		if (pointer == NULL)
			return -1;
		bio->fd = *(const int *)pointer;
		bio->close_on_free = (int)(value & 1);
		return 1;
	case VS_BIO_C_GET_FD:
		if (pointer != NULL)
			*(int *)pointer = bio->fd;
		return bio->fd;
	case VS_BIO_CTRL_GET_CLOSE:
		return bio->close_on_free;
	case VS_BIO_CTRL_SET_CLOSE:
		bio->close_on_free = (int)(value & 1);
		return 1;
	/* BIO_CTRL_FLUSH, BIO_CTRL_DUP and SSL-C's 128 */
	case 11:
	case 12:
	case 128:
		return 1;
	default:
		VITALS_VERBOSE("bio ctrl %d %ld ignored", command, value);
		return 0;
	}
}

/* BIO_set_cb_arg and BIO_get_cb_arg: libhttp's connection, which its certificate check finds the
 * connection's settings from */
void BIO_set_cb_arg(void *handle, void *argument)
{
	VsBio *bio = handle;
	if (is_bio(bio))
		bio->callback_argument = argument;
}

void *BIO_get_cb_arg(void *handle)
{
	VsBio *bio = handle;
	return is_bio(bio) ? bio->callback_argument : NULL;
}

/* _cellSslPemReadX509 (0x1a2c): the certificate a memory BIO holds, as PEM; freed with SSLCERT_free,
 * NULL when it isn't one */
void *_cellSslPemReadX509(void *handle)
{
	VsBio *bio = handle;
	if (!is_bio(bio) || !bio->memory || bio->length == 0)
		return NULL;
	return vs_cert_parse(bio->data, bio->length);
}

/* BIO_dump: OpenSSL 0.9.8's hex dump of data, 16 bytes a line ("0000 - 30 82 ...-...   0..."), written
 * to the BIO; what was written */
int BIO_dump(void *bio, const char *data, int length)
{
	int written = 0;
	for (int at = 0; data != NULL && at < length; at += 16) {
		char line[96];
		int used = snprintf(line, sizeof(line), "%04x - ", (unsigned)at);
		for (int i = 0; i < 16; ++i) {
			if (at + i < length)
				used += snprintf(line + used, sizeof(line) - (size_t)used, "%02x%c",
				                 (unsigned char)data[at + i], i == 7 ? '-' : ' ');
			else
				used += snprintf(line + used, sizeof(line) - (size_t)used, "   ");
		}
		used += snprintf(line + used, sizeof(line) - (size_t)used, "  ");
		for (int i = 0; i < 16 && at + i < length; ++i) {
			unsigned char c = (unsigned char)data[at + i];
			line[used++] = c >= ' ' && c <= '~' ? (char)c : '.';
		}
		line[used++] = '\n';
		line[used] = '\0';
		int result = BIO_printf(bio, "%s", line);
		if (result <= 0)
			return written > 0 ? written : result;
		written += result;
	}
	return written;
}

/* BIO_ptr_ctrl (0xc704): BIO_ctrl with a pointer for it to fill, libhttp's host name (123); the
 * pointer when BIO_ctrl gives more than 0, else NULL */
void *BIO_ptr_ctrl(void *bio, int command, long value)
{
	void *pointer = NULL;
	return BIO_ctrl(bio, command, value, &pointer) > 0 ? pointer : NULL;
}

/* BIO_printf: up to 1 KiB of text, written to the BIO (libhttp writes a client key into a memory BIO
 * a byte at a time, "%c", NULs too); what was written, 0 without a BIO, -1 when it failed */
int BIO_printf(void *handle, const char *format, ...)
{
	VsBio *bio = handle;
	if (!is_bio(bio) || format == NULL)
		return 0;
	char text[1024];
	va_list arguments;
	va_start(arguments, format);
	int length = vsnprintf(text, sizeof(text), format, arguments);
	va_end(arguments);
	if (length < 0)
		return -1;
	if ((size_t)length >= sizeof(text))
		length = (int)sizeof(text) - 1;
	if (bio->memory)
		return memory_write(bio, text, (size_t)length);
	int written = 0;
	while (written < length) {
		int sent = vs_platform_send(bio->fd, text + written, (size_t)(length - written));
		if (sent <= 0)
			return written > 0 ? written : -1;
		written += sent;
	}
	return written;
}

/* BIO_get_retry_reason: why a connect or accept is to be retried, which a socket BIO's reads and
 * writes never set (Sony's reads the field, 0x2f9c): 0 */
int BIO_get_retry_reason(void *handle)
{
	(void)handle;
	return 0;
}

/* ---- connections ---- */

/* SSL_new; NULL without a context (reason 195) or memory (33), as Sony's (0x2d988) */
void *SSL_new(void *handle)
{
	VsContext *context = handle;
	if (!is_context(context)) {
		vs_error_push(VS_ERR_PACK(VS_ERR_LIB_SSL, 186, 195));
		return NULL;
	}
	VsSsl *ssl = VS_CALLOC(1, sizeof(*ssl));
	if (ssl == NULL) {
		vs_error_push(VS_ERR_PACK(VS_ERR_LIB_SSL, 186, 33));
		return NULL;
	}
	ssl->magic = VS_SSL_MAGIC;
	vs_lock();
	++context->references;
	vs_unlock();
	ssl->context = context;
	ssl->method = context->method;
	ssl->info_callback = context->info_callback;
	mbedtls_ssl_init(&ssl->tls);
	mbedtls_ssl_config_init(&ssl->config);
	VITALS_LOG("SSL_new %p from %p", (void *)ssl, (void *)context);
	return ssl;
}

/* The connection's TLS state gone (SSL_clear and SSL_free); its BIOs and settings stay */
static void reset(VsSsl *ssl)
{
	mbedtls_ssl_free(&ssl->tls);
	mbedtls_ssl_config_free(&ssl->config);
	mbedtls_ssl_init(&ssl->tls);
	mbedtls_ssl_config_init(&ssl->config);
	if (ssl->peeked != NULL) {
		mbedtls_platform_zeroize(ssl->peeked, VS_PEEK_SIZE);
		VS_FREE(ssl->peeked);
	}
	ssl->peeked = NULL;
	ssl->peeked_size = ssl->peeked_at = 0;
	ssl->connecting = ssl->ready = ssl->handshake_done = 0;
	flush_one_byte_reads(ssl);
	ssl->close_notify = ssl->close_sent = ssl->close_logged = 0;
	ssl->failure = VS_FAILED_NOTHING;
	ssl->tls_result = 0;
	struct VsHeaderLog *logs[] = {&ssl->sent_headers, &ssl->received_headers};
	for (int i = 0; i < 2; ++i) {
		if (logs[i]->data != NULL) {
			mbedtls_platform_zeroize(logs[i]->data, VS_HEADER_LOG_SIZE);
			VS_FREE(logs[i]->data);
		}
		logs[i]->data = NULL;
		logs[i]->length = logs[i]->done = 0;
	}
}

/* SSL_set_bio's and SSL_free's: a BIO used both ways is freed once */
static void free_bios(VsSsl *ssl)
{
	if (ssl->rbio != NULL && ssl->rbio != ssl->wbio)
		bio_free(ssl->rbio);
	bio_free(ssl->wbio);
	ssl->rbio = ssl->wbio = NULL;
}

/* SSL_free, with its BIOs, as OpenSSL's */
void SSL_free(void *handle)
{
	VsSsl *ssl = handle;
	if (!is_ssl(ssl))
		return;
	VITALS_LOG("SSL_free %p", (void *)ssl);
#if VITALS_DEBUG >= 2
	VitalsPoolUse use;
	if (vitals_pool_use(&use) == 0)
		VITALS_VERBOSE("ssl %p: pool %u bytes free of %u, %u at the lowest, %u refused", (void *)ssl,
		       (unsigned)use.free_now, (unsigned)use.size, (unsigned)use.lowest_free, (unsigned)use.refused);
#endif
	reset(ssl);
	free_bios(ssl);
	context_release(ssl->context);
	mbedtls_platform_zeroize(ssl, sizeof(*ssl));
	VS_FREE(ssl);
}

/* SSL_clear: ready for another connection, with the method SSL_set_ssl_method gave, as Sony's
 * (0x246e4); libhttp calls it before SSL_free. 1 */
int SSL_clear(void *handle)
{
	VsSsl *ssl = handle;
	if (!is_ssl(ssl))
		return 0;
	reset(ssl);
	return 1;
}

/* SSL_set_ssl_method: libhttp's choice of version for a connection. 1 */
int SSL_set_ssl_method(void *handle, const void *method)
{
	VsSsl *ssl = handle;
	if (!is_ssl(ssl) || !is_method(method))
		return 0;
	ssl->method = method;
	return 1;
}

/* SSL_set_session: kept, and unused (there is no session resumption); libhttp gives NULL. 1 */
int SSL_set_session(void *handle, const void *session)
{
	VsSsl *ssl = handle;
	if (!is_ssl(ssl))
		return 0;
	ssl->session = session;
	return 1;
}

/* SSL_SESSION_free: nothing to free, as SSL_set_session keeps no session of its own */
void SSL_SESSION_free(void *session)
{
	(void)session;
}

/* SSL_set_bio; the BIOs it replaces are freed (libhttp's SSL_set_bio(NULL, NULL) frees its
 * socket BIO this way) */
void SSL_set_bio(void *handle, void *read_bio, void *write_bio)
{
	VsSsl *ssl = handle;
	if (!is_ssl(ssl))
		return;
	if (ssl->rbio != read_bio || ssl->wbio != write_bio) {
		if (ssl->rbio != read_bio && ssl->rbio != write_bio && ssl->rbio != ssl->wbio)
			bio_free(ssl->rbio);
		if (ssl->wbio != read_bio && ssl->wbio != write_bio)
			bio_free(ssl->wbio);
	}
	ssl->rbio = read_bio;
	ssl->wbio = write_bio;
}

void *SSL_get_rbio(const void *handle)
{
	const VsSsl *ssl = handle;
	return is_ssl(ssl) ? ssl->rbio : NULL;
}

/* SSL_set_connect_state */
void SSL_set_connect_state(void *handle)
{
	VsSsl *ssl = handle;
	if (is_ssl(ssl))
		ssl->connecting = 1;
}

/* Sony's socket BIO (0xf990 receives, its sender alike): what moved, else -1 with sys_net's errno
 * left for the caller; EAGAIN is a retry */
static int tls_send(void *context, const unsigned char *data, size_t size)
{
	VsSsl *ssl = context;
	if (!is_bio(ssl->wbio))
		return MBEDTLS_ERR_NET_INVALID_CONTEXT;
	int result = vs_platform_send(ssl->wbio->fd, data, size);
	if (result > 0)
		return result;
	ssl->socket_errno = vs_platform_net_errno();
	if (result < 0 && ssl->socket_errno == VS_NET_EAGAIN) {
		ssl->failure = VS_FAILED_WANT_WRITE;
		return MBEDTLS_ERR_SSL_WANT_WRITE;
	}
	ssl->failure = VS_FAILED_SOCKET;
	return MBEDTLS_ERR_NET_SEND_FAILED;
}

static int tls_recv(void *context, unsigned char *data, size_t size)
{
	VsSsl *ssl = context;
	if (!is_bio(ssl->rbio))
		return MBEDTLS_ERR_NET_INVALID_CONTEXT;
	int result = vs_platform_recv(ssl->rbio->fd, data, size);
	if (result >= 0)
		return result;
	ssl->socket_errno = vs_platform_net_errno();
	if (ssl->socket_errno == VS_NET_EAGAIN) {
		ssl->failure = VS_FAILED_WANT_READ;
		return MBEDTLS_ERR_SSL_WANT_READ;
	}
	ssl->failure = VS_FAILED_SOCKET;
	return MBEDTLS_ERR_NET_RECV_FAILED;
}

/* A context that checks the server without a check of its own (libhttp always gives its own) has
 * nothing to check it against until the CA store is written: no connection, unless the build says
 * to skip it (VITALS_SSL_UNVERIFIED, for trying the rest) */
static int verify_unavailable(void *context, mbedtls_x509_crt *certificate, int depth, uint32_t *flags)
{
	(void)context, (void)certificate;
#if defined(VITALS_SSL_UNVERIFIED) && VITALS_SSL_UNVERIFIED
	(void)depth;
	*flags = 0;
#else
	if (depth == 0)
		*flags |= MBEDTLS_X509_BADCERT_OTHER;
#endif
	return 0;
}

/* An IPv4 address: four decimal numbers up to 255 with dots between, nothing else */
static int is_ipv4(const char *host)
{
	for (int part = 0; part < 4; ++part) {
		unsigned value = 0;
		int digits = 0;
		while (*host >= '0' && *host <= '9' && digits < 4) {
			value = value * 10 + (unsigned)(*host++ - '0');
			++digits;
		}
		if (digits == 0 || digits > 3 || value > 255)
			return 0;
		if (part < 3 && *host++ != '.')
			return 0;
	}
	return *host == '\0';
}

static int no_issuers(void *context, const mbedtls_x509_crt *child, mbedtls_x509_crt **candidates)
{
	(void)context, (void)child;
	*candidates = NULL;
	return 0;
}

#define VS_MAX_CHAIN 16

#if VITALS_DEBUG >= 1
/* libhttp's reasons (OpenSSL 0.9.8's X509_V_ERR numbers): it sets only these, and leaves 0 for the
 * rest (the chain, the host name, a revoked Comodo serial) */
static const char *verify_reason(int reason)
{
	switch (reason) {
	case 0:
		return "none given";
	case 9:
		return "not yet valid";
	case 10:
		return "expired";
	case 17:
		return "out of memory";
	default:
		return "unknown";
	}
}

/* Where the chain's top issuer is, for the log: its name, and Sony's CA or Mozilla's bundle */
static void log_anchor(const VsSsl *ssl, const mbedtls_x509_crt *top, int accepted)
{
	char issuer[128], text[24];
	if (mbedtls_x509_dn_gets(issuer, sizeof(issuer), &top->issuer) < 0)
		memcpy(issuer, "?", 2);
	const char *source = vs_ca_store_source(top->issuer_raw.p, top->issuer_raw.len, text);
	VITALS_VERBOSE("ssl %p %s: issued by %s, %s%s", (const void *)ssl, accepted ? "trusted" : "not trusted", issuer,
	       source != NULL ? "from " : "which neither Sony's CAs nor Mozilla's bundle has",
	       source != NULL ? source : "");
}

/* Why libhttp refused the chain, as far as Mbed TLS can tell without the CAs: its own check of the
 * dates, the host name and the algorithms (the trust is log_anchor's) */
static void log_refusal(VsSsl *ssl, mbedtls_x509_crt *chain)
{
	static const struct {
		uint32_t flag;
		const char *name;
	} names[] = {{MBEDTLS_X509_BADCERT_EXPIRED, "expired"},
	             {MBEDTLS_X509_BADCERT_FUTURE, "not yet valid"},
	             {MBEDTLS_X509_BADCERT_CN_MISMATCH, "not for this host name"},
	             {MBEDTLS_X509_BADCERT_REVOKED, "revoked"},
	             {MBEDTLS_X509_BADCERT_KEY_USAGE, "key usage"},
	             {MBEDTLS_X509_BADCERT_EXT_KEY_USAGE, "extended key usage"},
	             {MBEDTLS_X509_BADCERT_BAD_MD, "hash not allowed"},
	             {MBEDTLS_X509_BADCERT_BAD_PK, "key type not allowed"},
	             {MBEDTLS_X509_BADCERT_BAD_KEY, "key too small"},
	             {MBEDTLS_X509_BADCERT_SKIP_VERIFY, "skipped"},
	             {MBEDTLS_X509_BADCERT_OTHER, "other"}};
	const char *host = is_bio(ssl->rbio) && ssl->rbio->host[0] != '\0' ? ssl->rbio->host : NULL;
	uint32_t flags = 0;
	(void)mbedtls_x509_crt_verify_with_profile(chain, NULL, NULL, &ssl->profile, host, &flags, NULL, NULL);
	flags &= ~(uint32_t)MBEDTLS_X509_BADCERT_NOT_TRUSTED;
	char text[160];
	size_t used = 0;
	text[0] = '\0';
	for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
		if ((flags & names[i].flag) == 0)
			continue;
		int n = snprintf(text + used, sizeof(text) - used, "%s%s", used != 0 ? ", " : "", names[i].name);
		if (n < 0 || (size_t)n >= sizeof(text) - used)
			break;
		used += (size_t)n;
	}
	VITALS_LOG("ssl %p refused: libhttp's reason %d (%s); Mbed TLS finds %s (host %s)", (void *)ssl,
	       ssl->verify_result, verify_reason(ssl->verify_result), used != 0 ? text : "nothing else wrong",
	       host != NULL ? host : "-");
}
#endif

/* With libhttp's check: Mbed TLS's own findings are dropped, and once it has the server's chain
 * (depth 0 comes last) the check decides, as Sony's calls it, with the certificates as the server
 * sent them, its own first (as the Vita's) */
static int verify_with_callback(void *context, mbedtls_x509_crt *certificate, int depth, uint32_t *flags)
{
	VsSsl *ssl = context;
	*flags = 0;
	if (depth > 0)
		return 0;
	VsCert *certs = VS_CALLOC(VS_MAX_CHAIN, sizeof(*certs));
	void *handles[VS_MAX_CHAIN];
	if (certs == NULL)
		return MBEDTLS_ERR_X509_ALLOC_FAILED;
	int count = 0;
	mbedtls_x509_crt *top = certificate;
	for (mbedtls_x509_crt *crt = certificate; crt != NULL && crt->raw.p != NULL && count < VS_MAX_CHAIN; crt = crt->next) {
		vs_cert_borrow(&certs[count], crt);
		handles[count] = &certs[count];
		top = crt;
		++count;
	}
	ssl->verify_result = 0;
	VITALS_VERBOSE("ssl %p verify callback with a chain of %d", (void *)ssl, count);
	int accepted = ssl->context->verify_callback(ssl, handles, count, ssl->context->verify_argument,
	                                             &ssl->verify_result);
	for (int i = 0; i < count; ++i)
		vs_cert_return(&certs[i]);
	VS_FREE(certs);
	VITALS_VERBOSE("ssl %p verify callback %d reason=%d chain=%d", (void *)ssl, accepted, ssl->verify_result, count);
#if VITALS_DEBUG >= 1
	if (count > 0)
		log_anchor(ssl, top, accepted);
	if (!accepted)
		log_refusal(ssl, certificate);
#else
	(void)top;
#endif
	if (!accepted)
		*flags = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
	return 0;
}

/* PSN's sign-in goes through a CDN that refuses a handshake that doesn't look like the console's
 * (a 403 from Akamai to the XMB's POST /nav/auth): its hosts get the XMB's own
 * ClientHello, as captured from a console signing in, byte for byte but for the random bytes, as
 * the Vita's vitals-ssl gives Sony's sign-in (vitalsSslCtxSetProfile): TLS 1.2, no session ID, the
 * console's suites in its order (3DES and RC4 only offered, offer-unknown-ciphersuites.patch; the
 * servers pick AES-SHA256), Mbed TLS's renegotiation SCSV after them, and only server_name and
 * signature_algorithms */
#define CONSOLE_HOSTS ".np.ac.playstation.net"

static const int k_console_suites[] = {
	MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA256,
	MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256,
	MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA,
	MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA,
	0x000A, /* TLS_RSA_WITH_3DES_EDE_CBC_SHA */
	0x0005, /* TLS_RSA_WITH_RC4_128_SHA */
	0x0004, /* TLS_RSA_WITH_RC4_128_MD5 */
	0,
};

/* RSA PKCS#1 with SHA-256, SHA-512, SHA-384, SHA-1, in the console's order */
static const uint16_t k_console_signatures[] = {
	MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA256,
	MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA512,
	MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA384,
	MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA1,
	MBEDTLS_TLS1_3_SIG_NONE,
};

/* 1 when host ends with CONSOLE_HOSTS, without case */
static int is_console_host(const char *host)
{
	size_t length = strlen(host), suffix = sizeof(CONSOLE_HOSTS) - 1;
	if (length <= suffix)
		return 0;
	for (size_t i = 0; i < suffix; ++i) {
		char c = host[length - suffix + i];
		if (c >= 'A' && c <= 'Z')
			c = (char)(c - 'A' + 'a');
		if (c != CONSOLE_HOSTS[i])
			return 0;
	}
	return 1;
}

static void console_profile(mbedtls_ssl_config *config)
{
	mbedtls_ssl_conf_max_tls_version(config, MBEDTLS_SSL_VERSION_TLS1_2);
	mbedtls_ssl_conf_ciphersuites(config, k_console_suites);
	mbedtls_ssl_conf_offer_unknown_ciphersuites(config, 1);
	mbedtls_ssl_conf_sig_algs(config, k_console_signatures);
	mbedtls_ssl_conf_extended_master_secret(config, MBEDTLS_SSL_EXTENDED_MS_DISABLED);
	mbedtls_ssl_conf_encrypt_then_mac(config, MBEDTLS_SSL_ETM_DISABLED);
	mbedtls_ssl_conf_session_tickets(config, MBEDTLS_SSL_SESSION_TICKETS_DISABLED);
}

/* Mbed TLS for one connection, on its first handshake: TLS 1.2 to 1.3, the host name the read BIO
 * carries as SNI; an IPv4 address isn't sent, as Sony's. PSN sign-in's hosts get the console's own
 * ClientHello instead (console_profile) */
static int setup(VsSsl *ssl)
{
	if (ssl->ready)
		return 0;
	int result = mbedtls_ssl_config_defaults(&ssl->config, MBEDTLS_SSL_IS_CLIENT,
	                                         MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	if (result != 0)
		return result;
	/* As vitals-http: SHA-1 signatures stay allowed for Sony's own servers */
	ssl->profile = mbedtls_x509_crt_profile_default;
	ssl->profile.allowed_mds |= MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA1);
	mbedtls_ssl_conf_cert_profile(&ssl->config, &ssl->profile);
	mbedtls_ssl_conf_min_tls_version(&ssl->config, MBEDTLS_SSL_VERSION_TLS1_2);
	mbedtls_ssl_conf_max_tls_version(&ssl->config, MBEDTLS_SSL_VERSION_TLS1_3);
	int verify = ssl->context->verify_mode & 1;
	mbedtls_ssl_conf_authmode(&ssl->config, verify ? MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_NONE);
	if (verify) {
		/* No roots for Mbed TLS: the check looks them up itself */
		mbedtls_ssl_conf_ca_cb(&ssl->config, no_issuers, NULL);
		mbedtls_ssl_conf_verify(&ssl->config,
		                        ssl->context->verify_callback != NULL ? verify_with_callback : verify_unavailable, ssl);
	}
	if (ssl->context->own_certificate != NULL && ssl->context->own_key != NULL) {
		result = mbedtls_ssl_conf_own_cert(&ssl->config, ssl->context->own_certificate, ssl->context->own_key);
		if (result != 0)
			return result;
	}
	const char *host = is_bio(ssl->rbio) ? ssl->rbio->host : NULL;
	if (host != NULL && (host[0] == '\0' || strlen(host) >= 256))
		host = NULL;
	ssl->is_address = host != NULL && is_ipv4(host);
	int console = host != NULL && !ssl->is_address && is_console_host(host);
	if (console)
		console_profile(&ssl->config);
	result = mbedtls_ssl_setup(&ssl->tls, &ssl->config);
	if (result != 0)
		return result;
	/* NULL: no SNI */
	result = mbedtls_ssl_set_hostname(&ssl->tls, ssl->is_address ? NULL : host);
	if (result != 0)
		return result;
	mbedtls_ssl_set_bio(&ssl->tls, ssl, tls_send, tls_recv, NULL);
	ssl->ready = 1;
	VITALS_VERBOSE("ssl %p host=%s verify=%d%s", (void *)ssl, host != NULL ? host : "-", verify, console ? " profile=console" : "");
	return 0;
}

#if VITALS_DEBUG >= 1
/* TLS's alert descriptions (RFC 8446 and before), for the log */
static const char *alert_name(int description)
{
	switch (description) {
	case 0: return "close_notify";
	case 10: return "unexpected_message";
	case 20: return "bad_record_mac";
	case 22: return "record_overflow";
	case 40: return "handshake_failure";
	case 42: return "bad_certificate";
	case 43: return "unsupported_certificate";
	case 44: return "certificate_revoked";
	case 45: return "certificate_expired";
	case 46: return "certificate_unknown";
	case 47: return "illegal_parameter";
	case 48: return "unknown_ca";
	case 49: return "access_denied";
	case 50: return "decode_error";
	case 51: return "decrypt_error";
	case 70: return "protocol_version";
	case 71: return "insufficient_security";
	case 80: return "internal_error";
	case 86: return "inappropriate_fallback";
	case 90: return "user_canceled";
	case 109: return "missing_extension";
	case 110: return "unsupported_extension";
	case 112: return "unrecognized_name";
	case 113: return "bad_certificate_status_response";
	case 115: return "unknown_psk_identity";
	case 116: return "certificate_required";
	case 120: return "no_application_protocol";
	default: return "unknown";
	}
}
#endif

/* The caller's return for an Mbed TLS failure, with failure set for SSL_get_error: -1 for a socket
 * failure or a retry (as Sony's BIO returns), 0 when the server closed the connection, -1 when the
 * TLS failed, with an error queued for ERR_peek_error */
static int failed(VsSsl *ssl, int result)
{
	if (result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE) {
		if (ssl->failure == VS_FAILED_NOTHING)
			ssl->failure = result == MBEDTLS_ERR_SSL_WANT_READ ? VS_FAILED_WANT_READ : VS_FAILED_WANT_WRITE;
		return -1;
	}
	if ((result == MBEDTLS_ERR_NET_RECV_FAILED || result == MBEDTLS_ERR_NET_SEND_FAILED) &&
	    ssl->failure == VS_FAILED_SOCKET)
		return -1;
	if (result == MBEDTLS_ERR_SSL_CONN_EOF) {
		if (!ssl->close_logged)
			VITALS_VERBOSE("ssl %p the server closed the connection without a close_notify", (void *)ssl);
		ssl->close_logged = 1;
		ssl->failure = VS_FAILED_EOF;
		return 0;
	}
	if (result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
		if (!ssl->close_logged)
			VITALS_VERBOSE("ssl %p the server closed the connection (close_notify)", (void *)ssl);
		ssl->close_logged = 1;
		ssl->failure = VS_FAILED_CLOSED;
		ssl->close_notify = 1;
		return 0;
	}
	ssl->failure = VS_FAILED_TLS;
	ssl->tls_result = result;
	/* SSL-C's library, Mbed TLS's error as the reason */
	vs_error_push((unsigned long)VS_ERR_LIB_SSL << 24 | ((unsigned long)-result & 0xFFF));
	if (result == MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE)
		VITALS_LOG("ssl %p the server sent a fatal alert: %d, %s", (void *)ssl,
		       (int)ssl->tls.MBEDTLS_PRIVATE(in_msg)[1], alert_name(ssl->tls.MBEDTLS_PRIVATE(in_msg)[1]));
	/* An alert from the server, for the info callback */
	if (result == MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE && ssl->info_callback != NULL)
		ssl->info_callback(ssl, VS_CB_ALERT | VS_CB_READ, (2 << 8) | (int)ssl->tls.MBEDTLS_PRIVATE(in_msg)[1]);
	return -1;
}

static int connect_now(VsSsl *ssl)
{
	ssl->failure = VS_FAILED_NOTHING;
	if (!vs_initialized()) {
		ssl->failure = VS_FAILED_TLS;
		return -1;
	}
	int result = setup(ssl);
	if (result != 0)
		return failed(ssl, result);
	/* On the caller's thread and stack, as Sony's libssl runs its handshake: libhttp's certificate
	 * check and the game's SSL callback then run on the game's thread, under its locks, as they
	 * expect */
	int handshake = mbedtls_ssl_handshake(&ssl->tls);
	VITALS_VERBOSE("ssl %p handshake -0x%04X", (void *)ssl, (unsigned)-handshake);
	if (ssl->failure == VS_FAILED_WANT_READ || ssl->failure == VS_FAILED_WANT_WRITE ||
	    ssl->failure == VS_FAILED_SOCKET)
		vs_platform_set_net_errno(ssl->socket_errno);
	if (handshake != 0) {
		int returned = failed(ssl, handshake);
		if (ssl->failure == VS_FAILED_TLS)
			VITALS_LOG("ssl %p handshake failed -0x%04X flags=%08X", (void *)ssl, (unsigned)-handshake,
			       (unsigned int)mbedtls_ssl_get_verify_result(&ssl->tls));
		return returned;
	}
	ssl->handshake_done = 1;
	VITALS_LOG("ssl %p connected %s %s", (void *)ssl, mbedtls_ssl_get_version(&ssl->tls),
	       mbedtls_ssl_get_ciphersuite(&ssl->tls));
	return 1;
}

/* Without SSL_set_connect_state, SSL-C has no handshake to run: -1, reason 144 (connection type not
 * set), as Sony's SSL_do_handshake (0x2d5f0) */
static int not_connecting(VsSsl *ssl)
{
	ssl->failure = VS_FAILED_TLS;
	vs_error_push(VS_ERR_PACK(VS_ERR_LIB_SSL, 180, 144));
	return -1;
}

/* SSL_do_handshake: 1 once connected; a socket that would block gives -1 and SSL_get_error 2 or 3,
 * and the next call carries on */
int SSL_do_handshake(void *handle)
{
	VsSsl *ssl = handle;
	if (!is_ssl(ssl))
		return -1;
	if (!ssl->connecting)
		return not_connecting(ssl);
	return ssl->handshake_done ? 1 : connect_now(ssl);
}

/* Mbed TLS's reads and writes on a stack it fits in. The XMB calls libssl from threads whose stacks
 * are 4 to 16 KB: one of PSN's, with 3 KB left of 4, never came back from AES-GCM's encryption (it
 * ran off its stack: no error, no crash; the XMB then signed the console out).
 * With less than VS_STACK_NEEDED left, the read or write runs on a thread of its own with
 * VS_HELPER_STACK, the caller waiting, as the Vita's vitals-ssl runs its handshakes; the socket's
 * errno is handed back, as it's per thread. So does SSL_shutdown's close_notify, an alert encrypted
 * as a write is: sent on the caller's 4 KB thread, it crashed the XMB (and so the system) when a
 * game started and PSN's connection was closed. Handshakes stay on the caller's
 * thread, as Sony's: the certificate check calls back into the caller's code, under its locks */
#define VS_STACK_NEEDED 8192u
#define VS_HELPER_STACK (64u * 1024u)

enum { VS_IO_READ, VS_IO_WRITE, VS_IO_CLOSE_NOTIFY };

typedef struct VsIo {
	VsSsl *ssl;
	unsigned char *data;
	size_t size;
	int op, result;
} VsIo;

/* For the log only (release builds log nothing) */
static const char *const k_io_names[] __attribute__((unused)) = {"read", "write", "close_notify"};

static void io_on_this_thread(void *argument)
{
	VsIo *io = argument;
	io->result = io->op == VS_IO_WRITE   ? mbedtls_ssl_write(&io->ssl->tls, io->data, io->size)
	             : io->op == VS_IO_READ  ? mbedtls_ssl_read(&io->ssl->tls, io->data, io->size)
	                                     : mbedtls_ssl_close_notify(&io->ssl->tls);
}

static int tls_io(VsSsl *ssl, unsigned char *data, size_t size, int op)
{
	VsIo io = {ssl, data, size, op, 0};
	uint32_t stack_size = 0, stack_left = 0;
	vs_platform_stack(&stack_size, &stack_left);
	if (stack_left == 0 || stack_left >= VS_STACK_NEEDED) {
		io_on_this_thread(&io);
		return io.result;
	}
	int rc = vs_platform_run_with_stack(io_on_this_thread, &io, VS_HELPER_STACK);
	if (rc != 0) {
		/* What may run off the caller's stack: the one case that hung PSN's writer before */
		VITALS_VERBOSE("ssl %p %s %u: no thread of its own (0x%08X), so on the caller's %u of %u bytes of stack left",
		       (void *)ssl, k_io_names[op], (unsigned)size, (unsigned)rc, (unsigned)stack_left,
		       (unsigned)stack_size);
		io_on_this_thread(&io);
		return io.result;
	}
	VITALS_VERBOSE("ssl %p %s %u ran on a thread of its own: the caller had %u of %u bytes of stack left", (void *)ssl,
	        k_io_names[op], (unsigned)size, (unsigned)stack_left, (unsigned)stack_size);
	if (ssl->failure == VS_FAILED_WANT_READ || ssl->failure == VS_FAILED_WANT_WRITE ||
	    ssl->failure == VS_FAILED_SOCKET)
		vs_platform_set_net_errno(ssl->socket_errno);
	return io.result;
}

/* SSL_read and SSL_peek: what was read, connecting first if it hasn't. Once the server's
 * close_notify has come, a read ends at once with 0, as the Vita's */
static int read_data(VsSsl *ssl, void *buffer, int size, int keep)
{
	if (!is_ssl(ssl) || buffer == NULL || size < 0)
		return -1;
	/* As Sony's (0x1f658): after the server's close_notify, 0 at once */
	if (ssl->close_notify) {
		ssl->failure = VS_FAILED_CLOSED;
		return 0;
	}
	if (!ssl->handshake_done) {
		if (!ssl->connecting)
			return not_connecting(ssl);
		int connected = connect_now(ssl);
		if (connected <= 0)
			return connected;
	}
	if (size == 0)
		return 0;
	if (ssl->peeked_at < ssl->peeked_size) {
		int count = ssl->peeked_size - ssl->peeked_at;
		if (count > size)
			count = size;
		memcpy(buffer, ssl->peeked + ssl->peeked_at, (size_t)count);
		if (!keep)
			ssl->peeked_at += count;
		return count;
	}
	if (ssl->close_notify) {
		ssl->failure = VS_FAILED_CLOSED;
		return 0;
	}
	unsigned char *into = buffer;
	size_t room = (size_t)size;
	if (keep) {
		if (ssl->peeked == NULL && (ssl->peeked = VS_CALLOC(1, VS_PEEK_SIZE)) == NULL) {
			ssl->failure = VS_FAILED_TLS;
			vs_error_push((unsigned long)VS_ERR_LIB_SSL << 24 | 0xFFF);
			return -1;
		}
		into = ssl->peeked;
		room = VS_PEEK_SIZE;
	}
	for (;;) {
		ssl->failure = VS_FAILED_NOTHING;
		int result = tls_io(ssl, into, room, VS_IO_READ);
		if (result > 0) {
			if (!keep)
				return result;
			ssl->peeked_size = result;
			ssl->peeked_at = 0;
			int count = result < size ? result : size;
			memcpy(buffer, into, (size_t)count);
			return count;
		}
		if (result == 0)
			result = MBEDTLS_ERR_SSL_CONN_EOF;
		/* TLS 1.3's session tickets, read on the way to the data, which Mbed TLS 4 reports: first as
		 * a want-read with the transport untouched, then as a ticket */
		if (result == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET ||
		    (result == MBEDTLS_ERR_SSL_WANT_READ && ssl->failure == VS_FAILED_NOTHING))
			continue;
		return failed(ssl, result);
	}
}

/* What a read or write did, for the debug log: sizes and codes, never the data. One-byte reads that
 * work (libhttp reads the headers a byte at a time) are counted, and logged as one line before the
 * next other transfer, the headers or the connection's end */
static void log_transfer(VsSsl *ssl, const char *what, int size, int result)
{
	(void)ssl, (void)what, (void)size, (void)result;
#if VITALS_DEBUG >= 2
	if (is_ssl(ssl)) {
		if (size == 1 && result == 1 && what[0] == 'r') {
			++ssl->one_byte_reads;
			return;
		}
		flush_one_byte_reads(ssl);
	}
#endif
	/* With the socket's own error when it failed: a timeout (EAGAIN) reads as WANT_READ, anything else
	 * as SYSCALL (kind 5), and which it was tells a server's reset from a quiet connection */
	VITALS_VERBOSE("ssl %p %s %d of %d: kind %d, tls -0x%04X, socket errno %d", (const void *)ssl, what, result, size,
	       result > 0 ? 0 : SSL_get_error(ssl, result), (unsigned)-(is_ssl(ssl) ? ssl->tls_result : 0),
	       result > 0 || !is_ssl(ssl) ? 0 : ssl->socket_errno);
}

/* The debug log's HTTP headers, as your rules for vitals' logs have it: header lines as they are,
 * but for the values of Cookie, Set-Cookie, Authorization, Proxy-Authorization and any header whose
 * name has token, session, auth, ticket, key, secret or password in it, and of a request line's query
 * parameters, which are logged as their length; bodies only as their size (log_transfer's) */

#if VITALS_DEBUG >= 2
static int contains(const char *text, int length, const char *word)
{
	int size = (int)strlen(word);
	for (int at = 0; at + size <= length; ++at) {
		int same = 1;
		for (int i = 0; i < size && same; ++i) {
			char c = text[at + i];
			if (c >= 'A' && c <= 'Z')
				c = (char)(c + ('a' - 'A'));
			same = c == word[i];
		}
		if (same)
			return 1;
	}
	return 0;
}

static int secret_header(const char *name, int length)
{
	static const char *const words[] = {"cookie", "authorization", "token", "session", "auth", "ticket",
	                                    "key", "secret", "password", "passphrase"};
	for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); ++i)
		if (contains(name, length, words[i]))
			return 1;
	return 0;
}

/* Appends text, printable characters only, to line */
static void append(char *line, int *used, const char *text, int length)
{
	for (int i = 0; i < length && *used < VS_HEADER_LINE - 1; ++i)
		line[(*used)++] = text[i] >= ' ' && text[i] <= '~' ? text[i] : '?';
	line[*used] = '\0';
}

static void append_length(char *line, int *used, int length)
{
	char text[24];
	int size = snprintf(text, sizeof(text), "<%d bytes>", length);
	append(line, used, text, size);
}

/* A request line, its query's values as their length: "POST /login?user=<5 bytes> HTTP/1.1" */
static void log_request_line(const VsSsl *ssl, const char *direction, const char *text, int length)
{
	char line[VS_HEADER_LINE];
	int used = 0, at = 0;
	line[0] = '\0';
	while (at < length && text[at] != '?')
		++at;
	append(line, &used, text, at);
	if (at < length) {
		int end = at;
		while (end < length && text[end] != ' ')
			++end;
		while (at < end) {
			/* "?" or "&", then a name, then "=" and a value */
			int name = at + 1, equals = name;
			while (equals < end && text[equals] != '=' && text[equals] != '&')
				++equals;
			append(line, &used, text + at, equals - at);
			int value_end = equals;
			while (value_end < end && text[value_end] != '&')
				++value_end;
			if (equals < end && text[equals] == '=') {
				append(line, &used, "=", 1);
				append_length(line, &used, value_end - equals - 1);
			}
			at = value_end;
		}
		append(line, &used, text + end, length - end);
	}
	VITALS_VERBOSE("ssl %p %s %s", (const void *)ssl, direction, line);
}

static void log_header_line(const VsSsl *ssl, const char *direction, const char *text, int length)
{
	char line[VS_HEADER_LINE];
	int used = 0, colon = 0;
	line[0] = '\0';
	while (colon < length && text[colon] != ':')
		++colon;
	if (colon < length && secret_header(text, colon)) {
		append(line, &used, text, colon + 1);
		append(line, &used, " ", 1);
		int value = colon + 1;
		while (value < length && text[value] == ' ')
			++value;
		append_length(line, &used, length - value);
	} else {
		append(line, &used, text, length);
	}
	VITALS_VERBOSE("ssl %p %s %s", (const void *)ssl, direction, line);
}

/* The headers gathered, line by line; the first sent line is the request line */
static void log_headers(VsSsl *ssl, const struct VsHeaderLog *headers, int sent)
{
	flush_one_byte_reads(ssl);
	int at = 0, first = 1;
	while (at < headers->length) {
		int end = at;
		while (end < headers->length && headers->data[end] != '\n')
			++end;
		int length = end - at;
		if (length > 0 && headers->data[at + length - 1] == '\r')
			--length;
		if (length == 0)
			break;
		/* A request line wherever it is ("... HTTP/1.x" at its end), so its query is never logged */
		if ((sent && first) || (length > 9 && memcmp(headers->data + at + length - 9, " HTTP/1.", 8) == 0))
			log_request_line(ssl, sent ? ">" : "<", headers->data + at, length);
		else
			log_header_line(ssl, sent ? ">" : "<", headers->data + at, length);
		first = 0;
		at = end + 1;
	}
}
#endif

/* Gathers what went by until the headers' blank line, then logs them (VITALS_DEBUG 2); bytes after
 * the blank line, a body, aren't kept */
static void note_headers(VsSsl *ssl, struct VsHeaderLog *headers, const unsigned char *data, int length, int sent)
{
#if VITALS_DEBUG >= 2
	if (headers->done || length <= 0)
		return;
	if (headers->data == NULL && (headers->data = VS_CALLOC(1, VS_HEADER_LOG_SIZE)) == NULL)
		return;
	for (int i = 0; i < length && !headers->done; ++i) {
		if (headers->length < VS_HEADER_LOG_SIZE)
			headers->data[headers->length++] = (char)data[i];
		int n = headers->length;
		if ((n >= 4 && memcmp(headers->data + n - 4, "\r\n\r\n", 4) == 0) ||
		    (n >= 2 && memcmp(headers->data + n - 2, "\n\n", 2) == 0) || n == VS_HEADER_LOG_SIZE)
			headers->done = 1;
	}
	if (headers->done) {
		log_headers(ssl, headers, sent);
		mbedtls_platform_zeroize(headers->data, VS_HEADER_LOG_SIZE);
		VS_FREE(headers->data);
		headers->data = NULL;
	}
#else
	(void)ssl, (void)headers, (void)data, (void)length, (void)sent;
#endif
}

int SSL_read(void *handle, void *buffer, int size)
{
	int result = read_data(handle, buffer, size, 0);
	if (result > 0 && is_ssl(handle))
		note_headers(handle, &((VsSsl *)handle)->received_headers, buffer, result, 0);
	log_transfer(handle, "read", size, result);
	return result;
}

/* SSL_peek: as SSL_read, and the next read gives the same data again */
int SSL_peek(void *handle, void *buffer, int size)
{
	int result = read_data(handle, buffer, size, 1);
	log_transfer(handle, "peek", size, result);
	return result;
}

static int write_data(void *handle, const void *buffer, int size);

/* SSL_write: all of the data, or the failure */
int SSL_write(void *handle, const void *buffer, int size)
{
	int result = write_data(handle, buffer, size);
	if (result > 0 && is_ssl(handle))
		note_headers(handle, &((VsSsl *)handle)->sent_headers, buffer, result, 1);
	log_transfer(handle, "write", size, result);
	return result;
}

static int write_data(void *handle, const void *buffer, int size)
{
	VsSsl *ssl = handle;
	if (!is_ssl(ssl) || buffer == NULL || size < 0)
		return -1;
	/* After this side's close_notify, writing fails: reason 207 (protocol is shut down), as Sony's
	 * (0x216e0) */
	if (ssl->close_sent) {
		ssl->failure = VS_FAILED_TLS;
		ssl->tls_result = MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
		vs_error_push(VS_ERR_PACK(VS_ERR_LIB_SSL, 209, 207));
		return -1;
	}
	if (!ssl->handshake_done) {
		if (!ssl->connecting)
			return not_connecting(ssl);
		int connected = connect_now(ssl);
		if (connected <= 0)
			return connected;
	}
	int written = 0;
	while (written < size) {
		ssl->failure = VS_FAILED_NOTHING;
		int result = tls_io(ssl, (unsigned char *)buffer + written, (size_t)(size - written), VS_IO_WRITE);
		/* A TLS 1.3 session ticket read on the way, which Mbed TLS 4 reports */
		if (result == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET)
			continue;
		if (result <= 0)
			return written > 0 ? written : failed(ssl, result == 0 ? MBEDTLS_ERR_SSL_WANT_WRITE : result);
		written += result;
	}
	return written;
}

/* SSL_shutdown; sends close_notify once, and is 1 when the server's has arrived too. As Sony's
 * (0x2d6c0): 1 for no connection, and -1 while the handshake isn't done, unless option 0x40000 is
 * set (libhttp sets it); then, as SSL-C's own shutdown, 1 before any handshake (both sides count as
 * shut down) */
int SSL_shutdown(void *handle)
{
	VsSsl *ssl = handle;
	if (ssl == NULL)
		return 1;
	if (!is_ssl(ssl) || (!ssl->handshake_done && (ssl->options & VS_OPTION_SHUTDOWN_IN_HANDSHAKE) == 0 &&
	                     (ssl->context->options & VS_OPTION_SHUTDOWN_IN_HANDSHAKE) == 0))
		return -1;
	if (!ssl->ready) {
		ssl->close_sent = ssl->close_notify = 1;
		return 1;
	}
	if (!ssl->close_sent) {
		ssl->close_sent = 1;
		if (ssl->handshake_done)
			(void)tls_io(ssl, NULL, 0, VS_IO_CLOSE_NOTIFY);
	}
	flush_one_byte_reads(ssl);
	VITALS_LOG("ssl %p shutdown, the server's close_notify %d", (void *)ssl, ssl->close_notify);
	return ssl->close_notify ? 1 : 0;
}

/* SSL_get_error, as Sony's (OpenSSL 0.9.8's, 0x2ddf4): 0 for a return above 0; 1 when the TLS
 * failed; 2 or 3 when the socket would block; for a 0 return 6 after the server's close_notify;
 * else 5, a system error, whose errno the caller reads */
int SSL_get_error(const void *handle, int returned)
{
	const VsSsl *ssl = handle;
	if (returned > 0)
		return VS_KIND_NONE;
	if (!is_ssl(ssl))
		return VS_KIND_SSL;
	switch (ssl->failure) {
	case VS_FAILED_TLS:
		return VS_KIND_SSL;
	case VS_FAILED_WANT_READ:
		return returned < 0 ? VS_KIND_WANT_READ : VS_KIND_SYSCALL;
	case VS_FAILED_WANT_WRITE:
		return returned < 0 ? VS_KIND_WANT_WRITE : VS_KIND_SYSCALL;
	case VS_FAILED_CLOSED:
		return returned == 0 ? VS_KIND_ZERO_RETURN : VS_KIND_SYSCALL;
	default:
		return VS_KIND_SYSCALL;
	}
}

/* SSL_version: the negotiated version (0x0303, 0x0304), and before a handshake its method's */
int SSL_version(const void *handle)
{
	VsSsl *ssl = (VsSsl *)handle;
	if (!is_ssl(ssl))
		return 0;
	if (ssl->handshake_done)
		return (int)mbedtls_ssl_get_version_number(&ssl->tls);
	return ssl->method->version;
}

/* SSL_get_version: SSL_version's, named as Sony's names them (0x1fbf0), "TLSv12" and so on, and TLS
 * 1.3, which it has no name for, the same way */
const char *SSL_get_version(const void *handle)
{
	switch (SSL_version(handle)) {
	case 0x0304:
		return "TLSv13";
	case 0x0303:
		return "TLSv12";
	case 0x0302:
		return "TLSv11";
	case 0x0301:
		return "TLSv1";
	case 0x0300:
		return "SSLv3";
	default:
		return "unknown";
	}
}

/* SSL_state, as OpenSSL numbers it: 3 (SSL_ST_OK) once connected, before that
 * SSL_ST_BEFORE | SSL_ST_CONNECT */
int SSL_state(const void *handle)
{
	const VsSsl *ssl = handle;
	if (!is_ssl(ssl))
		return 0;
	return ssl->handshake_done ? 0x03 : 0x5000;
}

/* SSL_state_string_long, as Sony's table (0x1fdd8) names those two states: it has no name for
 * SSL_ST_BEFORE | SSL_ST_CONNECT */
const char *SSL_state_string_long(const void *handle)
{
	return SSL_state(handle) == 0x03 ? "SSL negotiation finished successfully" : "unknown state";
}

/* SSL_want: 3 (reading) while the socket would block on a receive, 2 (writing) on a send, 1
 * (nothing) otherwise */
int SSL_want(const void *handle)
{
	const VsSsl *ssl = handle;
	if (!is_ssl(ssl))
		return 1;
	switch (ssl->failure) {
	case VS_FAILED_WANT_READ:
		return 3;
	case VS_FAILED_WANT_WRITE:
		return 2;
	default:
		return 1;
	}
}

/* SSL_alert_type_string_long: an alert's level, as (level << 8) | description gives it */
const char *SSL_alert_type_string_long(int value)
{
	switch (value >> 8) {
	case 1:
		return "warning";
	case 2:
		return "fatal";
	default:
		return "unknown";
	}
}

/* SSL_alert_desc_string_long: the alert descriptions Sony's names, OpenSSL 0.9.8's first twelve;
 * "unknown" for the rest */
const char *SSL_alert_desc_string_long(int value)
{
	switch (value & 0xFF) {
	case 0:
		return "close notify";
	case 10:
		return "unexpected_message";
	case 20:
		return "bad record mac";
	case 30:
		return "decompression failure";
	case 40:
		return "handshake failure";
	case 41:
		return "no certificate";
	case 42:
		return "bad certificate";
	case 43:
		return "unsupported certificate";
	case 44:
		return "certificate revoked";
	case 45:
		return "certificate expired";
	case 46:
		return "certificate unknown";
	case 47:
		return "illegal parameter";
	default:
		return "unknown";
	}
}

/* ---- ciphers ---- */

/* SSL_get_current_cipher, NULL before the handshake; it lasts as long as the connection */
const void *SSL_get_current_cipher(const void *handle)
{
	VsSsl *ssl = (VsSsl *)handle;
	if (!is_ssl(ssl) || !ssl->handshake_done)
		return NULL;
	int suite = mbedtls_ssl_get_ciphersuite_id_from_ssl(&ssl->tls);
	ssl->cipher.id = 0x03000000u | (uint32_t)suite;
	ssl->cipher.tls13 = mbedtls_ssl_get_version_number(&ssl->tls) == MBEDTLS_SSL_VERSION_TLS1_3;
	ssl->cipher.name = mbedtls_ssl_get_ciphersuite(&ssl->tls);
	/* Every suite Mbed TLS offers is AES or ChaCha20: 128 bits, or 256 as its name says */
	ssl->cipher.bits = ssl->cipher.name != NULL && (strstr(ssl->cipher.name, "256") != NULL ||
	                                                strstr(ssl->cipher.name, "CHACHA20") != NULL)
	                       ? 256
	                       : 128;
	return &ssl->cipher;
}

/* SSL_CIPHER_get_name, "(NONE)" without one */
const char *SSL_CIPHER_get_name(const void *handle)
{
	const struct VsCipher *cipher = handle;
	return cipher != NULL && cipher->name != NULL ? cipher->name : "(NONE)";
}

/* SSL_CIPHER_get_bits: the key's bits, also in *algorithm_bits; 0 without a cipher */
int SSL_CIPHER_get_bits(const void *handle, int *algorithm_bits)
{
	const struct VsCipher *cipher = handle;
	int bits = cipher != NULL ? cipher->bits : 0;
	if (algorithm_bits != NULL)
		*algorithm_bits = bits;
	return bits;
}

/* SSL_CIPHER_get_version: OpenSSL 0.9.8's "TLSv1/SSLv3" for every suite it knows, "(NONE)" without
 * one */
const char *SSL_CIPHER_get_version(const void *handle)
{
	return handle != NULL ? "TLSv1/SSLv3" : "(NONE)";
}

/* SSL_CIPHER_get_id, as Sony's (0x1f504): the id without OpenSSL's 0x03 above it, the suite's
 * number, which libhttp gives _cellSslConvertCipherId; 0xFFFFFFFF without one */
unsigned long SSL_CIPHER_get_id(const void *handle)
{
	const struct VsCipher *cipher = handle;
	return cipher != NULL ? cipher->id & 0x00FFFFFFu : 0xFFFFFFFFu;
}

/* Between two parts of a suite's name ("TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"), copied */
static void name_part(const char *name, const char *from, const char *to, char *out, size_t size)
{
	const char *start = from != NULL ? strstr(name, from) : name;
	out[0] = '\0';
	if (start == NULL)
		return;
	start += from != NULL ? strlen(from) : 0;
	const char *end = to != NULL ? strstr(start, to) : NULL;
	size_t length = end != NULL ? (size_t)(end - start) : strlen(start);
	if (length >= size)
		length = size - 1;
	memcpy(out, start, length);
	out[length] = '\0';
}

/* SSL_CIPHER_description, in Sony's format (OpenSSL 0.9.8's, 0x24edc): name, version, key exchange,
 * authentication, encryption and MAC, from the suite's name (TLS 1.3's take any key exchange and
 * authentication, as OpenSSL 1.1 says). Without a buffer, 128 bytes of the pool, as Sony's
 * allocates (no memory: reason 33); NULL for less than 128 bytes (reason 16) */
char *SSL_CIPHER_description(const void *handle, char *buffer, int size)
{
	const struct VsCipher *cipher = handle;
	if (buffer == NULL) {
		size = 128;
		if ((buffer = VS_CALLOC(1, (size_t)size)) == NULL) {
			vs_error_push(VS_ERR_PACK(VS_ERR_LIB_SSL, 216, 33));
			return NULL;
		}
	} else if (size < 128) {
		vs_error_push(VS_ERR_PACK(VS_ERR_LIB_SSL, 216, 16));
		return NULL;
	}
	const char *name = cipher != NULL && cipher->name != NULL ? cipher->name : "";
	char exchange[24] = "any", authentication[24] = "any", encryption[40] = "", mac[24] = "AEAD", part[24];
	if (cipher == NULL || !cipher->tls13) {
		/* "TLS-<exchange>-<authentication>-WITH-<encryption>-<MAC>" ("TLS-RSA-WITH-" names both) */
		name_part(name, "TLS-", "-WITH-", part, sizeof(part));
		char *dash = strchr(part, '-');
		snprintf(exchange, sizeof(exchange), "%.*s", dash != NULL ? (int)(dash - part) : (int)strlen(part), part);
		snprintf(authentication, sizeof(authentication), "%s", dash != NULL ? dash + 1 : part);
		name_part(name, "-WITH-", NULL, part, sizeof(part));
	} else {
		name_part(name, "TLS1-3-", NULL, part, sizeof(part));
	}
	/* <encryption>-<MAC>: AES-128-GCM-SHA256 is AESGCM(128) and AEAD; AES-256-CBC-SHA384 AES(256) */
	int aead = strstr(part, "GCM") != NULL || strstr(part, "CCM") != NULL || strstr(part, "CHACHA20") != NULL;
	const char *last = strrchr(part, '-');
	if (!aead && last != NULL)
		snprintf(mac, sizeof(mac), "%s", last + 1);
	snprintf(encryption, sizeof(encryption), "%s%s(%d)",
	         strstr(part, "CHACHA20") != NULL ? "CHACHA20" : strstr(part, "ARIA") != NULL ? "ARIA" : "AES",
	         strstr(part, "GCM") != NULL ? "GCM" : strstr(part, "CCM") != NULL ? "CCM" : "",
	         cipher != NULL ? cipher->bits : 0);
	snprintf(buffer, (size_t)size, "%-23s %s Kx=%-8s Au=%-4s Enc=%-9s Mac=%-4s%s", SSL_CIPHER_get_name(handle),
	         cipher == NULL ? "unknown" : cipher->tls13 ? "TLSv13" : "SSLv3", exchange, authentication, encryption,
	         mac, "");
	return buffer;
}

/* _cellSslConvertCipherId, as Sony's (0x18e0): SSL-C's suite numbers for CELL_SSL_CIPHER's nine,
 * the suites of 1999, into *out; -1 for any other, which is every suite TLS offers now. 0 */
int _cellSslConvertCipherId(unsigned long id, int *out)
{
	static const struct {
		unsigned long id;
		int cell;
	} known[] = {{10, 0}, {5, 1}, {4, 2}, {9, 3}, {98, 4}, {100, 5}, {8, 6}, {6, 7}, {3, 8}};
	*out = -1;
	for (size_t i = 0; i < sizeof(known) / sizeof(known[0]); ++i)
		if (known[i].id == id)
			*out = known[i].cell;
	return 0;
}

/* _cellSslConvertSslVersion: Sony's (0x18a0) gives CELL_SSL_VERSION_SSL3 (1) for 0x0300 and
 * CELL_SSL_VERSION_TLS1 (0) for 0x0301, -1 for anything else; here TLS 1.1 to 1.3 are TLS1 too, so
 * a game sees TLS rather than an unknown version. 0 */
int _cellSslConvertSslVersion(int version, int *out)
{
	*out = version == 0x0300 ? 1 : version >= 0x0301 && version <= 0x0304 ? 0 : -1;
	return 0;
}
