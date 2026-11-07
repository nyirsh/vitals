/* cellHttpUtil, as Sony's libhttp gives it (the probe's util half, tests/http-probe/source/util.c):
 * none of it needs cellHttpInit. Its errors:
 *   0x80711001 the caller's pool or buffer too small (*required left alone)
 *   0x80711002 nothing to write into or to give the size in, or no source
 *   0x80711003 no input
 *   0x80711004 a Build function's buffer too small (*required given)
 *   0x80711005 a URI, or an escape in one, that can't be read
 *   0x80711006 a header that can't be read, 0x80711007 a request line, 0x80711008 a status line
 *   0x80711009 base64 not in groups of 4, 0x8071100a a character base64 hasn't
 * Functions that fill a structure put its strings in the caller's pool, each with its NUL, in
 * an order each has its own (kept here, as games may look). Sony's quirks are kept where the probe
 * shows them: SweepPath reads its size as a buffer's (the last byte is the NUL's), a status line's
 * parsed length counts from its reason, AppendHeaderValue joins with a space */

#include "vh.h"

#include <cell/http.h>
#include <string.h>

#define UTIL_NO_MEMORY ((int)0x80711001)
#define UTIL_NO_BUFFER ((int)0x80711002)
#define UTIL_NO_INPUT ((int)0x80711003)
#define UTIL_TOO_SMALL ((int)0x80711004)
#define UTIL_BAD_URI ((int)0x80711005)
#define UTIL_BAD_HEADER ((int)0x80711006)
#define UTIL_BAD_REQUEST ((int)0x80711007)
#define UTIL_BAD_STATUS ((int)0x80711008)
#define UTIL_BASE64_LENGTH ((int)0x80711009)
#define UTIL_BASE64_CHARACTER ((int)0x8071100a)

static int is_digit(int c)
{
	return c >= '0' && c <= '9';
}

static int is_alpha(int c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static int is_alnum(int c)
{
	return is_alpha(c) || is_digit(c);
}

static int is_blank(int c)
{
	return c == ' ' || c == '\t';
}

static size_t length_of(const char *text)
{
	return text != NULL ? strlen(text) : 0;
}

/* A string of length bytes into the pool at *at, with its NUL; where it went */
static const char *put(char **at, const char *text, size_t length)
{
	char *where = *at;
	if (length > 0)
		memcpy(where, text, length);
	where[length] = '\0';
	*at += length + 1;
	return where;
}

static const char *put_string(char **at, const char *text)
{
	return put(at, text != NULL ? text : "", length_of(text));
}

/* The common end of the functions that fill a structure: with nothing to fill, the size alone (or
 * 0x80711002 without anywhere to give it); 0x80711001 for a pool too small; else 1 to go on */
static int sizing(int fill, size_t need, size_t size, size_t *required, int *rc)
{
	if (!fill) {
		if (required == NULL) {
			*rc = UTIL_NO_BUFFER;
			return 0;
		}
		*required = need;
		*rc = 0;
		return 0;
	}
	if (size < need) {
		*rc = UTIL_NO_MEMORY;
		return 0;
	}
	if (required != NULL)
		*required = need;
	return 1;
}

/* ---- escaping ---- */

static int unreserved(unsigned char c)
{
	return is_alnum(c) || c == '-' || c == '_' || c == '.' || c == '*';
}

static const char k_hex[] = "0123456789ABCDEF";

/* Each byte whole or not at all, then the NUL: a buffer too small keeps what fitted */
static int escape(char *out, size_t size, const unsigned char *in, size_t length, size_t *required, int form)
{
	if (in == NULL || length == 0)
		return UTIL_NO_INPUT;
	size_t need = 1;
	for (size_t i = 0; i < length; ++i)
		need += unreserved(in[i]) || (form && in[i] == ' ') ? 1 : 3;
	if (out == NULL) {
		if (required == NULL)
			return UTIL_NO_BUFFER;
		*required = need;
		return 0;
	}
	size_t used = 0;
	for (size_t i = 0; i < length; ++i) {
		unsigned char c = in[i];
		if (unreserved(c) || (form && c == ' ')) {
			if (used + 1 > size)
				return UTIL_NO_MEMORY;
			out[used++] = form && c == ' ' ? '+' : (char)c;
		} else {
			if (used + 3 > size)
				return UTIL_NO_MEMORY;
			out[used++] = '%';
			out[used++] = k_hex[c >> 4];
			out[used++] = k_hex[c & 15];
		}
	}
	if (used + 1 > size)
		return UTIL_NO_MEMORY;
	out[used] = '\0';
	if (required != NULL)
		*required = need;
	return 0;
}

static int hex_digit(int c)
{
	if (is_digit(c))
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/* Byte by byte, as Sony's: a bad escape or a buffer too small stops it where it is */
static int unescape(unsigned char *out, size_t size, const char *in, size_t *required, int form)
{
	if (in == NULL)
		return UTIL_NO_INPUT;
	size_t used = 0;
	for (size_t i = 0; in[i] != '\0';) {
		unsigned char byte;
		if (in[i] == '%') {
			int high = in[i + 1] != '\0' ? hex_digit((unsigned char)in[i + 1]) : -1;
			int low = high >= 0 ? hex_digit((unsigned char)in[i + 2]) : -1;
			if (low < 0)
				return UTIL_BAD_URI;
			byte = (unsigned char)(high << 4 | low);
			i += 3;
		} else {
			byte = form && in[i] == '+' ? ' ' : (unsigned char)in[i];
			++i;
		}
		if (out != NULL) {
			if (used + 1 > size)
				return UTIL_NO_MEMORY;
			out[used] = byte;
		}
		++used;
	}
	if (out == NULL) {
		if (required == NULL)
			return UTIL_NO_BUFFER;
		*required = used + 1;
		return 0;
	}
	if (used + 1 > size)
		return UTIL_NO_MEMORY;
	out[used] = '\0';
	if (required != NULL)
		*required = used + 1;
	return 0;
}

int cellHttpUtilEscapeUri(char *out, size_t size, const unsigned char *in, size_t length, size_t *required)
{
	return escape(out, size, in, length, required, 0);
}

int cellHttpUtilFormUrlEncode(char *out, size_t size, const unsigned char *in, size_t length, size_t *required)
{
	return escape(out, size, in, length, required, 1);
}

int cellHttpUtilUnescapeUri(unsigned char *out, size_t size, const char *in, size_t *required)
{
	return unescape(out, size, in, required, 0);
}

int cellHttpUtilFormUrlDecode(unsigned char *out, size_t size, const char *in, size_t *required)
{
	return unescape(out, size, in, required, 1);
}

/* ---- base64 ---- */

static const char k_base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* The text's length, without a NUL */
int cellHttpUtilBase64Encoder(char *out, const void *input, size_t length)
{
	if (out == NULL)
		return UTIL_NO_BUFFER;
	if (input == NULL || length == 0)
		return UTIL_NO_INPUT;
	const unsigned char *in = input;
	size_t used = 0;
	for (size_t i = 0; i < length; i += 3) {
		unsigned value = (unsigned)in[i] << 16;
		if (i + 1 < length)
			value |= (unsigned)in[i + 1] << 8;
		if (i + 2 < length)
			value |= in[i + 2];
		out[used++] = k_base64[value >> 18 & 63];
		out[used++] = k_base64[value >> 12 & 63];
		out[used++] = i + 1 < length ? k_base64[value >> 6 & 63] : '=';
		out[used++] = i + 2 < length ? k_base64[value & 63] : '=';
	}
	return (int)used;
}

static int base64_value(int c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A';
	if (c >= 'a' && c <= 'z')
		return c - 'a' + 26;
	if (is_digit(c))
		return c - '0' + 52;
	if (c == '+')
		return 62;
	if (c == '/')
		return 63;
	return -1;
}

/* Group by group, each checked before it's written; padding only in the last. 3 bytes a group
 * written, padded ones as 0; what was decoded */
int cellHttpUtilBase64Decoder(void *output, const char *in, size_t length)
{
	if (output == NULL)
		return UTIL_NO_BUFFER;
	if (in == NULL)
		return UTIL_NO_INPUT;
	if (length == 0 || length % 4 != 0)
		return UTIL_BASE64_LENGTH;
	unsigned char *out = output;
	int decoded = 0;
	for (size_t i = 0; i < length; i += 4) {
		int last = i + 4 == length;
		int v0 = base64_value((unsigned char)in[i]), v1 = base64_value((unsigned char)in[i + 1]);
		int pad2 = in[i + 2] == '=', pad3 = in[i + 3] == '=';
		int v2 = pad2 ? 0 : base64_value((unsigned char)in[i + 2]);
		int v3 = pad3 ? 0 : base64_value((unsigned char)in[i + 3]);
		if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0 || (pad2 && !pad3) || ((pad2 || pad3) && !last))
			return UTIL_BASE64_CHARACTER;
		unsigned value = (unsigned)v0 << 18 | (unsigned)v1 << 12 | (unsigned)v2 << 6 | (unsigned)v3;
		*out++ = (unsigned char)(value >> 16);
		*out++ = (unsigned char)(value >> 8);
		*out++ = (unsigned char)value;
		decoded += 3 - pad2 - pad3;
	}
	return decoded;
}

/* ---- URIs ---- */

typedef struct Span {
	const char *at;
	size_t length;
} Span;

typedef struct UriParts {
	Span scheme, username, password, host, path;
	uint32_t port;
} UriParts;

static int same_nocase(const char *at, size_t length, const char *word)
{
	if (strlen(word) != length)
		return 0;
	for (size_t i = 0; i < length; ++i) {
		int a = (unsigned char)at[i], b = (unsigned char)word[i];
		if ((a | 32) != (b | 32))
			return 0;
	}
	return 1;
}

static uint32_t default_port(const char *scheme, size_t length)
{
	if (length == 0 || same_nocase(scheme, length, "http"))
		return 80;
	if (same_nocase(scheme, length, "https"))
		return 443;
	if (same_nocase(scheme, length, "ftp"))
		return 21;
	return 0;
}

static int host_character(int c)
{
	return is_alnum(c) || c == '.' || c == '-' || c == '_';
}

/* [scheme ":" ["//"]] [user [":" password] "@"] host [":" port] path, as Sony's reads it: a scheme
 * is a letter then letters, digits, "+", "-" or "." up to a ":"; the user part is what comes
 * before the first "@" ahead of any "/", "?" or "#"; a host is letters, digits, ".", "-" and "_",
 * and whatever follows it is the path, but for a ":" with digits up to a "/" or the end. A proxy
 * (ParseProxy) has no scheme or path, and its port is 8080 by default */
static int parse_parts(const char *text, int proxy, UriParts *parts)
{
	memset(parts, 0, sizeof(*parts));
	if (text[0] == '\0')
		return UTIL_BAD_URI;
	const char *at = text;
	parts->scheme.at = at;
	if (!proxy && is_alpha((unsigned char)at[0])) {
		const char *end = at + 1;
		while (is_alnum((unsigned char)*end) || *end == '+' || *end == '-' || *end == '.')
			++end;
		if (*end == ':') {
			parts->scheme.length = (size_t)(end - at);
			at = end + 1;
			if (at[0] == '/' && at[1] == '/')
				at += 2;
		}
	}
	const char *stop = at;
	while (*stop != '\0' && *stop != '@' && *stop != '/' && *stop != '?' && *stop != '#')
		++stop;
	parts->username.at = parts->password.at = at;
	if (*stop == '@') {
		const char *colon = memchr(at, ':', (size_t)(stop - at));
		parts->username.length = (size_t)((colon != NULL ? colon : stop) - at);
		if (colon != NULL) {
			parts->password.at = colon + 1;
			parts->password.length = (size_t)(stop - colon - 1);
		}
		at = stop + 1;
	}
	parts->host.at = at;
	while (host_character((unsigned char)*at))
		++at;
	parts->host.length = (size_t)(at - parts->host.at);
	parts->port = proxy ? 8080 : default_port(parts->scheme.at, parts->scheme.length);
	if (*at == ':') {
		++at;
		uint64_t port = 0;
		int digits = 0;
		while (is_digit((unsigned char)*at)) {
			port = port * 10 + (uint64_t)(*at++ - '0');
			if (port > 0xffffffffu)
				return UTIL_BAD_URI;
			++digits;
		}
		if (*at != '\0' && *at != '/')
			return UTIL_BAD_URI;
		if (digits > 0)
			parts->port = (uint32_t)port;
	}
	parts->path.at = at;
	parts->path.length = proxy ? 0 : strlen(at);
	return 0;
}

/* ParseUri's order in the pool: scheme, user, password, host, path */
static int parse_uri(CellHttpUri *uri, const char *text, void *pool, size_t size, size_t *required, int proxy)
{
	if (text == NULL)
		return UTIL_NO_INPUT;
	UriParts parts;
	int rc = parse_parts(text, proxy, &parts);
	if (rc != 0)
		return rc;
	size_t need = parts.scheme.length + parts.username.length + parts.password.length + parts.host.length +
	              parts.path.length + 5;
	if (!sizing(uri != NULL && pool != NULL, need, size, required, &rc))
		return rc;
	char *at = pool;
	const char *scheme = put(&at, parts.scheme.at, parts.scheme.length);
	uri->username = put(&at, parts.username.at, parts.username.length);
	uri->password = put(&at, parts.password.at, parts.password.length);
	uri->hostname = put(&at, parts.host.at, parts.host.length);
	const char *path = put(&at, parts.path.at, parts.path.length);
	uri->scheme = proxy ? NULL : scheme;
	uri->path = proxy ? NULL : path;
	uri->port = parts.port;
	return 0;
}

int cellHttpUtilParseUri(CellHttpUri *uri, const char *text, void *pool, size_t size, size_t *required)
{
	return parse_uri(uri, text, pool, size, required, 0);
}

int cellHttpUtilParseProxy(CellHttpUri *proxy, const char *text, void *pool, size_t size, size_t *required)
{
	return parse_uri(proxy, text, pool, size, required, 1);
}

/* path, then "?query" up to a "#", then "#fragment", each with its NUL */
int cellHttpUtilParseUriPath(CellHttpUriPath *out, const char *text, void *pool, size_t size, size_t *required)
{
	if (text == NULL)
		return UTIL_NO_INPUT;
	if (text[0] == '\0')
		return UTIL_BAD_URI;
	size_t total = strlen(text);
	const char *hash = strchr(text, '#');
	size_t before_hash = hash != NULL ? (size_t)(hash - text) : total;
	const char *question = memchr(text, '?', before_hash);
	size_t path = question != NULL ? (size_t)(question - text) : before_hash;
	size_t query = before_hash - path, fragment = total - before_hash;
	int rc;
	if (!sizing(out != NULL && pool != NULL, total + 3, size, required, &rc))
		return rc;
	char *at = pool;
	out->path = put(&at, text, path);
	out->query = put(&at, text + path, query);
	out->fragment = put(&at, text + before_hash, fragment);
	return 0;
}

/* CopyUri's order: scheme, host, path, user, password */
int cellHttpUtilCopyUri(CellHttpUri *dest, const CellHttpUri *src, void *pool, size_t size, size_t *required)
{
	if (src == NULL)
		return UTIL_NO_BUFFER;
	size_t need = length_of(src->scheme) + length_of(src->hostname) + length_of(src->path) +
	              length_of(src->username) + length_of(src->password) + 5;
	int rc;
	if (!sizing(dest != NULL && pool != NULL, need, size, required, &rc))
		return rc;
	char *at = pool;
	CellHttpUri copy;
	copy.scheme = put_string(&at, src->scheme);
	copy.hostname = put_string(&at, src->hostname);
	copy.path = put_string(&at, src->path);
	copy.username = put_string(&at, src->username);
	copy.password = put_string(&at, src->password);
	copy.port = src->port;
	memset(copy.reserved, 0, sizeof(copy.reserved));
	*dest = copy;
	return 0;
}

/* ---- paths ---- */

/* The sweep, into dst (which holds what src has, at most size - 1 bytes and a NUL): in a path from
 * the root, "/./" and "/../" go, ".." taking the segment before; a path that isn't from the root,
 * or what follows a "?" or "#", is copied as it is. As Sony's: a "." or ".." is one only when a "/"
 * follows, which may be src's last byte though that byte isn't copied */
static void sweep(char *dst, const char *src, size_t size)
{
	size_t bound = size - 1, out = 0, i = 0;
	if (src[0] != '/') {
		while (i < bound && src[i] != '\0')
			dst[out++] = src[i++];
		dst[out] = '\0';
		return;
	}
	while (i < bound && src[i] != '\0') {
		char c = src[i];
		if (c == '?' || c == '#') {
			while (i < bound && src[i] != '\0')
				dst[out++] = src[i++];
			break;
		}
		dst[out++] = c;
		++i;
		if (c != '/')
			continue;
		for (;;) {
			if (i < bound && src[i] == '.' && i + 1 < size && src[i + 1] == '/') {
				i += 2;
			} else if (i < bound && src[i] == '.' && i + 1 < size && src[i + 1] == '.' && i + 2 < size &&
			           src[i + 2] == '/') {
				if (out > 1) {
					--out;
					while (out > 0 && dst[out - 1] != '/')
						--out;
				}
				i += 3;
			} else
				break;
		}
	}
	dst[out] = '\0';
}

int cellHttpUtilSweepPath(char *dst, const char *src, size_t size)
{
	if (dst == NULL || src == NULL)
		return UTIL_NO_BUFFER;
	if (size > 0)
		sweep(dst, src, size);
	return 0;
}

/* src's URI with path taken from it: a path from the root as it is, else after src's path up to its
 * last "/" (before any "?" or "#"), then swept. Its order: scheme, host, user, password, path.
 * As Sony's, a src without a path asks a byte more than it takes for a path not from the root */
int cellHttpUtilMergeUriPath(CellHttpUri *uri, const CellHttpUri *src, const char *path, void *pool, size_t size,
                             size_t *required)
{
	if (src == NULL)
		return UTIL_NO_BUFFER;
	if (path == NULL)
		return UTIL_NO_INPUT;
	const char *base = src->path != NULL ? src->path : "";
	size_t directory = 0, extra = 0;
	if (path[0] != '/') {
		size_t end = strcspn(base, "?#");
		for (size_t i = 0; i < end; ++i)
			if (base[i] == '/')
				directory = i + 1;
		extra = base[0] == '\0';
	}
	size_t merged = directory + strlen(path);
	size_t need = length_of(src->scheme) + length_of(src->hostname) + length_of(src->username) +
	              length_of(src->password) + 4 + merged + 1 + extra;
	int rc;
	if (!sizing(uri != NULL && pool != NULL, need, size, required, &rc))
		return rc;
	char *at = pool;
	CellHttpUri result;
	result.scheme = put_string(&at, src->scheme);
	result.hostname = put_string(&at, src->hostname);
	result.username = put_string(&at, src->username);
	result.password = put_string(&at, src->password);
	/* The merged path at its place, then swept onto itself: the sweep only ever shortens it */
	char *joined = at;
	memcpy(joined, base, directory);
	memcpy(joined + directory, path, strlen(path) + 1);
	sweep(joined, joined, merged + 1);
	result.path = joined;
	result.port = src->port;
	memset(result.reserved, 0, sizeof(result.reserved));
	*uri = result;
	return 0;
}

/* scheme "://" [user [":" password] "@"] host [":" port] path, the scheme "http" when there's none
 * and the port left out when it's 0 or the scheme's own (80 for http, 443 for https); flags
 * leave out the scheme, the user and password, the password, the path. With its NUL */
static size_t build_uri(const CellHttpUri *uri, char *out, int32_t flags)
{
	const char *scheme = uri->scheme != NULL ? uri->scheme : "http";
	char port[12];
	size_t port_length = 0;
	uint32_t usual = same_nocase(scheme, strlen(scheme), "http") ? 80 : same_nocase(scheme, strlen(scheme), "https") ? 443 : 0;
	if (uri->port != 0 && uri->port != usual) {
		uint32_t value = uri->port;
		char digits[12];
		size_t count = 0;
		do
			digits[count++] = (char)('0' + value % 10);
		while ((value /= 10) != 0);
		while (count > 0)
			port[port_length++] = digits[--count];
	}
	size_t used = 0;
#define EMIT(text, length)                                    \
	do {                                                  \
		if (out != NULL)                              \
			memcpy(out + used, (text), (length)); \
		used += (length);                             \
	} while (0)
	if (!(flags & CELL_HTTP_UTIL_URI_FLAG_NO_SCHEME)) {
		EMIT(scheme, strlen(scheme));
		EMIT("://", 3);
	}
	if (!(flags & CELL_HTTP_UTIL_URI_FLAG_NO_CREDENTIALS) && length_of(uri->username) > 0) {
		EMIT(uri->username, strlen(uri->username));
		if (!(flags & CELL_HTTP_UTIL_URI_FLAG_NO_PASSWORD) && length_of(uri->password) > 0) {
			EMIT(":", 1);
			EMIT(uri->password, strlen(uri->password));
		}
		EMIT("@", 1);
	}
	EMIT(uri->hostname, strlen(uri->hostname));
	if (port_length > 0) {
		EMIT(":", 1);
		EMIT(port, port_length);
	}
	if (!(flags & CELL_HTTP_UTIL_URI_FLAG_NO_PATH) && uri->path != NULL)
		EMIT(uri->path, strlen(uri->path));
	EMIT("", 1);
#undef EMIT
	return used;
}

int cellHttpUtilBuildUri(const CellHttpUri *uri, char *buffer, size_t length, size_t *required, int32_t flags)
{
	if (uri == NULL || uri->hostname == NULL)
		return UTIL_BAD_URI;
	size_t need = build_uri(uri, NULL, flags);
	if (required != NULL)
		*required = need;
	if (buffer == NULL)
		return 0;
	if (length < need)
		return UTIL_TOO_SMALL;
	build_uri(uri, buffer, flags);
	return 0;
}

/* ---- request and status lines, headers ---- */

static size_t decimal_text(uint32_t value, char *out)
{
	char digits[12];
	size_t count = 0, used = 0;
	do
		digits[count++] = (char)('0' + value % 10);
	while ((value /= 10) != 0);
	while (count > 0)
		out[used++] = digits[--count];
	return used;
}

/* method " " path " " protocol "/" major "." minor CRLF, an empty path as "/"; no NUL */
int cellHttpUtilBuildRequestLine(const CellHttpRequestLine *request, char *buffer, size_t length, size_t *required)
{
	if (request == NULL || request->method == NULL || request->path == NULL || request->protocol == NULL)
		return UTIL_BAD_REQUEST;
	const char *path = request->path[0] != '\0' ? request->path : "/";
	char major[12], minor[12];
	size_t major_length = decimal_text(request->majorVersion, major), minor_length = decimal_text(request->minorVersion, minor);
	size_t method_length = strlen(request->method), path_length = strlen(path), protocol_length = strlen(request->protocol);
	size_t need = method_length + 1 + path_length + 1 + protocol_length + 1 + major_length + 1 + minor_length + 2;
	if (required != NULL)
		*required = need;
	if (buffer == NULL)
		return 0;
	if (length < need)
		return UTIL_TOO_SMALL;
	char *at = buffer;
	memcpy(at, request->method, method_length), at += method_length, *at++ = ' ';
	memcpy(at, path, path_length), at += path_length, *at++ = ' ';
	memcpy(at, request->protocol, protocol_length), at += protocol_length, *at++ = '/';
	memcpy(at, major, major_length), at += major_length, *at++ = '.';
	memcpy(at, minor, minor_length), at += minor_length;
	*at++ = '\r', *at = '\n';
	return 0;
}

/* name ": " value CRLF; no NUL */
int cellHttpUtilBuildHeader(const CellHttpHeader *header, char *buffer, size_t length, size_t *required)
{
	if (header == NULL || header->name == NULL)
		return UTIL_BAD_HEADER;
	size_t name = strlen(header->name), value = length_of(header->value);
	size_t need = name + 2 + value + 2;
	if (required != NULL)
		*required = need;
	if (buffer == NULL)
		return 0;
	if (length < need)
		return UTIL_TOO_SMALL;
	memcpy(buffer, header->name, name);
	memcpy(buffer + name, ": ", 2);
	if (value > 0)
		memcpy(buffer + name + 2, header->value, value);
	memcpy(buffer + name + 2 + value, "\r\n", 2);
	return 0;
}

/* protocol "/" major "." minor " " code, one character, then the reason up to the line's LF (its
 * CR before it left out): from Sony's, the reason's length is counted before blanks at its start
 * are skipped, so "200x OK\r\n" gives "OK\r", and *parsed counts from that one character on */
int cellHttpUtilParseStatusLine(CellHttpStatusLine *status, const char *text, size_t length, void *pool, size_t size,
                                size_t *required, size_t *parsed)
{
	if (text == NULL)
		return UTIL_NO_INPUT;
	size_t i = 0;
	while (i < length && is_blank((unsigned char)text[i]))
		++i;
	size_t protocol_start = i;
	while (i < length && text[i] != '/' && text[i] != ' ' && text[i] != '\r' && text[i] != '\n')
		++i;
	if (i == length || text[i] != '/' || i == protocol_start)
		return UTIL_BAD_STATUS;
	size_t protocol_length = i - protocol_start;
	++i;
	uint32_t version[2] = {0, 0};
	for (int part = 0; part < 2; ++part) {
		size_t digits = i;
		while (i < length && is_digit((unsigned char)text[i]))
			version[part] = version[part] * 10 + (uint32_t)(text[i++] - '0');
		if (i == digits || i == length || text[i] != (part == 0 ? '.' : ' '))
			return UTIL_BAD_STATUS;
		++i;
	}
	size_t digits = i;
	int32_t code = 0;
	while (i < length && is_digit((unsigned char)text[i]))
		code = code * 10 + (text[i++] - '0');
	if (i == digits)
		return UTIL_BAD_STATUS;
	size_t newline = i;
	while (newline < length && text[newline] != '\n')
		++newline;
	if (newline == length)
		return UTIL_BAD_STATUS;
	size_t start = i + 1;
	long reason_length = (long)newline - (long)start;
	if (newline > 0 && text[newline - 1] == '\r')
		--reason_length;
	if (reason_length < 0)
		reason_length = 0;
	size_t reason = start;
	while (reason < newline && is_blank((unsigned char)text[reason]))
		++reason;
	if (reason + (size_t)reason_length > newline)
		reason_length = (long)(newline - reason);
	size_t used = newline + 1 >= start ? newline + 1 - start : 0;
	int rc;
	if (!sizing(status != NULL && pool != NULL, protocol_length + 1 + (size_t)reason_length + 1, size, required, &rc)) {
		if (rc == 0 && parsed != NULL)
			*parsed = used;
		return rc;
	}
	char *at = pool;
	status->protocol = put(&at, text + protocol_start, protocol_length);
	status->reasonPhrase = put(&at, text + reason, (size_t)reason_length);
	status->majorVersion = version[0];
	status->minorVersion = version[1];
	status->statusCode = code;
	if (parsed != NULL)
		*parsed = used;
	return 0;
}

/* A header's value from start: each line's text without blanks around it, lines that begin with
 * blank space joined to it with one space; into out (when there is one). Its length, *end where
 * it stopped; -1 for a line that continues into nothing */
static long header_value(const char *text, size_t length, size_t start, char *out, size_t *end)
{
	size_t i = start;
	long used = 0;
	for (;;) {
		size_t line = i;
		while (i < length && text[i] != '\r' && text[i] != '\n')
			++i;
		size_t stop = i;
		while (stop > line && is_blank((unsigned char)text[stop - 1]))
			--stop;
		if (stop > line) {
			if (used > 0) {
				if (out != NULL)
					out[used] = ' ';
				++used;
			}
			if (out != NULL)
				memcpy(out + used, text + line, stop - line);
			used += (long)(stop - line);
		}
		if (i < length && text[i] == '\r')
			++i;
		if (i < length && text[i] == '\n')
			++i;
		if (i < length && (is_blank((unsigned char)text[i]) || text[i] == '\r' || text[i] == '\n')) {
			while (i < length && (is_blank((unsigned char)text[i]) || text[i] == '\r' || text[i] == '\n'))
				++i;
			if (i == length)
				return -1;
			continue;
		}
		*end = i;
		return used;
	}
}

/* name ":" value, the name without blanks before it; *parsed counts from the value's first
 * character (0 for an empty value), as Sony's */
int cellHttpUtilParseHeader(CellHttpHeader *header, const char *text, size_t length, void *pool, size_t size,
                            size_t *required, size_t *parsed)
{
	if (text == NULL)
		return UTIL_NO_INPUT;
	size_t i = 0;
	while (i < length && is_blank((unsigned char)text[i]))
		++i;
	size_t name = i;
	while (i < length && text[i] != ':' && text[i] != '\r' && text[i] != '\n')
		++i;
	if (i == length || text[i] != ':' || i == name)
		return UTIL_BAD_HEADER;
	size_t name_length = i - name;
	++i;
	while (i < length && is_blank((unsigned char)text[i]))
		++i;
	if (i == length)
		return UTIL_BAD_HEADER;
	size_t value = i, end = i;
	long value_length = header_value(text, length, value, NULL, &end);
	if (value_length < 0)
		return UTIL_BAD_HEADER;
	size_t used = value_length > 0 ? end - value : 0;
	int rc;
	if (!sizing(header != NULL && pool != NULL, name_length + 1 + (size_t)value_length + 1, size, required, &rc)) {
		if (rc == 0 && parsed != NULL)
			*parsed = used;
		return rc;
	}
	char *at = pool;
	header->name = put(&at, text + name, name_length);
	char *written = at;
	header_value(text, length, value, written, &end);
	written[value_length] = '\0';
	header->value = written;
	if (parsed != NULL)
		*parsed = used;
	return 0;
}

/* ---- headers and status lines copied ---- */

int cellHttpUtilCopyHeader(CellHttpHeader *dest, const CellHttpHeader *src, void *pool, size_t size, size_t *required)
{
	if (src == NULL)
		return UTIL_NO_BUFFER;
	int rc;
	if (!sizing(dest != NULL && pool != NULL, length_of(src->name) + length_of(src->value) + 2, size, required, &rc))
		return rc;
	char *at = pool;
	CellHttpHeader copy;
	copy.name = put_string(&at, src->name);
	copy.value = put_string(&at, src->value);
	*dest = copy;
	return 0;
}

/* src's value, a space and value (either alone when the other is empty) */
int cellHttpUtilAppendHeaderValue(CellHttpHeader *dest, const CellHttpHeader *src, const char *value, void *pool,
                                  size_t size, size_t *required)
{
	if (src == NULL)
		return UTIL_NO_BUFFER;
	size_t name = length_of(src->name), old = length_of(src->value), more = length_of(value);
	size_t joined = old + more + (old > 0 && more > 0);
	int rc;
	if (!sizing(dest != NULL && pool != NULL, name + 1 + joined + 1, size, required, &rc))
		return rc;
	char *at = pool;
	const char *copied_name = put_string(&at, src->name);
	char *written = at;
	if (old > 0)
		memcpy(written, src->value, old);
	if (old > 0 && more > 0)
		written[old] = ' ';
	if (more > 0)
		memcpy(written + joined - more, value, more);
	written[joined] = '\0';
	dest->name = copied_name;
	dest->value = written;
	return 0;
}

int cellHttpUtilCopyStatusLine(CellHttpStatusLine *dest, const CellHttpStatusLine *src, void *pool, size_t size,
                               size_t *required)
{
	if (src == NULL)
		return UTIL_NO_BUFFER;
	int rc;
	if (!sizing(dest != NULL && pool != NULL, length_of(src->protocol) + length_of(src->reasonPhrase) + 2, size,
	            required, &rc))
		return rc;
	char *at = pool;
	CellHttpStatusLine copy = *src;
	copy.protocol = put_string(&at, src->protocol);
	copy.reasonPhrase = put_string(&at, src->reasonPhrase);
	*dest = copy;
	return 0;
}
