/* The probe's cellHttpUtil half: every one of its 20 functions, with good input, edge cases and bad
 * arguments, each result as one "probe: " line (main.c runs it after the rest). Output buffers start
 * filled with 0xA5, so a line shows what was written, NUL or not; strings a function puts in a pool
 * are shown with their offset in it */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <cell/http.h>

#define FILL 0xa5
#define UNTOUCHED ((size_t)0xa5a5a5a5u)

static void say(const char *format, ...) __attribute__((format(printf, 1, 2)));
static void say(const char *format, ...)
{
	char text[640];
	va_list arguments;
	va_start(arguments, format);
	vsnprintf(text, sizeof(text), format, arguments);
	va_end(arguments);
	printf("probe: %s\n", text);
}

/* Bytes as text: printable as they are, the rest as \xNN; at most 120 bytes */
static const char *bytes(const void *data, size_t length)
{
	static char out[2][520];
	static int which;
	char *text = out[which ^= 1];
	const unsigned char *at = data;
	size_t used = 0;
	if (data == NULL)
		return "(null)";
	for (size_t i = 0; i < length && i < 120; ++i) {
		unsigned char c = at[i];
		if (c >= 32 && c < 127 && c != '\\')
			text[used++] = (char)c;
		else
			used += (size_t)snprintf(text + used, 8, "\\x%02x", c);
	}
	text[used] = '\0';
	return text;
}

static const char *size_text(size_t value)
{
	static char out[2][24];
	static int which;
	char *text = out[which ^= 1];
	if (value == UNTOUCHED)
		return "untouched";
	snprintf(text, 24, "%u", (unsigned)value);
	return text;
}

/* A string a function gave: its offset in pool (or "out" when it's elsewhere) and its text */
static const char *placed(const char *text, const char *pool, size_t size)
{
	static char out[8][200];
	static int which;
	char *line = out[which = (which + 1) & 7];
	if (text == NULL)
		return "(null)";
	if ((uintptr_t)text == (uintptr_t)0xa5a5a5a5a5a5a5a5ull) /* the 0xa5 fill, at any pointer size */
		return "(untouched)";
	if (text >= pool && text < pool + size)
		snprintf(line, 200, "@%d\"%s\"", (int)(text - pool), bytes(text, strlen(text)));
	else
		snprintf(line, 200, "out\"%s\"", bytes(text, strlen(text)));
	return line;
}

static char g_pool[1024];

/* ---- escaping ---- */

typedef int (*Encoder)(char *, size_t, const unsigned char *, size_t, size_t *);
typedef int (*Decoder)(unsigned char *, size_t, const char *, size_t *);

static void encode(const char *name, Encoder encoder, const char *in, size_t length)
{
	char out[256];
	size_t required = UNTOUCHED;
	memset(out, FILL, sizeof(out));
	int rc = encoder(out, sizeof(out), (const unsigned char *)in, length, &required);
	size_t shown = required != UNTOUCHED && required < sizeof(out) ? required + 1 : 16;
	say("%s \"%s\" rc=0x%08x required=%s out=\"%s\"", name, bytes(in, length), (unsigned)rc, size_text(required),
	    bytes(out, shown));
}

static void encode_sizes(const char *name, Encoder encoder)
{
	static const char in[] = "a b&c";
	char out[64];
	size_t required = UNTOUCHED;
	int rc = encoder(NULL, 0, (const unsigned char *)in, 5, &required);
	say("%s no out rc=0x%08x required=%s", name, (unsigned)rc, size_text(required));
	size_t need = required == UNTOUCHED ? 8 : required;
	for (size_t size = need > 1 ? need - 1 : 0; size <= need + 1; ++size) {
		memset(out, FILL, sizeof(out));
		required = UNTOUCHED;
		rc = encoder(out, size, (const unsigned char *)in, 5, &required);
		say("%s size %u rc=0x%08x required=%s out=\"%s\"", name, (unsigned)size, (unsigned)rc, size_text(required),
		    bytes(out, need + 2));
	}
	memset(out, FILL, sizeof(out));
	rc = encoder(out, sizeof(out), (const unsigned char *)in, 5, NULL);
	say("%s no required rc=0x%08x out=\"%s\"", name, (unsigned)rc, bytes(out, need + 2));
	rc = encoder(out, sizeof(out), NULL, 5, &required);
	say("%s NULL in rc=0x%08x", name, (unsigned)rc);
	required = UNTOUCHED;
	rc = encoder(NULL, 0, NULL, 0, &required);
	say("%s nothing rc=0x%08x required=%s", name, (unsigned)rc, size_text(required));
}

static void decode(const char *name, Decoder decoder, const char *in)
{
	unsigned char out[256];
	size_t required = UNTOUCHED;
	memset(out, FILL, sizeof(out));
	int rc = decoder(out, sizeof(out), in, &required);
	size_t shown = required != UNTOUCHED && required < sizeof(out) ? required + 1 : 16;
	say("%s \"%s\" rc=0x%08x required=%s out=\"%s\"", name, bytes(in, strlen(in)), (unsigned)rc,
	    size_text(required), bytes(out, shown));
}

static void decode_sizes(const char *name, Decoder decoder)
{
	static const char in[] = "a%20b+c";
	unsigned char out[64];
	size_t required = UNTOUCHED;
	int rc = decoder(NULL, 0, in, &required);
	say("%s no out rc=0x%08x required=%s", name, (unsigned)rc, size_text(required));
	size_t need = required == UNTOUCHED ? 8 : required;
	for (size_t size = need > 1 ? need - 1 : 0; size <= need + 1; ++size) {
		memset(out, FILL, sizeof(out));
		required = UNTOUCHED;
		rc = decoder(out, size, in, &required);
		say("%s size %u rc=0x%08x required=%s out=\"%s\"", name, (unsigned)size, (unsigned)rc, size_text(required),
		    bytes(out, need + 2));
	}
	memset(out, FILL, sizeof(out));
	rc = decoder(out, sizeof(out), in, NULL);
	say("%s no required rc=0x%08x out=\"%s\"", name, (unsigned)rc, bytes(out, need + 2));
	rc = decoder(out, sizeof(out), NULL, &required);
	say("%s NULL in rc=0x%08x", name, (unsigned)rc);
}

static void escaping(void)
{
	static const char *const inputs[] = {"abc", "a b", "a/b?c=d&e=f#g", "~-_.!*'()", "100%", "+:@;,$[]",
	                                     "\"<>\\^`{|}", "caf\xc3\xa9"};
	for (unsigned i = 0; i < sizeof(inputs) / sizeof(inputs[0]); ++i)
		encode("EscapeUri", cellHttpUtilEscapeUri, inputs[i], strlen(inputs[i]));
	for (unsigned i = 0; i < sizeof(inputs) / sizeof(inputs[0]); ++i)
		encode("FormUrlEncode", cellHttpUtilFormUrlEncode, inputs[i], strlen(inputs[i]));
	/* Every byte, in four runs of 64 */
	unsigned char all[256];
	for (int i = 0; i < 256; ++i)
		all[i] = (unsigned char)i;
	for (int run = 0; run < 4; ++run) {
		char out[512];
		size_t required = UNTOUCHED;
		memset(out, FILL, sizeof(out));
		int rc = cellHttpUtilEscapeUri(out, sizeof(out), all + run * 64, 64, &required);
		say("EscapeUri bytes %d-%d rc=0x%08x required=%s out=\"%s\"", run * 64, run * 64 + 63, (unsigned)rc,
		    size_text(required), bytes(out, required < sizeof(out) ? required : 32));
		required = UNTOUCHED;
		memset(out, FILL, sizeof(out));
		rc = cellHttpUtilFormUrlEncode(out, sizeof(out), all + run * 64, 64, &required);
		say("FormUrlEncode bytes %d-%d rc=0x%08x required=%s out=\"%s\"", run * 64, run * 64 + 63, (unsigned)rc,
		    size_text(required), bytes(out, required < sizeof(out) ? required : 32));
	}
	encode("EscapeUri empty", cellHttpUtilEscapeUri, "", 0);
	encode("EscapeUri with NUL", cellHttpUtilEscapeUri, "a\0b", 3);
	for (size_t size = 1; size <= 4; ++size) {
		char out[16];
		size_t required = UNTOUCHED;
		memset(out, FILL, sizeof(out));
		int rc = cellHttpUtilEscapeUri(out, size, (const unsigned char *)"a b", 3, &required);
		say("EscapeUri \"a b\" size %u rc=0x%08x required=%s out=\"%s\"", (unsigned)size, (unsigned)rc,
		    size_text(required), bytes(out, 7));
		memset(out, FILL, sizeof(out));
		rc = cellHttpUtilUnescapeUri((unsigned char *)out, size, "a%20bc", &required);
		say("UnescapeUri \"a%%20bc\" size %u rc=0x%08x out=\"%s\"", (unsigned)size, (unsigned)rc, bytes(out, 7));
	}
	encode_sizes("EscapeUri", cellHttpUtilEscapeUri);
	encode_sizes("FormUrlEncode", cellHttpUtilFormUrlEncode);

	static const char *const escaped[] = {"abc", "a%20b", "a+b", "%41%4a%4A", "%zz", "%4", "%", "a%2", "%00x",
	                                      "%e2%82%ac", "100%25", ""};
	for (unsigned i = 0; i < sizeof(escaped) / sizeof(escaped[0]); ++i)
		decode("UnescapeUri", cellHttpUtilUnescapeUri, escaped[i]);
	for (unsigned i = 0; i < sizeof(escaped) / sizeof(escaped[0]); ++i)
		decode("FormUrlDecode", cellHttpUtilFormUrlDecode, escaped[i]);
	decode_sizes("UnescapeUri", cellHttpUtilUnescapeUri);
	decode_sizes("FormUrlDecode", cellHttpUtilFormUrlDecode);
}

/* ---- base64 ---- */

static void base64(void)
{
	static const char *const inputs[] = {"", "f", "fo", "foo", "foob", "fooba", "foobar"};
	for (unsigned i = 0; i < sizeof(inputs) / sizeof(inputs[0]); ++i) {
		char out[32];
		memset(out, FILL, sizeof(out));
		size_t length = strlen(inputs[i]);
		int rc = cellHttpUtilBase64Encoder(out, inputs[i], length);
		say("Base64Encoder \"%s\" rc=0x%08x out=\"%s\"", inputs[i], (unsigned)rc,
		    bytes(out, CELL_HTTP_UTIL_BASE64_ENC_BUF_SIZE(length) + 2));
	}
	unsigned char binary[] = {0x00, 0xff, 0xfe, 0x80, 0x7f, 0x01};
	char out[32];
	memset(out, FILL, sizeof(out));
	int rc = cellHttpUtilBase64Encoder(out, binary, sizeof(binary));
	say("Base64Encoder binary rc=0x%08x out=\"%s\"", (unsigned)rc, bytes(out, 10));
	say("Base64Encoder NULL out rc=0x%08x", (unsigned)cellHttpUtilBase64Encoder(NULL, "a", 1));
	say("Base64Encoder NULL in rc=0x%08x", (unsigned)cellHttpUtilBase64Encoder(out, NULL, 1));

	static const char *const encoded[] = {"", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy",
	                                      "AP/+gH8B", "Zm9", "Zm9vY", "Zg", "Z===", "Zm9v====", "Zm*v", "Zm 9v",
	                                      "Zm9v\n", "=Zm9", "Zm=v", "Zg==Zm9v", "Zm8=Zm9v", "zzzz", "Zm9v Zm9v"};
	for (unsigned i = 0; i < sizeof(encoded) / sizeof(encoded[0]); ++i) {
		unsigned char decoded[32];
		memset(decoded, FILL, sizeof(decoded));
		size_t length = strlen(encoded[i]);
		rc = cellHttpUtilBase64Decoder(decoded, encoded[i], length);
		say("Base64Decoder \"%s\" rc=0x%08x out=\"%s\"", bytes(encoded[i], length), (unsigned)rc,
		    bytes(decoded, CELL_HTTP_UTIL_BASE64_DEC_BUF_SIZE(length) + 2));
	}
	unsigned char decoded[8];
	say("Base64Decoder NULL out rc=0x%08x", (unsigned)cellHttpUtilBase64Decoder(NULL, "Zm9v", 4));
	say("Base64Decoder NULL in rc=0x%08x", (unsigned)cellHttpUtilBase64Decoder(decoded, NULL, 4));
}

/* ---- the structures ---- */

static void uri_shown(const char *name, int rc, const CellHttpUri *uri, size_t required)
{
	if (rc != 0) {
		say("%s rc=0x%08x required=%s", name, (unsigned)rc, size_text(required));
		return;
	}
	say("%s rc=0x%08x required=%s scheme=%s host=%s user=%s password=%s path=%s port=%u", name, (unsigned)rc,
	    size_text(required), placed(uri->scheme, g_pool, sizeof(g_pool)), placed(uri->hostname, g_pool, sizeof(g_pool)),
	    placed(uri->username, g_pool, sizeof(g_pool)), placed(uri->password, g_pool, sizeof(g_pool)),
	    placed(uri->path, g_pool, sizeof(g_pool)), (unsigned)uri->port);
}

static void parse_uri(const char *in)
{
	CellHttpUri uri;
	char name[160];
	size_t required = UNTOUCHED;
	memset(&uri, FILL, sizeof(uri));
	int rc = cellHttpUtilParseUri(NULL, in, NULL, 0, &required);
	snprintf(name, sizeof(name), "ParseUri \"%s\" size", in != NULL ? bytes(in, strlen(in)) : "(null)");
	say("%s rc=0x%08x required=%s", name, (unsigned)rc, size_text(required));
	size_t need = required;
	memset(g_pool, FILL, sizeof(g_pool));
	required = UNTOUCHED;
	rc = cellHttpUtilParseUri(&uri, in, g_pool, sizeof(g_pool), &required);
	snprintf(name, sizeof(name), "ParseUri \"%s\"", in != NULL ? bytes(in, strlen(in)) : "(null)");
	uri_shown(name, rc, &uri, required);
	if (rc == 0 && need != UNTOUCHED && need > 0) {
		required = UNTOUCHED;
		rc = cellHttpUtilParseUri(&uri, in, g_pool, need - 1, &required);
		say("ParseUri \"%s\" short rc=0x%08x required=%s", bytes(in, strlen(in)), (unsigned)rc, size_text(required));
	}
}

static void uris(void)
{
	static const char *const inputs[] = {"http://example.com/",
	                                     "http://example.com",
	                                     "https://user:pass@example.com:8443/a/b?c=d#e",
	                                     "http://user@example.com/",
	                                     "http://:pass@example.com/",
	                                     "HTTP://Example.COM/Path",
	                                     "ftp://example.com/file",
	                                     "example.com/path",
	                                     "//example.com/path",
	                                     "/path/only",
	                                     "http://example.com:/",
	                                     "http://example.com:0/",
	                                     "http://example.com:65535/",
	                                     "http://example.com:65536/",
	                                     "http://example.com:abc/",
	                                     "http://[::1]:8080/",
	                                     "http:///path",
	                                     "http://example.com?q=1",
	                                     "http://example.com#frag",
	                                     "http://exa mple.com/",
	                                     "http://example.com/a b",
	                                     "http://example.com/%20",
	                                     "mailto:someone@example.com",
	                                     "http:",
	                                     "",
	                                     "https://example.com/",
	                                     "HTTPS://a/",
	                                     "ws://a/",
	                                     "example.com:8080/path",
	                                     "localhost:80",
	                                     "http://example.com/a@b",
	                                     "http://a:80x/",
	                                     "http://a:80?q",
	                                     "http://user:pa:ss@host/",
	                                     "http://a@b@c/",
	                                     "http://a_b-c.d/",
	                                     "http://exa%41mple/",
	                                     "http://example.com:8080",
	                                     "http:/path",
	                                     "a:b",
	                                     "1http://a/",
	                                     "h+t.p-s://a/",
	                                     "http://example.com:080/",
	                                     "http://example.com:99999999999/",
	                                     "http://ex~ample/",
	                                     "http://a:b/c",
	                                     "http://user:@host/"};
	for (unsigned i = 0; i < sizeof(inputs) / sizeof(inputs[0]); ++i)
		parse_uri(inputs[i]);
	size_t required = UNTOUCHED;
	say("ParseUri NULL string rc=0x%08x", (unsigned)cellHttpUtilParseUri(NULL, NULL, NULL, 0, &required));
	CellHttpUri uri;
	say("ParseUri nothing rc=0x%08x", (unsigned)cellHttpUtilParseUri(&uri, "http://a/", NULL, 0, NULL));
	say("ParseUri no required rc=0x%08x", (unsigned)cellHttpUtilParseUri(&uri, "http://a/", g_pool, sizeof(g_pool), NULL));
	say("ParseUri pool no uri rc=0x%08x", (unsigned)cellHttpUtilParseUri(NULL, "http://a/", g_pool, sizeof(g_pool), &required));

	/* ParseProxy */
	static const char *const proxies[] = {"proxy.example:8080", "http://proxy.example:8080", "user:pw@proxy.example:3128",
	                                      "proxy.example", "proxy.example:", "http://proxy.example/", ":8080", "",
	                                      "proxy:0", "proxy:abc", "proxy:80x", "user@proxy", "proxy/path:1", "a_b:1",
	                                      "user:@proxy:1"};
	for (unsigned i = 0; i < sizeof(proxies) / sizeof(proxies[0]); ++i) {
		char name[120];
		memset(&uri, FILL, sizeof(uri));
		required = UNTOUCHED;
		int rc = cellHttpUtilParseProxy(NULL, proxies[i], NULL, 0, &required);
		say("ParseProxy \"%s\" size rc=0x%08x required=%s", proxies[i], (unsigned)rc, size_text(required));
		memset(g_pool, FILL, sizeof(g_pool));
		required = UNTOUCHED;
		rc = cellHttpUtilParseProxy(&uri, proxies[i], g_pool, sizeof(g_pool), &required);
		snprintf(name, sizeof(name), "ParseProxy \"%s\"", proxies[i]);
		uri_shown(name, rc, &uri, required);
	}

	/* ParseUriPath */
	static const char *const paths[] = {"/a/b?c=d#e", "/a/b", "/a?q", "/a#f", "?q", "#f", "/a?q#f?g", "/a#f?q", ""};
	for (unsigned i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
		CellHttpUriPath path;
		memset(&path, FILL, sizeof(path));
		required = UNTOUCHED;
		int rc = cellHttpUtilParseUriPath(NULL, paths[i], NULL, 0, &required);
		say("ParseUriPath \"%s\" size rc=0x%08x required=%s", paths[i], (unsigned)rc, size_text(required));
		size_t need = required;
		memset(g_pool, FILL, sizeof(g_pool));
		required = UNTOUCHED;
		rc = cellHttpUtilParseUriPath(&path, paths[i], g_pool, sizeof(g_pool), &required);
		if (rc != 0)
			say("ParseUriPath \"%s\" rc=0x%08x required=%s", paths[i], (unsigned)rc, size_text(required));
		else
			say("ParseUriPath \"%s\" rc=0x%08x required=%s path=%s query=%s fragment=%s", paths[i], (unsigned)rc,
			    size_text(required), placed(path.path, g_pool, sizeof(g_pool)), placed(path.query, g_pool, sizeof(g_pool)),
			    placed(path.fragment, g_pool, sizeof(g_pool)));
		if (rc == 0 && need != UNTOUCHED && need > 0) {
			required = UNTOUCHED;
			rc = cellHttpUtilParseUriPath(&path, paths[i], g_pool, need - 1, &required);
			say("ParseUriPath \"%s\" short rc=0x%08x required=%s", paths[i], (unsigned)rc, size_text(required));
		}
	}

	/* BuildUri, with each flag */
	CellHttpUri full = {"https", "example.com", "user", "pass", "/a/b?c", 8443, {0}};
	CellHttpUri plain = {"http", "example.com", "", "", "/", 80, {0}};
	CellHttpUri noport = {"http", "example.com", NULL, NULL, NULL, 0, {0}};
	CellHttpUri nouser = {"http", "example.com", "", "pw", "/x", 8080, {0}};
	CellHttpUri other = {"ftp", "example.com", "u", "", "/x", 21, {0}};
	CellHttpUri secure = {"https", "example.com", "", "", "/", 443, {0}};
	CellHttpUri http443 = {"http", "example.com", "", "", "/", 443, {0}};
	CellHttpUri secure80 = {"HTTPS", "example.com", "", "", "x", 80, {0}};
	CellHttpUri http80 = {"HTTP", "example.com", "", "", "/", 80, {0}};
	const CellHttpUri *const built[] = {&full, &plain, &noport, &nouser, &other, &secure, &http443, &secure80, &http80};
	static const int32_t flags[] = {0, 1, 2, 4, 8, 15};
	for (unsigned i = 0; i < sizeof(built) / sizeof(built[0]); ++i)
		for (unsigned j = 0; j < sizeof(flags) / sizeof(flags[0]); ++j) {
			char out[128];
			memset(out, FILL, sizeof(out));
			required = UNTOUCHED;
			int rc = cellHttpUtilBuildUri(built[i], out, sizeof(out), &required, flags[j]);
			say("BuildUri %u flags %d rc=0x%08x required=%s out=\"%s\"", i, (int)flags[j], (unsigned)rc,
			    size_text(required), bytes(out, required != UNTOUCHED && required < sizeof(out) ? required + 1 : 8));
		}
	required = UNTOUCHED;
	char out[64];
	int rc = cellHttpUtilBuildUri(&full, NULL, 0, &required, 0);
	say("BuildUri size rc=0x%08x required=%s", (unsigned)rc, size_text(required));
	size_t need = required == UNTOUCHED ? 8 : required;
	for (size_t size = need - 1; size <= need + 1; ++size) {
		memset(out, FILL, sizeof(out));
		required = UNTOUCHED;
		rc = cellHttpUtilBuildUri(&full, out, size, &required, 0);
		say("BuildUri size %u rc=0x%08x required=%s out=\"%s\"", (unsigned)size, (unsigned)rc, size_text(required),
		    bytes(out, need + 2));
	}
	say("BuildUri NULL uri rc=0x%08x", (unsigned)cellHttpUtilBuildUri(NULL, out, sizeof(out), &required, 0));
	CellHttpUri nohost = {"http", NULL, NULL, NULL, "/", 80, {0}};
	say("BuildUri no host rc=0x%08x", (unsigned)cellHttpUtilBuildUri(&nohost, out, sizeof(out), &required, 0));
	CellHttpUri noscheme = {NULL, "example.com", NULL, NULL, "/", 80, {0}};
	required = UNTOUCHED;
	memset(out, FILL, sizeof(out));
	rc = cellHttpUtilBuildUri(&noscheme, out, sizeof(out), &required, 0);
	say("BuildUri no scheme rc=0x%08x required=%s out=\"%s\"", (unsigned)rc, size_text(required), bytes(out, 24));
	say("BuildUri nothing rc=0x%08x", (unsigned)cellHttpUtilBuildUri(&full, NULL, 0, NULL, 0));

	/* CopyUri */
	CellHttpUri copy;
	required = UNTOUCHED;
	rc = cellHttpUtilCopyUri(NULL, &full, NULL, 0, &required);
	say("CopyUri size rc=0x%08x required=%s", (unsigned)rc, size_text(required));
	memset(g_pool, FILL, sizeof(g_pool));
	memset(&copy, FILL, sizeof(copy));
	required = UNTOUCHED;
	rc = cellHttpUtilCopyUri(&copy, &full, g_pool, sizeof(g_pool), &required);
	uri_shown("CopyUri", rc, &copy, required);
	memset(&copy, FILL, sizeof(copy));
	required = UNTOUCHED;
	rc = cellHttpUtilCopyUri(&copy, &noport, g_pool, sizeof(g_pool), &required);
	uri_shown("CopyUri NULLs", rc, &copy, required);
	say("CopyUri NULL src rc=0x%08x", (unsigned)cellHttpUtilCopyUri(&copy, NULL, g_pool, sizeof(g_pool), &required));
	required = UNTOUCHED;
	rc = cellHttpUtilCopyUri(&copy, &full, g_pool, 10, &required);
	say("CopyUri short rc=0x%08x required=%s", (unsigned)rc, size_text(required));
	required = UNTOUCHED;
	rc = cellHttpUtilCopyUri(&copy, &full, NULL, 0, &required);
	say("CopyUri no pool rc=0x%08x required=%s", (unsigned)rc, size_text(required));
	required = UNTOUCHED;
	rc = cellHttpUtilCopyUri(NULL, &full, g_pool, sizeof(g_pool), &required);
	say("CopyUri no dest rc=0x%08x required=%s", (unsigned)rc, size_text(required));

	/* MergeUriPath */
	static const char *const merged[] = {"c", "/c", "../c", "./c", "c/d", "?q", "#f", "", "../../../c", "http://other/x"};
	CellHttpUri base = {"http", "example.com", "u", "p", "/a/b", 8080, {0}};
	CellHttpUri dir = {"http", "example.com", "", "", "/a/b/", 80, {0}};
	CellHttpUri empty = {"http", "example.com", NULL, NULL, "", 80, {0}};
	CellHttpUri noslash = {"http", "example.com", "", "", "abc", 80, {0}};
	CellHttpUri queried = {"http", "example.com", "", "", "/a/b?x=/y", 80, {0}};
	const CellHttpUri *const bases[] = {&base, &dir, &empty, &noslash, &queried};
	for (unsigned b = 0; b < 5; ++b)
		for (unsigned i = 0; i < sizeof(merged) / sizeof(merged[0]); ++i) {
			char name[96];
			required = UNTOUCHED;
			rc = cellHttpUtilMergeUriPath(NULL, bases[b], merged[i], NULL, 0, &required);
			say("MergeUriPath %u \"%s\" size rc=0x%08x required=%s", b, merged[i], (unsigned)rc, size_text(required));
			memset(g_pool, FILL, sizeof(g_pool));
			memset(&copy, FILL, sizeof(copy));
			required = UNTOUCHED;
			rc = cellHttpUtilMergeUriPath(&copy, bases[b], merged[i], g_pool, sizeof(g_pool), &required);
			snprintf(name, sizeof(name), "MergeUriPath %u \"%s\"", b, merged[i]);
			uri_shown(name, rc, &copy, required);
		}
	say("MergeUriPath NULL path rc=0x%08x", (unsigned)cellHttpUtilMergeUriPath(&copy, &base, NULL, g_pool, sizeof(g_pool), &required));
	say("MergeUriPath NULL src rc=0x%08x", (unsigned)cellHttpUtilMergeUriPath(&copy, NULL, "c", g_pool, sizeof(g_pool), &required));
	required = UNTOUCHED;
	rc = cellHttpUtilMergeUriPath(&copy, &base, "c", g_pool, 8, &required);
	say("MergeUriPath short rc=0x%08x required=%s", (unsigned)rc, size_text(required));

	/* SweepPath */
	static const char *const swept[] = {"/a/./b/../c", "/../a", "a//b", "/a/b/..", "/a/b/../", "/./", "/a/../../b",
	                                    "a/b/../../..", "/a/b/c/./../../d", "/.", "/..", "", "/a/.b/..c/...",
	                                    "/a?x=/../b", "/a/b%2e%2e/c", "/a#x/../b", "/a//b/../c", "//a/../b",
	                                    "/a/b/./", "/a/b/.x/", "/a/b/../../../../c/"};
	for (unsigned i = 0; i < sizeof(swept) / sizeof(swept[0]); ++i) {
		char result[64];
		memset(result, FILL, sizeof(result));
		size_t length = strlen(swept[i]);
		rc = cellHttpUtilSweepPath(result, swept[i], length);
		say("SweepPath \"%s\" rc=0x%08x out=\"%s\"", swept[i], (unsigned)rc,
		    bytes(result, memchr(result, 0, length + 1) != NULL ? strlen(result) + 1 : length + 1));
		memset(result, FILL, sizeof(result));
		rc = cellHttpUtilSweepPath(result, swept[i], length + 1);
		say("SweepPath \"%s\" with NUL rc=0x%08x out=\"%s\"", swept[i], (unsigned)rc,
		    bytes(result, memchr(result, 0, length + 2) != NULL ? strlen(result) + 1 : length + 2));
	}
	char result[16];
	memset(result, FILL, sizeof(result));
	rc = cellHttpUtilSweepPath(result, "/a/b/c", 4);
	say("SweepPath size 4 rc=0x%08x out=\"%s\"", (unsigned)rc, bytes(result, strlen(result) + 1));
	say("SweepPath NULL dst rc=0x%08x", (unsigned)cellHttpUtilSweepPath(NULL, "/a", 2));
	say("SweepPath NULL src rc=0x%08x", (unsigned)cellHttpUtilSweepPath(result, NULL, 2));
	memset(result, FILL, sizeof(result));
	rc = cellHttpUtilSweepPath(result, "/a", 0);
	say("SweepPath size 0 rc=0x%08x out=\"%s\"", (unsigned)rc, bytes(result, 4));
}

/* ---- status lines and headers ---- */

static void status_line(const char *in, size_t length)
{
	CellHttpStatusLine status;
	size_t required = UNTOUCHED, parsed = UNTOUCHED;
	memset(&status, FILL, sizeof(status));
	int rc = cellHttpUtilParseStatusLine(NULL, in, length, NULL, 0, &required, &parsed);
	say("ParseStatusLine \"%s\" size rc=0x%08x required=%s parsed=%s", bytes(in, length), (unsigned)rc,
	    size_text(required), size_text(parsed));
	size_t need = required;
	memset(g_pool, FILL, sizeof(g_pool));
	required = parsed = UNTOUCHED;
	rc = cellHttpUtilParseStatusLine(&status, in, length, g_pool, sizeof(g_pool), &required, &parsed);
	if (rc != 0)
		say("ParseStatusLine \"%s\" rc=0x%08x required=%s parsed=%s", bytes(in, length), (unsigned)rc,
		    size_text(required), size_text(parsed));
	else
		say("ParseStatusLine \"%s\" rc=0x%08x required=%s parsed=%s protocol=%s %u.%u code=%d reason=%s",
		    bytes(in, length), (unsigned)rc, size_text(required), size_text(parsed),
		    placed(status.protocol, g_pool, sizeof(g_pool)), (unsigned)status.majorVersion,
		    (unsigned)status.minorVersion, (int)status.statusCode, placed(status.reasonPhrase, g_pool, sizeof(g_pool)));
	if (rc == 0 && need != UNTOUCHED && need > 0) {
		required = parsed = UNTOUCHED;
		rc = cellHttpUtilParseStatusLine(&status, in, length, g_pool, need - 1, &required, &parsed);
		say("ParseStatusLine \"%s\" short rc=0x%08x required=%s parsed=%s", bytes(in, length), (unsigned)rc,
		    size_text(required), size_text(parsed));
	}
}

static void header(const char *in, size_t length)
{
	CellHttpHeader parsed_header;
	size_t required = UNTOUCHED, parsed = UNTOUCHED;
	memset(&parsed_header, FILL, sizeof(parsed_header));
	int rc = cellHttpUtilParseHeader(NULL, in, length, NULL, 0, &required, &parsed);
	say("ParseHeader \"%s\" size rc=0x%08x required=%s parsed=%s", bytes(in, length), (unsigned)rc,
	    size_text(required), size_text(parsed));
	size_t need = required;
	memset(g_pool, FILL, sizeof(g_pool));
	required = parsed = UNTOUCHED;
	rc = cellHttpUtilParseHeader(&parsed_header, in, length, g_pool, sizeof(g_pool), &required, &parsed);
	if (rc != 0)
		say("ParseHeader \"%s\" rc=0x%08x required=%s parsed=%s", bytes(in, length), (unsigned)rc,
		    size_text(required), size_text(parsed));
	else
		say("ParseHeader \"%s\" rc=0x%08x required=%s parsed=%s name=%s value=%s", bytes(in, length), (unsigned)rc,
		    size_text(required), size_text(parsed), placed(parsed_header.name, g_pool, sizeof(g_pool)),
		    placed(parsed_header.value, g_pool, sizeof(g_pool)));
	if (rc == 0 && need != UNTOUCHED && need > 0) {
		required = parsed = UNTOUCHED;
		rc = cellHttpUtilParseHeader(&parsed_header, in, length, g_pool, need - 1, &required, &parsed);
		say("ParseHeader \"%s\" short rc=0x%08x required=%s parsed=%s", bytes(in, length), (unsigned)rc,
		    size_text(required), size_text(parsed));
	}
}

static void lines(void)
{
	static const char *const statuses[] = {"HTTP/1.1 200 OK\r\n", "HTTP/1.0 404 Not Found\r\nX-Next: 1\r\n",
	                                       "HTTP/1.1 200\r\n", "HTTP/1.1 200 \r\n", "HTTP/1.1 200 OK\n",
	                                       "HTTP/1.1 200 OK", "HTTP/2 200 OK\r\n", "HTTP/1.1 99 Low\r\n",
	                                       "HTTP/1.1 1000 High\r\n", "HTTP/1.1 abc OK\r\n", "http/1.1 200 OK\r\n",
	                                       "ICY 200 OK\r\n", "HTTP/1.1  200  OK  \r\n", "HTTP/12.34 200 OK\r\n",
	                                       "garbage\r\n", "\r\n", "", "FOO/1.1 200 OK\r\n", "HTTP/1.1 200 OK\rX\n",
	                                       "HTTP/1.1 200 O K\r\n", "HTTP/a.b 200 OK\r\n", "HTTP/1. 200 OK\r\n",
	                                       "HTTP/1.1 -1 OK\r\n", "HTTP/1.1 200 OK \r\n", "HTTP/1.1 200 OK\r",
	                                       "HTTP1.1 200 OK\r\n", "HTTP/1.1 200x OK\r\n", " HTTP/1.1 200 OK\r\n",
	                                       "HTTP/1.1 200\tOK\r\n"};
	for (unsigned i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i)
		status_line(statuses[i], strlen(statuses[i]));
	status_line("HTTP/1.1 200 OK\r\nmore", 17);
	size_t required = UNTOUCHED, parsed = UNTOUCHED;
	CellHttpStatusLine status;
	say("ParseStatusLine NULL string rc=0x%08x",
	    (unsigned)cellHttpUtilParseStatusLine(&status, NULL, 5, g_pool, sizeof(g_pool), &required, &parsed));
	say("ParseStatusLine no parsed rc=0x%08x",
	    (unsigned)cellHttpUtilParseStatusLine(&status, "HTTP/1.1 200 OK\r\n", 17, g_pool, sizeof(g_pool), &required, NULL));
	say("ParseStatusLine no required rc=0x%08x",
	    (unsigned)cellHttpUtilParseStatusLine(&status, "HTTP/1.1 200 OK\r\n", 17, g_pool, sizeof(g_pool), NULL, &parsed));

	static const char *const headers[] = {"Name: value\r\n", "Name:value\r\n", "Name:  spaced out  \r\n",
	                                      "Name: v\r\n continued\r\n", "Name: v\r\n\tcontinued\r\nNext: x\r\n",
	                                      "Name: v\r\nNext: x\r\n", "Name:\r\n", "Name: \r\n", "NoColon\r\n",
	                                      ": novalue\r\n", "Name : v\r\n", "Name: v\n", "Name: v", "Name: a:b:c\r\n",
	                                      "\r\n", "", "Name:\tv\r\n", "Name: a  b\r\n", "Name: v\r\n \r\n",
	                                      "Name: v\r\n continued", "Name: v\r", "N\tame: v\r\n", "Name: v\r\n\r\n",
	                                      "Name: v\r\n  a  \r\n\tb\r\n", " Name: v\r\n", "Name:v\n continued\n"};
	for (unsigned i = 0; i < sizeof(headers) / sizeof(headers[0]); ++i)
		header(headers[i], strlen(headers[i]));
	header("Name: value\r\n", 6);
	CellHttpHeader parsed_header;
	say("ParseHeader NULL string rc=0x%08x",
	    (unsigned)cellHttpUtilParseHeader(&parsed_header, NULL, 5, g_pool, sizeof(g_pool), &required, &parsed));
	say("ParseHeader no parsed rc=0x%08x",
	    (unsigned)cellHttpUtilParseHeader(&parsed_header, "N: v\r\n", 6, g_pool, sizeof(g_pool), &required, NULL));

	/* Build */
	CellHttpRequestLine requests[] = {{"GET", "/a?b", "HTTP", 1, 1}, {"POST", "/", "HTTP", 1, 0},
	                                  {"OPTIONS", "*", "RTSP", 2, 0}, {"GET", "", "HTTP", 1, 1}, {"GET", "/", NULL, 1, 1}};
	for (unsigned i = 0; i < sizeof(requests) / sizeof(requests[0]); ++i) {
		char out[64];
		memset(out, FILL, sizeof(out));
		required = UNTOUCHED;
		int rc = cellHttpUtilBuildRequestLine(&requests[i], out, sizeof(out), &required);
		say("BuildRequestLine %u rc=0x%08x required=%s out=\"%s\"", i, (unsigned)rc, size_text(required),
		    bytes(out, required != UNTOUCHED && required < sizeof(out) ? required + 1 : 8));
	}
	char out[64];
	required = UNTOUCHED;
	int rc = cellHttpUtilBuildRequestLine(&requests[0], NULL, 0, &required);
	say("BuildRequestLine size rc=0x%08x required=%s", (unsigned)rc, size_text(required));
	size_t need = required == UNTOUCHED ? 8 : required;
	for (size_t size = need - 1; size <= need + 1; ++size) {
		memset(out, FILL, sizeof(out));
		required = UNTOUCHED;
		rc = cellHttpUtilBuildRequestLine(&requests[0], out, size, &required);
		say("BuildRequestLine size %u rc=0x%08x required=%s out=\"%s\"", (unsigned)size, (unsigned)rc,
		    size_text(required), bytes(out, need + 2));
	}
	say("BuildRequestLine NULL rc=0x%08x", (unsigned)cellHttpUtilBuildRequestLine(NULL, out, sizeof(out), &required));
	CellHttpRequestLine nomethod = {NULL, "/", "HTTP", 1, 1};
	say("BuildRequestLine no method rc=0x%08x", (unsigned)cellHttpUtilBuildRequestLine(&nomethod, out, sizeof(out), &required));
	CellHttpRequestLine nopath = {"GET", NULL, "HTTP", 1, 1};
	say("BuildRequestLine no path rc=0x%08x", (unsigned)cellHttpUtilBuildRequestLine(&nopath, out, sizeof(out), &required));
	say("BuildRequestLine nothing rc=0x%08x", (unsigned)cellHttpUtilBuildRequestLine(&requests[0], NULL, 0, NULL));

	CellHttpHeader built[] = {{"Name", "value"}, {"Empty", ""}, {"X", "a b"}};
	for (unsigned i = 0; i < sizeof(built) / sizeof(built[0]); ++i) {
		memset(out, FILL, sizeof(out));
		required = UNTOUCHED;
		rc = cellHttpUtilBuildHeader(&built[i], out, sizeof(out), &required);
		say("BuildHeader %u rc=0x%08x required=%s out=\"%s\"", i, (unsigned)rc, size_text(required),
		    bytes(out, required != UNTOUCHED && required < sizeof(out) ? required + 1 : 8));
	}
	required = UNTOUCHED;
	rc = cellHttpUtilBuildHeader(&built[0], NULL, 0, &required);
	say("BuildHeader size rc=0x%08x required=%s", (unsigned)rc, size_text(required));
	need = required == UNTOUCHED ? 8 : required;
	for (size_t size = need - 1; size <= need + 1; ++size) {
		memset(out, FILL, sizeof(out));
		required = UNTOUCHED;
		rc = cellHttpUtilBuildHeader(&built[0], out, size, &required);
		say("BuildHeader size %u rc=0x%08x required=%s out=\"%s\"", (unsigned)size, (unsigned)rc, size_text(required),
		    bytes(out, need + 2));
	}
	CellHttpHeader nameless = {NULL, "v"}, valueless = {"N", NULL};
	say("BuildHeader NULL rc=0x%08x", (unsigned)cellHttpUtilBuildHeader(NULL, out, sizeof(out), &required));
	say("BuildHeader no name rc=0x%08x", (unsigned)cellHttpUtilBuildHeader(&nameless, out, sizeof(out), &required));
	say("BuildHeader no value rc=0x%08x", (unsigned)cellHttpUtilBuildHeader(&valueless, out, sizeof(out), &required));
	say("BuildHeader nothing rc=0x%08x", (unsigned)cellHttpUtilBuildHeader(&built[0], NULL, 0, NULL));

	/* CopyHeader, AppendHeaderValue, CopyStatusLine */
	CellHttpHeader copy;
	required = UNTOUCHED;
	rc = cellHttpUtilCopyHeader(NULL, &built[0], NULL, 0, &required);
	say("CopyHeader size rc=0x%08x required=%s", (unsigned)rc, size_text(required));
	memset(g_pool, FILL, sizeof(g_pool));
	memset(&copy, FILL, sizeof(copy));
	required = UNTOUCHED;
	rc = cellHttpUtilCopyHeader(&copy, &built[0], g_pool, sizeof(g_pool), &required);
	say("CopyHeader rc=0x%08x required=%s name=%s value=%s", (unsigned)rc, size_text(required),
	    placed(copy.name, g_pool, sizeof(g_pool)), placed(copy.value, g_pool, sizeof(g_pool)));
	required = UNTOUCHED;
	rc = cellHttpUtilCopyHeader(&copy, &built[0], g_pool, 5, &required);
	say("CopyHeader short rc=0x%08x required=%s", (unsigned)rc, size_text(required));
	memset(&copy, FILL, sizeof(copy));
	required = UNTOUCHED;
	rc = cellHttpUtilCopyHeader(&copy, &valueless, g_pool, sizeof(g_pool), &required);
	say("CopyHeader no value rc=0x%08x required=%s name=%s value=%s", (unsigned)rc, size_text(required),
	    placed(copy.name, g_pool, sizeof(g_pool)), placed(copy.value, g_pool, sizeof(g_pool)));
	say("CopyHeader NULL src rc=0x%08x", (unsigned)cellHttpUtilCopyHeader(&copy, NULL, g_pool, sizeof(g_pool), &required));

	static const char *const appended[] = {"more", "", NULL};
	for (unsigned i = 0; i < 3; ++i)
		for (unsigned h = 0; h < 2; ++h) {
			required = UNTOUCHED;
			rc = cellHttpUtilAppendHeaderValue(NULL, &built[h], appended[i], NULL, 0, &required);
			say("AppendHeaderValue %u \"%s\" size rc=0x%08x required=%s", h, appended[i] != NULL ? appended[i] : "(null)",
			    (unsigned)rc, size_text(required));
			memset(g_pool, FILL, sizeof(g_pool));
			memset(&copy, FILL, sizeof(copy));
			required = UNTOUCHED;
			rc = cellHttpUtilAppendHeaderValue(&copy, &built[h], appended[i], g_pool, sizeof(g_pool), &required);
			say("AppendHeaderValue %u \"%s\" rc=0x%08x required=%s name=%s value=%s", h,
			    appended[i] != NULL ? appended[i] : "(null)", (unsigned)rc, size_text(required),
			    rc == 0 ? placed(copy.name, g_pool, sizeof(g_pool)) : "-", rc == 0 ? placed(copy.value, g_pool, sizeof(g_pool)) : "-");
		}
	required = UNTOUCHED;
	rc = cellHttpUtilAppendHeaderValue(&copy, &built[0], "more", g_pool, 8, &required);
	say("AppendHeaderValue short rc=0x%08x required=%s", (unsigned)rc, size_text(required));

	CellHttpStatusLine line_in = {"HTTP", 1, 1, "OK", 200, {0}};
	CellHttpStatusLine line_out;
	required = UNTOUCHED;
	rc = cellHttpUtilCopyStatusLine(NULL, &line_in, NULL, 0, &required);
	say("CopyStatusLine size rc=0x%08x required=%s", (unsigned)rc, size_text(required));
	memset(g_pool, FILL, sizeof(g_pool));
	memset(&line_out, FILL, sizeof(line_out));
	required = UNTOUCHED;
	rc = cellHttpUtilCopyStatusLine(&line_out, &line_in, g_pool, sizeof(g_pool), &required);
	say("CopyStatusLine rc=0x%08x required=%s protocol=%s %u.%u code=%d reason=%s", (unsigned)rc, size_text(required),
	    placed(line_out.protocol, g_pool, sizeof(g_pool)), (unsigned)line_out.majorVersion,
	    (unsigned)line_out.minorVersion, (int)line_out.statusCode, placed(line_out.reasonPhrase, g_pool, sizeof(g_pool)));
	required = UNTOUCHED;
	rc = cellHttpUtilCopyStatusLine(&line_out, &line_in, g_pool, 4, &required);
	say("CopyStatusLine short rc=0x%08x required=%s", (unsigned)rc, size_text(required));
	CellHttpStatusLine noreason = {"HTTP", 1, 0, NULL, 204, {0}};
	memset(&line_out, FILL, sizeof(line_out));
	required = UNTOUCHED;
	rc = cellHttpUtilCopyStatusLine(&line_out, &noreason, g_pool, sizeof(g_pool), &required);
	say("CopyStatusLine no reason rc=0x%08x required=%s protocol=%s reason=%s", (unsigned)rc, size_text(required),
	    placed(line_out.protocol, g_pool, sizeof(g_pool)), placed(line_out.reasonPhrase, g_pool, sizeof(g_pool)));
	say("CopyStatusLine NULL src rc=0x%08x",
	    (unsigned)cellHttpUtilCopyStatusLine(&line_out, NULL, g_pool, sizeof(g_pool), &required));
}

void util_probe(void)
{
	escaping();
	base64();
	uris();
	lines();
}
