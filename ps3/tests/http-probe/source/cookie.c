/* The probe's cookie half: the cookie store as Sony's libhttp keeps it, through server.py's
 * /setcookie/<name> paths and the Cookie header /echo shows back; the send and receive callbacks,
 * GetCookie, export and import, the flushes and AddCookieWithClientId (main.c runs it after the
 * util half). One "probe: " line a result */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <cell/http.h>

#define HOST "127.0.0.1"
#define PORT 18080
#define FILL 0xa5
#define UNTOUCHED ((size_t)0xa5a5a5a5u)

/* Sony's, not in PS3DK's headers (the stub has them) */
int cellHttpGetCookie(const CellHttpUri *uri, char *buffer, size_t size, size_t *required);
int cellHttpCookieFlush(void);
int cellHttpCookieExport(void *buffer, size_t size, size_t *exported);
int cellHttpCookieImport(const void *buffer, size_t size);

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

static const char *bytes(const void *data, size_t length)
{
	static char out[2][520];
	static int which;
	char *text = out[which ^= 1];
	const unsigned char *at = data;
	size_t used = 0;
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

/* A Cookie value's cookies sorted: the order Sony's sends them in comes from its store's hash and
 * sort, which vitals' doesn't copy (it sends them as RFC 6265 says), so the probe compares sets */
static const char *sorted(const char *value)
{
	static char out[4][600];
	static int which;
	char *text = out[which = (which + 1) & 3];
	char copy[600], *items[64];
	int count = 0;
	snprintf(copy, sizeof(copy), "%s", value);
	for (char *at = copy; at != NULL && count < 64;) {
		items[count++] = at;
		char *end = strstr(at, "; ");
		if (end != NULL) {
			*end = '\0';
			at = end + 2;
		} else
			at = NULL;
	}
	for (int i = 1; i < count; ++i)
		for (int j = i; j > 0 && strcmp(items[j - 1], items[j]) > 0; --j) {
			char *swap = items[j];
			items[j] = items[j - 1];
			items[j - 1] = swap;
		}
	text[0] = '\0';
	for (int i = 0; i < count; ++i) {
		if (i > 0)
			strcat(text, "; ");
		strncat(text, items[i], sizeof(out[0]) - strlen(text) - 3);
	}
	return text;
}

/* ---- the callbacks ---- */

static int g_send_answer, g_recv_answer, g_send_calls, g_recv_calls;

static int send_callback(CellHttpTransId transaction, const CellHttpUri *uri, const char *value, void *argument)
{
	(void)transaction;
	++g_send_calls;
	{
		__typeof__((g_send_calls) + 0) say_0 = g_send_calls;
		__typeof__((uri != NULL && uri->hostname != NULL ? uri->hostname : "-") + 0) say_1 = uri != NULL && uri->hostname != NULL ? uri->hostname : "-";
		__typeof__((uri != NULL && uri->path != NULL ? uri->path : "-") + 0) say_2 = uri != NULL && uri->path != NULL ? uri->path : "-";
		__typeof__((value != NULL ? bytes(sorted(value), strlen(value)) : "(null)") + 0) say_3 = value != NULL ? bytes(sorted(value), strlen(value)) : "(null)";
		say("cookie send callback %d: %s %s \"%s\" argument %s -> %d", say_0, say_1, say_2, say_3, argument == &g_send_answer ? "ok" : "wrong", g_send_answer);
	}
	return g_send_answer;
}

static int recv_callback(CellHttpTransId transaction, const CellHttpUri *uri, const char *value, void *argument)
{
	(void)transaction;
	++g_recv_calls;
	{
		__typeof__((g_recv_calls) + 0) say_0 = g_recv_calls;
		__typeof__((uri != NULL && uri->hostname != NULL ? uri->hostname : "-") + 0) say_1 = uri != NULL && uri->hostname != NULL ? uri->hostname : "-";
		__typeof__((uri != NULL && uri->path != NULL ? uri->path : "-") + 0) say_2 = uri != NULL && uri->path != NULL ? uri->path : "-";
		__typeof__((value != NULL ? bytes(value, strlen(value)) : "(null)") + 0) say_3 = value != NULL ? bytes(value, strlen(value)) : "(null)";
		say("cookie recv callback %d: %s %s \"%s\" argument %s -> %d", say_0, say_1, say_2, say_3, argument == &g_recv_answer ? "ok" : "wrong", g_recv_answer);
	}
	return g_recv_answer;
}

/* ---- requests ---- */

/* A GET, its status, and the Cookie lines /echo sent back (or "none") */
static void fetch(const char *name, CellHttpClientId client, const char *path)
{
	CellHttpUri uri = {"http", HOST, "", "", path, PORT, {0}};
	CellHttpTransId transaction = 0;
	int rc = cellHttpCreateTransaction(&transaction, client, "GET", &uri);
	if (rc < 0) {
		say("%s %s create rc=0x%08x", name, path, (unsigned)rc);
		return;
	}
	size_t sent = 0;
	rc = cellHttpSendRequest(transaction, NULL, 0, &sent);
	int32_t code = 0;
	if (rc >= 0)
		rc = cellHttpResponseGetStatusCode(transaction, &code);
	char body[1024];
	size_t have = 0;
	while (rc >= 0 && have < sizeof(body) - 1) {
		size_t got = 0;
		rc = cellHttpRecvResponse(transaction, body + have, sizeof(body) - 1 - have, &got);
		if (rc < 0 || got == 0)
			break;
		have += got;
	}
	body[have] = '\0';
	char cookies[400] = "";
	for (char *line = body; line != NULL && *line != '\0';) {
		char *end = strchr(line, '\n');
		if (end != NULL)
			*end = '\0';
		if (strncmp(line, "Cookie: ", 8) == 0 && strlen(cookies) + strlen(line) + 3 < sizeof(cookies)) {
			if (cookies[0] != '\0')
				strcat(cookies, " | ");
			strcat(cookies, "Cookie: ");
			strcat(cookies, sorted(line + 8));
		}
		line = end != NULL ? end + 1 : NULL;
	}
	{
		__typeof__((name) + 0) say_0 = name;
		__typeof__((path) + 0) say_1 = path;
		__typeof__(((unsigned)rc) + 0) say_2 = (unsigned)rc;
		__typeof__(((int)code) + 0) say_3 = (int)code;
		__typeof__((strncmp(path, "/setcookie/", 11) == 0 && strcmp(path, "/setcookie/echo") != 0 ? "" : cookies[0] != '\0' ? cookies : "no cookie") + 0) say_4 = strncmp(path, "/setcookie/", 11) == 0 && strcmp(path, "/setcookie/echo") != 0 ? "" : cookies[0] != '\0' ? cookies : "no cookie";
		say("%s %s rc=0x%08x HTTP %d %s", say_0, say_1, say_2, say_3, say_4);
	}
	cellHttpDestroyTransaction(transaction);
}

/* /echo's header names, in order, to see where Cookie goes */
static void header_order(const char *name, CellHttpClientId client)
{
	CellHttpUri uri = {"http", HOST, "", "", "/setcookie/echo", PORT, {0}};
	CellHttpTransId transaction = 0;
	if (cellHttpCreateTransaction(&transaction, client, "GET", &uri) < 0)
		return;
	CellHttpHeader extra = {"X-Request", "1"};
	cellHttpRequestAddHeader(transaction, &extra);
	size_t sent = 0;
	int rc = cellHttpSendRequest(transaction, NULL, 0, &sent);
	char body[1024];
	size_t have = 0;
	while (rc >= 0 && have < sizeof(body) - 1) {
		size_t got = 0;
		rc = cellHttpRecvResponse(transaction, body + have, sizeof(body) - 1 - have, &got);
		if (rc < 0 || got == 0)
			break;
		have += got;
	}
	body[have] = '\0';
	char names[300] = "";
	char *line = strchr(body, '\n');
	while (line != NULL && line[1] != '\0' && line[1] != '\n') {
		++line;
		char *colon = strchr(line, ':');
		char *end = strchr(line, '\n');
		if (colon != NULL && (end == NULL || colon < end) && strlen(names) + (size_t)(colon - line) + 2 < sizeof(names)) {
			strncat(names, line, (size_t)(colon - line));
			strcat(names, ",");
		}
		line = end;
	}
	say("%s header order rc=0x%08x %s", name, (unsigned)rc, names);
	cellHttpDestroyTransaction(transaction);
}

static void get_cookie(const char *name, const char *path)
{
	CellHttpUri uri = {"http", HOST, "", "", path, PORT, {0}};
	char buffer[600];
	size_t required = UNTOUCHED;
	int rc = cellHttpGetCookie(&uri, NULL, 0, &required);
	size_t need = required;
	say("%s GetCookie %s size rc=0x%08x required=%u", name, path, (unsigned)rc,
	    required == UNTOUCHED ? 0xa5a5a5a5u : (unsigned)required);
	memset(buffer, FILL, sizeof(buffer));
	required = UNTOUCHED;
	rc = cellHttpGetCookie(&uri, buffer, sizeof(buffer), &required);
	size_t text = rc == 0 ? strlen(buffer) : 0;
	{
		__typeof__((name) + 0) say_0 = name;
		__typeof__((path) + 0) say_1 = path;
		__typeof__(((unsigned)rc) + 0) say_2 = (unsigned)rc;
		__typeof__((required == UNTOUCHED ? 0xa5a5a5a5u : (unsigned)required) + 0) say_3 = required == UNTOUCHED ? 0xa5a5a5a5u : (unsigned)required;
		__typeof__((rc == 0 ? sorted(buffer) : "-") + 0) say_4 = rc == 0 ? sorted(buffer) : "-";
		__typeof__((rc == 0 && required != UNTOUCHED && required < sizeof(buffer) ? bytes(buffer + text, required + 1 - text) : "-") + 0) say_5 = rc == 0 && required != UNTOUCHED && required < sizeof(buffer) ? bytes(buffer + text, required + 1 - text) : "-";
		say("%s GetCookie %s rc=0x%08x required=%u \"%s\" then \"%s\"", say_0, say_1, say_2, say_3, say_4, say_5);
	}
	if (rc == 0 && need != UNTOUCHED && need > 1) {
		required = UNTOUCHED;
		rc = cellHttpGetCookie(&uri, buffer, need - 1, &required);
		say("%s GetCookie %s short rc=0x%08x required=%u", name, path, (unsigned)rc,
		    required == UNTOUCHED ? 0xa5a5a5a5u : (unsigned)required);
	}
}

/* An export, shown 100 bytes a line */
static size_t export_store(const char *name, CellHttpClientId client, int with_client, unsigned char *buffer, size_t size)
{
	size_t exported = UNTOUCHED;
	int rc = with_client ? cellHttpCookieExportWithClientId(NULL, 0, &exported, client)
	                     : cellHttpCookieExport(NULL, 0, &exported);
	say("%s size rc=0x%08x exported=%u", name, (unsigned)rc, exported == UNTOUCHED ? 0xa5a5a5a5u : (unsigned)exported);
	size_t need = exported;
	if (need != UNTOUCHED && need > 1 && need + 8 <= size) {
		memset(buffer, FILL, size);
		exported = UNTOUCHED;
		rc = with_client ? cellHttpCookieExportWithClientId(buffer, need - 1, &exported, client)
		                 : cellHttpCookieExport(buffer, need - 1, &exported);
		/* Sony's writes the whole export past the buffer's end; only what's inside it is shown */
		{
			__typeof__((name) + 0) say_0 = name;
			__typeof__(((unsigned)rc) + 0) say_1 = (unsigned)rc;
			__typeof__((exported == UNTOUCHED ? 0xa5a5a5a5u : (unsigned)exported) + 0) say_2 = exported == UNTOUCHED ? 0xa5a5a5a5u : (unsigned)exported;
			__typeof__((bytes(buffer + need - 4, 3)) + 0) say_3 = bytes(buffer + need - 4, 3);
			say("%s short rc=0x%08x exported=%u last bytes \"%s\"", say_0, say_1, say_2, say_3);
		}
	}
	memset(buffer, FILL, size);
	exported = UNTOUCHED;
	rc = with_client ? cellHttpCookieExportWithClientId(buffer, size, &exported, client)
	                 : cellHttpCookieExport(buffer, size, &exported);
	say("%s rc=0x%08x exported=%u", name, (unsigned)rc, exported == UNTOUCHED ? 0xa5a5a5a5u : (unsigned)exported);
	if (rc == 0 && exported != UNTOUCHED)
		for (size_t at = 0; at < exported && at < 1200; at += 100)
			{
				__typeof__((name) + 0) say_0 = name;
				__typeof__(((unsigned)at) + 0) say_1 = (unsigned)at;
				__typeof__((bytes(buffer + at, exported - at < 100 ? exported - at : 100)) + 0) say_2 = bytes(buffer + at, exported - at < 100 ? exported - at : 100);
				say("%s %u: \"%s\"", say_0, say_1, say_2);
			}
	return rc == 0 && exported != UNTOUCHED ? exported : 0;
}

void cookie_probe(void)
{
	static char pool[64 * 1024];
	say("cookies InitCookie rc=0x%08x", (unsigned)cellHttpInitCookie(pool, sizeof(pool)));

	CellHttpClientId off = 0, on = 0, other = 0;
	cellHttpCreateClient(&off);
	cellHttpCreateClient(&on);
	cellHttpCreateClient(&other);
	bool status = true;
	{
		__typeof__(((unsigned)cellHttpClientGetCookieStatus(off, &status)) + 0) say_0 = (unsigned)cellHttpClientGetCookieStatus(off, &status);
		say("cookies default status rc=0x%08x %d", say_0, status ? 1 : 0);
	}
	say("cookies set status rc=0x%08x", (unsigned)cellHttpClientSetCookieStatus(on, true));
	cellHttpClientSetCookieStatus(other, true);

	/* With cookies off, nothing is kept or sent */
	fetch("off", off, "/setcookie/session");
	fetch("off", off, "/echo");
	fetch("off", off, "/setcookie/echo");
	get_cookie("off", "/setcookie/");

	say("cookies send callback rc=0x%08x", (unsigned)cellHttpClientSetCookieSendCallback(on, send_callback, &g_send_answer));
	say("cookies recv callback rc=0x%08x", (unsigned)cellHttpClientSetCookieRecvCallback(on, recv_callback, &g_recv_answer));

	static const char *const steps[] = {"session", "path",   "expires",  "domain",  "domainok", "secure",
	                                    "httponly", "two",   "spaces",   "noequal", "quoted",   "subpath",
	                                    "replace",  "attributes"};
	for (unsigned i = 0; i < sizeof(steps) / sizeof(steps[0]); ++i) {
		char path[64];
		snprintf(path, sizeof(path), "/setcookie/%s", steps[i]);
		fetch("on", on, path);
		fetch("on", on, "/echo");
		fetch("on", on, "/cookie/echo");
		fetch("on", on, "/cookie/sub/echo");
		fetch("on", on, "/setcookie/echo");
	}
	/* Another client with cookies on, and the one with them off: one store, or one each? */
	fetch("other", other, "/echo");
	fetch("off", off, "/echo");
	get_cookie("on", "/");
	get_cookie("on", "/cookie/");
	get_cookie("on", "/cookie/sub/x");
	char buffer[2048];
	size_t required = UNTOUCHED;
	get_cookie("on", "/nothing");
	get_cookie("on", "/setcookie/");
	fetch("other", other, "/setcookie/echo");
	header_order("on", on);
	header_order("off", off);
	CellHttpUri secure_uri = {"https", HOST, "", "", "/setcookie/", 18443, {0}};
	required = UNTOUCHED;
	memset(buffer, FILL, sizeof(buffer));
	int secure_rc = cellHttpGetCookie(&secure_uri, buffer, sizeof(buffer), &required);
	{
		__typeof__(((unsigned)secure_rc) + 0) say_0 = (unsigned)secure_rc;
		__typeof__((secure_rc == 0 ? sorted(buffer) : "-") + 0) say_1 = secure_rc == 0 ? sorted(buffer) : "-";
		say("on GetCookie https /setcookie/ rc=0x%08x \"%s\"", say_0, say_1);
	}
	fetch("persist", on, "/setcookie/persist");
	fetch("persist", on, "/setcookie/prefix");
	fetch("persist", on, "/setcookie/echo");
	fetch("persist", on, "/cookie/echo");
	fetch("persist", on, "/cookie/sub/echo");
	fetch("persist", on, "/echo");
	CellHttpUri https_uri = {"https", HOST, "", "", "/", 18443, {0}};
	required = UNTOUCHED;
	{
		__typeof__(((unsigned)cellHttpGetCookie(&https_uri, buffer, sizeof(buffer), &required)) + 0) say_0 = (unsigned)cellHttpGetCookie(&https_uri, buffer, sizeof(buffer), &required);
		say("on GetCookie https rc=0x%08x required=%u", say_0, required == UNTOUCHED ? 0xa5a5a5a5u : (unsigned)required);
	}
	say("GetCookie NULL uri rc=0x%08x", (unsigned)cellHttpGetCookie(NULL, buffer, sizeof(buffer), &required));
	CellHttpUri path_uri = {"http", HOST, "", "", "/", PORT, {0}};
	say("GetCookie nothing rc=0x%08x", (unsigned)cellHttpGetCookie(&path_uri, NULL, 0, NULL));

	/* Export, flush, import */
	static unsigned char saved[4096], saved_client[4096];
	size_t saved_size = export_store("Export", 0, 0, saved, sizeof(saved));
	size_t client_size = export_store("ExportWithClientId on", on, 1, saved_client, sizeof(saved_client));
	export_store("ExportWithClientId off", off, 1, (unsigned char *)buffer, sizeof(buffer));
	export_store("ExportWithClientId other", other, 1, (unsigned char *)buffer, sizeof(buffer));
	size_t exported = 0;
	say("Export NULL size rc=0x%08x", (unsigned)cellHttpCookieExport(buffer, sizeof(buffer), NULL));
	say("Export tiny rc=0x%08x", (unsigned)cellHttpCookieExport(buffer, 10, &exported));
	say("ExportWithClientId bad client rc=0x%08x",
	    (unsigned)cellHttpCookieExportWithClientId(buffer, sizeof(buffer), &exported, (CellHttpClientId)0x10));

	say("SessionCookieFlush rc=0x%08x", (unsigned)cellHttpSessionCookieFlush(on));
	fetch("after session flush", on, "/echo");
	fetch("after session flush", on, "/cookie/echo");
	fetch("after session flush", on, "/setcookie/echo");
	say("SessionCookieFlush bad client rc=0x%08x", (unsigned)cellHttpSessionCookieFlush((CellHttpClientId)0x10));
	say("CookieFlush rc=0x%08x", (unsigned)cellHttpCookieFlush());
	fetch("after flush", on, "/echo");
	fetch("after flush", on, "/cookie/echo");
	fetch("after flush", on, "/setcookie/echo");
	say("Import rc=0x%08x", (unsigned)cellHttpCookieImport(saved, saved_size));
	fetch("after import", on, "/echo");
	fetch("after import", on, "/cookie/echo");
	fetch("after import", on, "/cookie/sub/echo");
	fetch("after import", on, "/setcookie/echo");
	cellHttpCookieFlush();
	say("ImportWithClientId rc=0x%08x", (unsigned)cellHttpCookieImportWithClientId(saved_client, client_size, on));
	fetch("after client import", on, "/echo");
	fetch("after client import", other, "/echo");
	fetch("after client import", on, "/setcookie/echo");
	say("Import garbage rc=0x%08x", (unsigned)cellHttpCookieImport("garbage that isn't an export", 28));
	fetch("after import garbage", on, "/echo");
	say("Import NULL rc=0x%08x", (unsigned)cellHttpCookieImport(NULL, 10));
	fetch("after import null", on, "/echo");
	say("Import empty rc=0x%08x", (unsigned)cellHttpCookieImport(saved, 0));
	fetch("after import empty", on, "/echo");
	say("ImportWithClientId bad client rc=0x%08x",
	    (unsigned)cellHttpCookieImportWithClientId(saved, saved_size, (CellHttpClientId)0x10));
	fetch("after bad imports", on, "/echo");

	/* AddCookieWithClientId */
	cellHttpCookieFlush();
	CellHttpUri add_uri = {"http", HOST, "", "", "/cookie/", PORT, {0}};
	say("AddCookie rc=0x%08x", (unsigned)cellHttpAddCookieWithClientId(&add_uri, "z=26", on));
	say("AddCookie path rc=0x%08x", (unsigned)cellHttpAddCookieWithClientId(&add_uri, "w=23; Path=/", on));
	say("AddCookie other client rc=0x%08x", (unsigned)cellHttpAddCookieWithClientId(&add_uri, "v=22; Path=/", other));
	say("AddCookie no client rc=0x%08x", (unsigned)cellHttpAddCookieWithClientId(&add_uri, "u=21; Path=/", 0));
	CellHttpUri other_host = {"http", "other.example", "", "", "/", 80, {0}};
	say("AddCookie other host rc=0x%08x", (unsigned)cellHttpAddCookieWithClientId(&other_host, "o=1", on));
	CellHttpUri wrong_domain = {"http", HOST, "", "", "/", PORT, {0}};
	say("AddCookie wrong domain rc=0x%08x",
	    (unsigned)cellHttpAddCookieWithClientId(&wrong_domain, "o=2; Domain=other.example", on));
	say("AddCookie NULL uri rc=0x%08x", (unsigned)cellHttpAddCookieWithClientId(NULL, "z=1", on));
	say("AddCookie NULL cookie rc=0x%08x", (unsigned)cellHttpAddCookieWithClientId(&add_uri, NULL, on));
	say("AddCookie empty cookie rc=0x%08x", (unsigned)cellHttpAddCookieWithClientId(&add_uri, "", on));
	say("AddCookie bad client rc=0x%08x", (unsigned)cellHttpAddCookieWithClientId(&add_uri, "z=1", (CellHttpClientId)0x10));
	fetch("after add", on, "/echo");
	fetch("after add", on, "/cookie/echo");
	fetch("after add", other, "/cookie/echo");
	get_cookie("after add", "/cookie/");

	/* The callbacks' answers */
	cellHttpCookieFlush();
	g_recv_answer = -1;
	fetch("recv refusing", on, "/setcookie/two");
	fetch("recv refusing", on, "/setcookie/echo");
	g_recv_answer = 1;
	fetch("recv 1", on, "/setcookie/session");
	fetch("recv 1", on, "/setcookie/echo");
	g_recv_answer = 0;
	fetch("recv 0", on, "/setcookie/two");
	g_send_answer = -1;
	fetch("send refusing", on, "/setcookie/echo");
	g_send_answer = 1;
	fetch("send 1", on, "/setcookie/echo");
	g_send_answer = 0;
	{
		__typeof__(((unsigned)cellHttpClientSetCookieSendCallback(on, NULL, NULL)) + 0) say_0 = (unsigned)cellHttpClientSetCookieSendCallback(on, NULL, NULL);
		__typeof__(((unsigned)cellHttpClientSetCookieRecvCallback(on, NULL, NULL)) + 0) say_1 = (unsigned)cellHttpClientSetCookieRecvCallback(on, NULL, NULL);
		say("cookies clear callbacks rc=0x%08x rc=0x%08x", say_0, say_1);
	}

	/* Max-Age and deleting, after the exports so those stay the same each run */
	fetch("maxage", on, "/setcookie/maxage");
	fetch("maxage", on, "/setcookie/echo");
	fetch("delete", on, "/setcookie/session");
	fetch("delete", on, "/setcookie/delete");
	fetch("delete", on, "/setcookie/echo");

	/* Cookies turned off on the client again, then the store ended */
	cellHttpClientSetCookieStatus(on, false);
	fetch("status off", on, "/setcookie/echo");
	cellHttpClientSetCookieStatus(on, true);
	say("cookies EndCookie rc=0x%08x", (unsigned)cellHttpEndCookie());
	fetch("ended", on, "/setcookie/session");
	fetch("ended", on, "/setcookie/echo");
	required = UNTOUCHED;
	say("ended GetCookie rc=0x%08x", (unsigned)cellHttpGetCookie(&path_uri, buffer, sizeof(buffer), &required));
	say("ended Export rc=0x%08x", (unsigned)cellHttpCookieExport(buffer, sizeof(buffer), &exported));
	say("ended Import rc=0x%08x", (unsigned)cellHttpCookieImport(saved, saved_size));
	say("ended CookieFlush rc=0x%08x", (unsigned)cellHttpCookieFlush());
	say("ended SessionCookieFlush rc=0x%08x", (unsigned)cellHttpSessionCookieFlush(on));
	say("ended AddCookie rc=0x%08x", (unsigned)cellHttpAddCookieWithClientId(&add_uri, "z=1", on));

	/* A fresh store: valueless cookies, how many a host keeps, path prefixes, names' case */
	say("again InitCookie rc=0x%08x", (unsigned)cellHttpInitCookie(pool, sizeof(pool)));
	CellHttpUri set_uri = {"http", HOST, "", "", "/setcookie/x", PORT, {0}};
	fetch("again", on, "/setcookie/noequal");
	say("again AddCookie k5 rc=0x%08x", (unsigned)cellHttpAddCookieWithClientId(&set_uri, "k5", on));
	get_cookie("again valueless", "/setcookie/");
	say("again AddCookie =v rc=0x%08x", (unsigned)cellHttpAddCookieWithClientId(&set_uri, "=v", on));
	get_cookie("again empty name", "/setcookie/");
	cellHttpCookieFlush();
	for (int i = 0; i < 40; ++i) {
		char cookie[32];
		snprintf(cookie, sizeof(cookie), "n%02d=%d; Path=/", i, i);
		int add = cellHttpAddCookieWithClientId(&path_uri, cookie, on);
		if (add != 0)
			say("again AddCookie %d rc=0x%08x", i, (unsigned)add);
	}
	get_cookie("again forty", "/");
	CellHttpUri second_host = {"http", "second.example", "", "", "/", 80, {0}};
	for (int i = 0; i < 5; ++i) {
		char cookie[32];
		snprintf(cookie, sizeof(cookie), "m%02d=%d", i, i);
		cellHttpAddCookieWithClientId(&second_host, cookie, on);
	}
	get_cookie("again forty after second host", "/");
	cellHttpCookieFlush();
	cellHttpAddCookieWithClientId(&path_uri, "pb=1; Path=/cook", on);
	cellHttpAddCookieWithClientId(&path_uri, "pc=1; Path=/cookie/", on);
	cellHttpAddCookieWithClientId(&path_uri, "Aa=1; Path=/", on);
	cellHttpAddCookieWithClientId(&path_uri, "aa=2; Path=/", on);
	cellHttpAddCookieWithClientId(&path_uri, "same=1; Path=/", on);
	cellHttpAddCookieWithClientId(&path_uri, "same=2; Path=/cookie", on);
	cellHttpAddCookieWithClientId(&path_uri, "case=1; PATH=/cookie; DOMAIN=127.0.0.1", on);
	fetch("again", on, "/cookie/echo");
	fetch("again", on, "/cookiex/echo");
	fetch("again", on, "/echo");
	cellHttpEndCookie();
	cellHttpDestroyClient(off);
	cellHttpDestroyClient(on);
	cellHttpDestroyClient(other);
}
