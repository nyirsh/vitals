/* The probe's proxy and cache half: requests through server.py's proxy (port 18081), plain and
 * https (through CONNECT), from libhttp's proxy and a client's, and the HTTP cache's functions
 * with requests a cache could answer. main.c runs it after the authentication half; one
 * "probe: " line a result */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cell/http.h>

#define HOST "127.0.0.1"
#define PORT 18080
#define PROXY_PORT 18081

/* Sony's, not in PS3DK's headers (the probe's stub has them) */
int cellHttpSetProxy(const CellHttpUri *proxy);
int cellHttpInitCache(uint32_t size);
int cellHttpEndCache(void);
int cellHttpFlushCache(void);
int cellHttpGetCacheInfo(uint32_t *info);
int cellHttpEndExternalCache(void);
int cellHttpClientSetCacheStatus(CellHttpClientId client, bool enable);
/* main.c's */
char *read_ca(size_t *size);

static void say(const char *format, ...) __attribute__((format(printf, 1, 2)));
static void say(const char *format, ...)
{
	char text[700];
	va_list arguments;
	va_start(arguments, format);
	vsnprintf(text, sizeof(text), format, arguments);
	va_end(arguments);
	printf("probe: %s\n", text);
}

/* A body's lines, each as its own "probe: " line after name */
static void say_body(const char *name, const char *body)
{
	char copy[2048];
	snprintf(copy, sizeof(copy), "%s", body);
	for (char *line = copy; line != NULL && *line != '\0';) {
		char *end = strchr(line, '\n');
		if (end != NULL)
			*end = '\0';
		if (strlen(line) > 160)
			line[160] = '\0';
		if (*line != '\0')
			say("%s | %s", name, line);
		line = end != NULL ? end + 1 : NULL;
	}
}

static void fetch(const char *name, CellHttpClientId client, const char *method, const char *scheme, const char *host,
                  unsigned port, const char *path, const void *data, size_t size, int show)
{
	CellHttpUri uri = {scheme, host, "", "", path, port, {0}};
	CellHttpTransId transaction = 0;
	int rc = cellHttpCreateTransaction(&transaction, client, method, &uri);
	if (rc >= 0 && data != NULL)
		cellHttpRequestSetContentLength(transaction, size);
	size_t sent = 0;
	if (rc >= 0)
		rc = cellHttpSendRequest(transaction, data, data != NULL ? size : 0, &sent);
	int send_rc = rc;
	int32_t code = 0;
	if (rc >= 0)
		rc = cellHttpResponseGetStatusCode(transaction, &code);
	char body[2048];
	size_t have = 0;
	while (rc >= 0 && have < sizeof(body) - 1) {
		size_t got = 0;
		rc = cellHttpRecvResponse(transaction, body + have, sizeof(body) - 1 - have, &got);
		if (rc < 0 || got == 0)
			break;
		have += got;
	}
	body[have] = '\0';
	say("%s %s %s://%s:%u%s send rc=0x%08x rc=0x%08x HTTP %d", name, method, scheme, host, port, path, (unsigned)send_rc,
	    (unsigned)rc, (int)code);
	if (show)
		say_body(name, body);
	if (transaction != 0)
		cellHttpDestroyTransaction(transaction);
}

static void proxy_log(const char *name, CellHttpClientId client)
{
	CellHttpUri uri = {"http", HOST, "", "", "/proxylog", PORT, {0}};
	CellHttpTransId transaction = 0;
	if (cellHttpCreateTransaction(&transaction, client, "GET", &uri) < 0)
		return;
	size_t sent = 0;
	int rc = cellHttpSendRequest(transaction, NULL, 0, &sent);
	char body[2048];
	size_t have = 0;
	while (rc >= 0 && have < sizeof(body) - 1) {
		size_t got = 0;
		rc = cellHttpRecvResponse(transaction, body + have, sizeof(body) - 1 - have, &got);
		if (rc < 0 || got == 0)
			break;
		have += got;
	}
	body[have] = '\0';
	say_body(name, body);
	cellHttpDestroyTransaction(transaction);
}

static void cache_info(const char *name)
{
	uint32_t info[4] = {0xa5a5a5a5u, 0xa5a5a5a5u, 0xa5a5a5a5u, 0xa5a5a5a5u};
	int rc = cellHttpGetCacheInfo(info);
	say("%s cache info rc=0x%08x %u %s %s", name, (unsigned)rc, (unsigned)info[0],
	    info[1] == 0xa5a5a5a5u ? "untouched" : info[1] == 0 ? "0 used" : "some used",
	    info[2] == 0xa5a5a5a5u ? "third untouched" : "third written");
}


/* https through the proxy's CONNECT tunnel, to the probe's TLS ports: main.c's https half runs it
 * while cellHttpsInit is in force (Sony's refuses a second one after cellHttpsEnd) */
void proxy_https_probe(void)
{
	CellHttpUri proxy = {"http", HOST, "", "", "/", PROXY_PORT, {0}};
	CellHttpClientId secure = 0, direct = 0;
	cellHttpCreateClient(&secure);
	cellHttpCreateClient(&direct);
	say("proxy client set rc=0x%08x", (unsigned)cellHttpClientSetProxy(secure, &proxy));
	fetch("proxied https", secure, "GET", "https", HOST, 18443, "/plain", NULL, 0, 1);
	fetch("proxied https again", secure, "GET", "https", HOST, 18443, "/plain", NULL, 0, 1);
	fetch("proxied https wrong host", secure, "GET", "https", HOST, 18444, "/plain", NULL, 0, 1);
	proxy_log("proxy log", direct);
	CellHttpUri user_proxy = {"http", HOST, "puser", "psecret", "/", PROXY_PORT, {0}};
	cellHttpClientSetProxy(secure, &user_proxy);
	fetch("proxy with user https", secure, "GET", "https", HOST, 18443, "/plain", NULL, 0, 0);
	proxy_log("proxy log with user", direct);
	CellHttpUri dead_proxy = {"http", HOST, "", "", "/", 1, {0}};
	cellHttpClientSetProxy(secure, &dead_proxy);
	fetch("dead proxy https", secure, "GET", "https", HOST, 18443, "/plain", NULL, 0, 0);
	cellHttpDestroyClient(secure);
	cellHttpDestroyClient(direct);
}

void proxy_cache_probe(void)
{
	/* ---- proxies ---- */
	CellHttpUri proxy = {"http", HOST, "", "", "/", PROXY_PORT, {0}};
	say("proxy set rc=0x%08x", (unsigned)cellHttpSetProxy(&proxy));
	CellHttpClientId client = 0;
	cellHttpCreateClient(&client);
	cellHttpSetProxy(NULL);
	fetch("proxied", client, "GET", "http", "proxied.example", 80, "/a/b?c=d", NULL, 0, 1);
	fetch("proxied port", client, "GET", "http", "proxied.example", 8080, "/x", NULL, 0, 1);
	fetch("proxied post", client, "POST", "http", "proxied.example", 80, "/form", "a=1", 3, 1);
	fetch("proxied head", client, "HEAD", "http", "proxied.example", 80, "/h", NULL, 0, 0);
	cellHttpClientSetKeepAlive(client, false);
	fetch("proxied no keep-alive", client, "GET", "http", "proxied.example", 80, "/k", NULL, 0, 1);
	cellHttpClientSetKeepAlive(client, true);

	CellHttpClientId direct = 0;
	cellHttpCreateClient(&direct);
	CellHttpUri user_proxy = {"http", HOST, "puser", "psecret", "/", PROXY_PORT, {0}};
	cellHttpClientSetProxy(client, &user_proxy);
	fetch("proxy with user", client, "GET", "http", "proxied.example", 80, "/u", NULL, 0, 1);
	CellHttpUri dead_proxy = {"http", HOST, "", "", "/", 1, {0}};
	cellHttpClientSetProxy(client, &dead_proxy);
	fetch("dead proxy", client, "GET", "http", "proxied.example", 80, "/d", NULL, 0, 0);
	cellHttpClientSetProxy(client, NULL);
	fetch("proxy cleared", client, "GET", "http", HOST, PORT, "/plain", NULL, 0, 1);
	cellHttpDestroyClient(client);


	/* ---- the cache ---- */
	cache_info("before init");
	say("cache flush before init rc=0x%08x", (unsigned)cellHttpFlushCache());
	say("cache end before init rc=0x%08x", (unsigned)cellHttpEndCache());
	say("cache end external before init rc=0x%08x", (unsigned)cellHttpEndExternalCache());
	say("cache init rc=0x%08x", (unsigned)cellHttpInitCache(64 * 1024));
	say("cache init again rc=0x%08x", (unsigned)cellHttpInitCache(64 * 1024));
	cache_info("after init");
	say("cache info NULL rc=0x%08x", (unsigned)cellHttpGetCacheInfo(NULL));
	CellHttpClientId cached = 0;
	cellHttpCreateClient(&cached);
	fetch("cache default 1", cached, "GET", "http", HOST, PORT, "/cache/full", NULL, 0, 1);
	fetch("cache default 2", cached, "GET", "http", HOST, PORT, "/cache/full", NULL, 0, 1);
	say("cache status rc=0x%08x", (unsigned)cellHttpClientSetCacheStatus(cached, true));
	say("cache status bad rc=0x%08x", (unsigned)cellHttpClientSetCacheStatus((CellHttpClientId)0x10, true));
	static const char *const kinds[] = {"full", "lm", "maxage", "plain", "etag", "nocache", "nostore", "private",
	                                    "pragma", "expires", "s304", "e304"};
	for (unsigned i = 0; i < sizeof(kinds) / sizeof(kinds[0]); ++i) {
		char path[32], name[48];
		snprintf(path, sizeof(path), "/cache/%s", kinds[i]);
		for (int round = 1; round <= 3; ++round) {
			snprintf(name, sizeof(name), "cache %s %d", kinds[i], round);
			fetch(name, cached, "GET", "http", HOST, PORT, path, NULL, 0, 1);
		}
		snprintf(name, sizeof(name), "%s", kinds[i]);
		cache_info(name);
	}
	fetch("cache full head", cached, "HEAD", "http", HOST, PORT, "/cache/full", NULL, 0, 0);
	fetch("cache full post", cached, "POST", "http", HOST, PORT, "/cache/full", "a", 1, 1);
	say("cache flush rc=0x%08x", (unsigned)cellHttpFlushCache());
	cache_info("after flush");
	fetch("cache after flush", cached, "GET", "http", HOST, PORT, "/cache/s304", NULL, 0, 1);
	CellHttpClientId other = 0;
	cellHttpCreateClient(&other);
	cellHttpClientSetCacheStatus(other, true);
	fetch("cache other client", other, "GET", "http", HOST, PORT, "/cache/s304", NULL, 0, 1);
	cellHttpClientSetCacheStatus(cached, false);
	fetch("cache off", cached, "GET", "http", HOST, PORT, "/cache/s304", NULL, 0, 1);
	cellHttpClientSetCacheStatus(cached, true);
	fetch("cache big 1", cached, "GET", "http", HOST, PORT, "/cache/big", NULL, 0, 0);
	cache_info("big");
	fetch("cache big 2", cached, "GET", "http", HOST, PORT, "/cache/big", NULL, 0, 0);
	say("cache end rc=0x%08x", (unsigned)cellHttpEndCache());
	say("cache end again rc=0x%08x", (unsigned)cellHttpEndCache());
	cache_info("after end");
	fetch("cache ended", cached, "GET", "http", HOST, PORT, "/cache/s304", NULL, 0, 1);
	say("cache init small rc=0x%08x", (unsigned)cellHttpInitCache(16));
	cache_info("small");
	fetch("cache small 1", cached, "GET", "http", HOST, PORT, "/cache/s304", NULL, 0, 1);
	fetch("cache small 2", cached, "GET", "http", HOST, PORT, "/cache/s304", NULL, 0, 1);
	cellHttpEndCache();
	say("cache init 0 rc=0x%08x", (unsigned)cellHttpInitCache(0));
	cellHttpEndCache();
	cellHttpDestroyClient(other);
	cellHttpDestroyClient(cached);
	cellHttpDestroyClient(direct);
}
