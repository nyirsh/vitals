/* The libhttp probe: exercises Sony's libhttp API and prints one line a result on the TTY, the same
 * way every run, so Sony's libhttp and vitals' (tools/rpcs3_run.sh, VITALS_HTTP) can be diffed
 * (tools/http_probe.sh). Defaults, return codes for bad arguments, and requests to server.py on
 * this machine (127.0.0.1:18080: RPCS3's sockets are the host's). Each line starts "probe: " */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/process.h>

#include <net/net.h>

#include <cell/cell_fs.h>
#include <cell/http.h>
#include <cell/ssl.h>
#include <cell/sysmodule.h>

SYS_PROCESS_PARAM(1001, 0x10000);

/* https through the proxy (proxy.c), run by the https half while cellHttpsInit holds */
void proxy_https_probe(void);
void unnamed_https_probe(void);
/* vitals' additions (additions.c) */
void additions_probe(void);
void additions_https_probe(void);

#define HTTP_POOL_SIZE (512 * 1024)
#define HOST "127.0.0.1"
#define PORT 18080

static void line(const char *format, ...) __attribute__((format(printf, 1, 2)));
static void line(const char *format, ...)
{
	char text[512];
	va_list arguments;
	va_start(arguments, format);
	vsnprintf(text, sizeof(text), format, arguments);
	va_end(arguments);
	printf("probe: %s\n", text);
}

/* Whether memory still holds the probe's 0xa5 fill, whatever a pointer's size */
static int filled(const void *memory, size_t size)
{
	const unsigned char *bytes = memory;
	for (size_t i = 0; i < size; ++i)
		if (bytes[i] != 0xa5)
			return 0;
	return 1;
}

/* Text with its line ends shown, at most 160 characters */
static const char *shown(const char *data, size_t length)
{
	static char out[200];
	size_t used = 0;
	for (size_t i = 0; i < length && used + 3 < sizeof(out) && used < 160; ++i) {
		char c = data[i];
		if (c == '\r')
			out[used++] = '\\', out[used++] = 'r';
		else if (c == '\n')
			out[used++] = '\\', out[used++] = 'n';
		else
			out[used++] = c >= 32 && c < 127 ? c : '?';
	}
	out[used] = '\0';
	return out;
}

static void defaults(CellHttpClientId client)
{
	bool flag = false;
	int64_t usec = -1;
	size_t size = 0;
	int number = -1;
	uint32_t major = 0, minor = 0;
	int32_t version = -1;
	int rc;
	rc = cellHttpClientGetKeepAlive(client, &flag);
	line("default KeepAlive rc=0x%08x %d", rc, flag);
	rc = cellHttpClientGetPipeline(client, &flag);
	line("default Pipeline rc=0x%08x %d", rc, flag);
	rc = cellHttpClientGetAutoRedirect(client, &flag);
	line("default AutoRedirect rc=0x%08x %d", rc, flag);
	rc = cellHttpClientGetAutoAuthentication(client, &flag);
	line("default AutoAuthentication rc=0x%08x %d", rc, flag);
	rc = cellHttpClientGetAuthenticationCacheStatus(client, &flag);
	line("default AuthenticationCacheStatus rc=0x%08x %d", rc, flag);
	rc = cellHttpClientGetCookieStatus(client, &flag);
	line("default CookieStatus rc=0x%08x %d", rc, flag);
	rc = cellHttpClientGetConnectionWaitStatus(client, &flag);
	line("default ConnectionWaitStatus rc=0x%08x %d", rc, flag);
	rc = cellHttpClientGetConnTimeout(client, &usec);
	line("default ConnTimeout rc=0x%08x %lld", rc, (long long)usec);
	rc = cellHttpClientGetRecvTimeout(client, &usec);
	line("default RecvTimeout rc=0x%08x %lld", rc, (long long)usec);
	rc = cellHttpClientGetSendTimeout(client, &usec);
	line("default SendTimeout rc=0x%08x %lld", rc, (long long)usec);
	rc = cellHttpClientGetConnectionWaitTimeout(client, &usec);
	line("default ConnectionWaitTimeout rc=0x%08x %lld", rc, (long long)usec);
	rc = cellHttpClientGetTotalPoolSize(client, &size);
	line("default TotalPoolSize rc=0x%08x %u", rc, (unsigned)size);
	rc = cellHttpClientGetPerHostPoolSize(client, &size);
	line("default PerHostPoolSize rc=0x%08x %u", rc, (unsigned)size);
	rc = cellHttpClientGetPerHostKeepAliveMax(client, &size);
	line("default PerHostKeepAliveMax rc=0x%08x %u", rc, (unsigned)size);
	rc = cellHttpClientGetPerPipelineMax(client, &size);
	line("default PerPipelineMax rc=0x%08x %u", rc, (unsigned)size);
	rc = cellHttpClientGetResponseBufferMax(client, &size);
	line("default ResponseBufferMax rc=0x%08x %u", rc, (unsigned)size);
	rc = cellHttpClientGetRecvBufferSize(client, &number);
	line("default RecvBufferSize rc=0x%08x %d", rc, number);
	rc = cellHttpClientGetSendBufferSize(client, &number);
	line("default SendBufferSize rc=0x%08x %d", rc, number);
	rc = cellHttpClientGetVersion(client, &major, &minor);
	line("default Version rc=0x%08x %u.%u", rc, major, minor);
	rc = cellHttpClientGetSslVersion(client, &version);
	line("default SslVersion rc=0x%08x %d", rc, (int)version);
	rc = cellHttpClientGetMinSslVersion(client, &version);
	line("default MinSslVersion rc=0x%08x %d", rc, (int)version);
	char agent[64] = "";
	size_t required = 0;
	rc = cellHttpClientGetUserAgent(client, NULL, 0, &required);
	line("default UserAgent size rc=0x%08x required=%u", rc, (unsigned)required);
	rc = cellHttpClientGetUserAgent(client, agent, 4, &required);
	line("default UserAgent small rc=0x%08x required=%u", rc, (unsigned)required);
	rc = cellHttpClientGetUserAgent(client, agent, sizeof(agent), &required);
	line("default UserAgent rc=0x%08x \"%s\" required=%u", rc, agent, (unsigned)required);
}

/* The response's status, length, headers and body, read through a small buffer */
static void response(const char *name, CellHttpTransId transaction)
{
	int32_t code = 0;
	uint64_t length = 0;
	int rc = cellHttpResponseGetStatusCode(transaction, &code);
	line("%s status rc=0x%08x %d", name, rc, (int)code);
	rc = cellHttpResponseGetContentLength(transaction, &length);
	line("%s length rc=0x%08x %llu", name, rc, (unsigned long long)length);
	char pool[1024];
	size_t required = 0;
	CellHttpStatusLine status;
	memset(&status, 0, sizeof(status));
	rc = cellHttpResponseGetStatusLine(transaction, &status, pool, sizeof(pool), &required);
	line("%s status line rc=0x%08x %s %u.%u %d \"%s\" required=%u", name, rc, status.protocol ? status.protocol : "-",
	     status.majorVersion, status.minorVersion, (int)status.statusCode,
	     status.reasonPhrase ? status.reasonPhrase : "-", (unsigned)required);
	CellHttpHeader header;
	memset(&header, 0, sizeof(header));
	rc = cellHttpResponseGetHeader(transaction, &header, "X-Probe", NULL, 0, &required);
	line("%s header size rc=0x%08x required=%u", name, rc, (unsigned)required);
	rc = cellHttpResponseGetHeader(transaction, &header, "x-probe", pool, sizeof(pool), &required);
	line("%s header rc=0x%08x %s: %s", name, rc, header.name ? header.name : "-", header.value ? header.value : "-");
	CellHttpHeaderPtr headers = NULL;
	size_t items = 0;
	rc = cellHttpResponseGetAllHeaders(transaction, &headers, &items, pool, sizeof(pool), &required);
	line("%s all headers rc=0x%08x items=%u required=%u", name, rc, (unsigned)items, (unsigned)required);
	for (size_t i = 0; rc >= 0 && headers != NULL && i < items; ++i)
		line("%s header %u %s: %s", name, (unsigned)i, headers[i].name, headers[i].value);
	char body[1024];
	size_t total = 0, received = 0;
	char sizes[256] = "";
	for (int reads = 0; reads < 64; ++reads) {
		rc = cellHttpRecvResponse(transaction, body + total, total + 5 < sizeof(body) ? 5 : sizeof(body) - total,
		                          &received);
		snprintf(sizes + strlen(sizes), sizeof(sizes) - strlen(sizes), "%d/0x%x ", (int)received, (unsigned)rc);
		if (rc < 0 || received == 0)
			break;
		total += received;
	}
	line("%s reads %s", name, sizes);
	line("%s body (%u) \"%s\"", name, (unsigned)total, shown(body, total));
	rc = cellHttpRecvResponse(transaction, body, sizeof(body), &received);
	line("%s read after end rc=0x%08x %u", name, rc, (unsigned)received);
}

/* The SSL getters, after a response */
static void ssl_details(const char *name, CellHttpTransId transaction)
{
	char text[128] = "";
	size_t required = 0;
	int32_t id = -1, effective = -1, algorithm = -1, version = -1;
	int rc = cellHttpTransactionGetSslCipherName(transaction, text, sizeof(text), &required);
	line("%s cipher name rc=0x%08x \"%s\" required=%u", name, rc, rc >= 0 ? text : "-", (unsigned)required);
	rc = cellHttpTransactionGetSslCipherId(transaction, &id);
	line("%s cipher id rc=0x%08x %d", name, rc, (int)id);
	text[0] = '\0';
	rc = cellHttpTransactionGetSslCipherVersion(transaction, text, sizeof(text), &required);
	line("%s cipher version rc=0x%08x \"%s\" required=%u", name, rc, rc >= 0 ? text : "-", (unsigned)required);
	rc = cellHttpTransactionGetSslCipherBits(transaction, &effective, &algorithm);
	line("%s cipher bits rc=0x%08x %d %d", name, rc, (int)effective, (int)algorithm);
	text[0] = '\0';
	rc = cellHttpTransactionGetSslCipherString(transaction, text, sizeof(text));
	line("%s cipher string rc=0x%08x \"%s\"", name, rc, rc >= 0 ? shown(text, strlen(text)) : "-");
	rc = cellHttpTransactionGetSslVersion(transaction, &version);
	line("%s ssl version rc=0x%08x %d", name, rc, (int)version);
	CellHttpSslId session = 0;
	rc = cellHttpTransactionGetSslId(transaction, &session);
	line("%s ssl id rc=0x%08x %s", name, rc, session != 0 ? "id" : "none");
}

static void request_at(CellHttpClientId client, const char *name, const char *method, const char *scheme,
                       unsigned port, const char *path, const void *data, size_t size);

static void request(CellHttpClientId client, const char *name, const char *method, const char *path, const void *data,
                    size_t size)
{
	request_at(client, name, method, "http", PORT, path, data, size);
}

static void request_at(CellHttpClientId client, const char *name, const char *method, const char *scheme,
                       unsigned port, const char *path, const void *data, size_t size)
{
	CellHttpUri uri = {scheme, HOST, "", "", path, port, {0}};
	CellHttpTransId transaction = 0;
	int rc = cellHttpCreateTransaction(&transaction, client, method, &uri);
	line("%s create rc=0x%08x", name, rc);
	if (rc < 0)
		return;
	if (data != NULL) {
		rc = cellHttpRequestSetContentLength(transaction, size);
		line("%s content length rc=0x%08x", name, rc);
	}
	size_t sent = 0;
	rc = cellHttpSendRequest(transaction, data, data != NULL ? size / 2 : 0, &sent);
	line("%s send rc=0x%08x sent=%u", name, rc, (unsigned)sent);
	if (data != NULL && rc >= 0) {
		rc = cellHttpSendRequest(transaction, (const char *)data + size / 2, size - size / 2, &sent);
		line("%s send rest rc=0x%08x sent=%u", name, rc, (unsigned)sent);
	}
	if (rc >= 0) {
		response(name, transaction);
		if (strcmp(scheme, "https") == 0)
			ssl_details(name, transaction);
	}
	rc = cellHttpDestroyTransaction(transaction);
	line("%s destroy rc=0x%08x", name, rc);
}

/* The game's SSL callback: what libhttp gives it, and a set answer */
static int ssl_answer, ssl_calls;
static int ssl_callback(uint32_t error, CellSslCert const certificates[], int count, const char *host, CellHttpSslId id,
                        void *argument)
{
	(void)certificates, (void)id;
	++ssl_calls;
	line("ssl callback %d: flags 0x%08x, %d certificates, host \"%s\", argument %s -> %d", ssl_calls, (unsigned)error,
	     count, host != NULL ? host : "(null)", argument == (void *)&ssl_answer ? "ok" : "wrong", ssl_answer);
	return ssl_answer;
}

/* The probe's CA, which tools/http_probe.sh puts on RPCS3's hdd */
char *read_ca(size_t *size);
char *read_ca(size_t *size)
{
	int fd;
	CellFsStat status;
	*size = 0;
	if (cellFsOpen("/dev_hdd0/vitals-probe/ca.pem", CELL_FS_O_RDONLY, &fd, NULL, 0) != CELL_FS_SUCCEEDED)
		return NULL;
	char *data = NULL;
	if (cellFsFstat(fd, &status) == CELL_FS_SUCCEEDED && (data = malloc((size_t)status.st_size + 1)) != NULL) {
		uint64_t read = 0;
		cellFsRead(fd, data, status.st_size, &read);
		data[read] = '\0';
		*size = (size_t)read;
	}
	cellFsClose(fd);
	return data;
}

static void https(void)
{
	CellHttpClientId client = 0;
	cellHttpCreateClient(&client);
	request_at(client, "https before init", CELL_HTTP_METHOD_GET, "https", PORT + 363, "/plain", NULL, 0);
	size_t size = 0;
	char *ca = read_ca(&size);
	line("ca %s", ca != NULL ? "read" : "missing");
	CellHttpsData list = {ca, (uint32_t)size};
	/* Not cellHttpsInit(1, NULL) or (0, list): Sony's returns 0 for them without making its lock,
	 * and the next https request waits forever on it (in RPCS3) */
	line("HttpsInit rc=0x%08x", cellHttpsInit(1, &list));
	line("HttpsInit again rc=0x%08x", cellHttpsInit(1, &list));
	/* A client made before cellHttpsInit has no SSL state in Sony's libhttp: its first https
	 * request waits forever on a lock that was never made (in RPCS3). Games make theirs after */
	cellHttpDestroyClient(client);
	cellHttpCreateClient(&client);
	request_at(client, "https", CELL_HTTP_METHOD_GET, "https", PORT + 363, "/plain", NULL, 0);
	request_at(client, "https wrong host", CELL_HTTP_METHOD_GET, "https", PORT + 364, "/plain", NULL, 0);
	request_at(client, "https self-signed", CELL_HTTP_METHOD_GET, "https", PORT + 365, "/plain", NULL, 0);
	request_at(client, "https expired", CELL_HTTP_METHOD_GET, "https", PORT + 366, "/plain", NULL, 0);
	line("set ssl callback rc=0x%08x", cellHttpClientSetSslCallback(client, ssl_callback, &ssl_answer));
	ssl_answer = 0;
	request_at(client, "https callback", CELL_HTTP_METHOD_GET, "https", PORT + 363, "/chunked", NULL, 0);
	request_at(client, "https callback wrong host", CELL_HTTP_METHOD_GET, "https", PORT + 364, "/plain", NULL, 0);
	request_at(client, "https callback self-signed", CELL_HTTP_METHOD_GET, "https", PORT + 365, "/plain", NULL, 0);
	request_at(client, "https callback expired", CELL_HTTP_METHOD_GET, "https", PORT + 366, "/plain", NULL, 0);
	/* Fresh clients: a kept connection has no handshake, so no callback */
	cellHttpDestroyClient(client);
	cellHttpCreateClient(&client);
	cellHttpClientSetSslCallback(client, ssl_callback, &ssl_answer);
	ssl_answer = 0;
	request_at(client, "https callback valid", CELL_HTTP_METHOD_GET, "https", PORT + 363, "/plain", NULL, 0);
	cellHttpDestroyClient(client);
	cellHttpCreateClient(&client);
	cellHttpClientSetSslCallback(client, ssl_callback, &ssl_answer);
	ssl_answer = -1;
	request_at(client, "https refusing wrong host", CELL_HTTP_METHOD_GET, "https", PORT + 364, "/plain", NULL, 0);
	ssl_answer = 1;
	request_at(client, "https answering 1", CELL_HTTP_METHOD_GET, "https", PORT + 365, "/plain", NULL, 0);
	cellHttpDestroyClient(client);
	proxy_https_probe();
	unnamed_https_probe();
	additions_https_probe();
	line("HttpsEnd rc=0x%08x", cellHttpsEnd());
	line("HttpsEnd again rc=0x%08x", cellHttpsEnd());
	free(ca);
}

/* The cellHttpUtil half (util.c) */
void util_probe(void);
/* The cookie half (cookie.c) */
void cookie_probe(void);
/* The transaction half (transaction.c) */
void transaction_probe(void);
/* The authentication half (auth.c) */
void auth_probe(void);
/* The proxy and cache half (proxy.c) */
void proxy_cache_probe(void);
/* The unnamed half (unnamed.c) */
void unnamed_probe(void);
int cellHttpAuthCacheFlush(void);
int cellHttpAuthCacheGetEntryMax(uint32_t *max);

/* Sony's, not in PS3DK's headers (the stub has them) */
int cellHttpSetProxy(const CellHttpUri *proxy);
int cellHttpGetProxy(CellHttpUri *proxy, void *pool, size_t size, size_t *required);

#define UNTOUCHED ((size_t)0xa5a5a5a5u)

/* A proxy as a getter gave it: each string, and where in the pool it was put */
static void proxy_shown(const char *name, int rc, const CellHttpUri *uri, const char *pool, size_t required)
{
	if (rc != 0) {
		line("%s rc=0x%08x required=%u", name, (unsigned)rc, (unsigned)required);
		return;
	}
#define AT(field) (uri->field == NULL ? -1 : (int)(uri->field - pool)), (uri->field == NULL ? "(null)" : uri->field)
	line("%s rc=0x%08x required=%u scheme@%d \"%s\" host@%d \"%s\" user@%d \"%s\" password@%d \"%s\" path@%d \"%s\" port=%u",
	     name, (unsigned)rc, (unsigned)required, AT(scheme), AT(hostname), AT(username), AT(password), AT(path),
	     (unsigned)uri->port);
#undef AT
}

/* A getter's answers: the size alone, then into a pool that fits, one a byte short, none at all */
static void proxy_get(const char *name, CellHttpClientId client)
{
	static char pool[512];
	char label[64];
	size_t required = UNTOUCHED;
	CellHttpUri uri;
	memset(&uri, 0xa5, sizeof(uri));
	int rc = client != 0 ? cellHttpClientGetProxy(client, NULL, NULL, 0, &required)
	                     : cellHttpGetProxy(NULL, NULL, 0, &required);
	line("%s size rc=0x%08x required=%s%u", name, (unsigned)rc, required == UNTOUCHED ? "untouched " : "",
	     required == UNTOUCHED ? 0 : (unsigned)required);
	size_t need = required == UNTOUCHED ? 0 : required;
	size_t again = UNTOUCHED;
	rc = client != 0 ? cellHttpClientGetProxy(client, &uri, pool, sizeof(pool), &again)
	                 : cellHttpGetProxy(&uri, pool, sizeof(pool), &again);
	snprintf(label, sizeof(label), "%s full", name);
	if (rc == 0 && need == 0)
		line("%s rc=0x%08x required=%u uri %s", label, (unsigned)rc, (unsigned)again,
		     filled(&uri.hostname, sizeof(uri.hostname)) ? "untouched" : "written");
	else
		proxy_shown(label, rc, &uri, pool, again);
	if (need > 0) {
		again = UNTOUCHED;
		rc = client != 0 ? cellHttpClientGetProxy(client, &uri, pool, need - 1, &again)
		                 : cellHttpGetProxy(&uri, pool, need - 1, &again);
		line("%s short rc=0x%08x required=%u", name, (unsigned)rc, (unsigned)again);
		rc = client != 0 ? cellHttpClientGetProxy(client, &uri, pool, need, NULL) : cellHttpGetProxy(&uri, pool, need, NULL);
		line("%s exact no required rc=0x%08x", name, (unsigned)rc);
	}
	rc = client != 0 ? cellHttpClientGetProxy(client, NULL, NULL, 0, NULL) : cellHttpGetProxy(NULL, NULL, 0, NULL);
	line("%s nothing rc=0x%08x", name, (unsigned)rc);
}

/* The proxy settings (libhttp's and a client's) and the cookie store's init and end, after
 * everything else so nothing before depends on them */
static void proxies_and_cookies(void)
{
	CellHttpUri proxy = {"http", "proxy.example", "user", "secret", "/", 8080, {0}};
	CellHttpUri bare = {"http", "bare.example", NULL, NULL, NULL, 0, {0}};
	CellHttpUri nohost = {"http", "", "", "", "/", 8080, {0}};
	proxy_get("GetProxy unset", 0);
	line("SetProxy rc=0x%08x", cellHttpSetProxy(&proxy));
	proxy_get("GetProxy set", 0);
	line("SetProxy bare rc=0x%08x", cellHttpSetProxy(&bare));
	proxy_get("GetProxy bare", 0);
	line("SetProxy no host rc=0x%08x", cellHttpSetProxy(&nohost));
	proxy_get("GetProxy after no host", 0);
	CellHttpClientId client = 0;
	line("proxy client rc=0x%08x", cellHttpCreateClient(&client));
	proxy_get("ClientGetProxy inherited", client);
	line("ClientSetProxy rc=0x%08x", cellHttpClientSetProxy(client, &proxy));
	proxy_get("ClientGetProxy set", client);
	line("ClientSetProxy NULL rc=0x%08x", cellHttpClientSetProxy(client, NULL));
	proxy_get("ClientGetProxy cleared", client);
	line("SetProxy NULL rc=0x%08x", cellHttpSetProxy(NULL));
	proxy_get("GetProxy cleared", 0);
	CellHttpClientId other = 0;
	line("proxy client 2 rc=0x%08x", cellHttpCreateClient(&other));
	proxy_get("ClientGetProxy fresh", other);
	line("ClientGetProxy bad client rc=0x%08x", cellHttpClientGetProxy((CellHttpClientId)0x10, NULL, NULL, 0, NULL));
	line("ClientSetProxy bad client rc=0x%08x", cellHttpClientSetProxy((CellHttpClientId)0x10, &proxy));
	cellHttpDestroyClient(other);
	cellHttpDestroyClient(client);

	static char cookies[16 * 1024];
	line("EndCookie before rc=0x%08x", cellHttpEndCookie());
	line("InitCookie NULL rc=0x%08x", cellHttpInitCookie(NULL, sizeof(cookies)));
	line("InitCookie size 0 rc=0x%08x", cellHttpInitCookie(cookies, 0));
	line("InitCookie small rc=0x%08x", cellHttpInitCookie(cookies, 64));
	/* The smallest pool it takes */
	static const unsigned sizes[] = {576, 584, 592, 600, 608, 616, 624, 632, 640, 4096};
	for (unsigned i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i) {
		int got = cellHttpInitCookie(cookies, sizes[i]);
		line("InitCookie %u rc=0x%08x", sizes[i], (unsigned)got);
		if (got == 0)
			cellHttpEndCookie();
	}
	line("InitCookie rc=0x%08x", cellHttpInitCookie(cookies, sizeof(cookies)));
	line("InitCookie again rc=0x%08x", cellHttpInitCookie(cookies, sizeof(cookies)));
	line("EndCookie rc=0x%08x", cellHttpEndCookie());
	line("EndCookie again rc=0x%08x", cellHttpEndCookie());
	line("InitCookie after end rc=0x%08x", cellHttpInitCookie(cookies, sizeof(cookies)));
	line("EndCookie last rc=0x%08x", cellHttpEndCookie());
}

static void request_headers(CellHttpClientId client)
{
	CellHttpUri uri = {"http", HOST, "", "", "/echo", PORT, {0}};
	CellHttpTransId transaction = 0;
	int rc = cellHttpCreateTransaction(&transaction, client, CELL_HTTP_METHOD_GET, &uri);
	CellHttpHeader one = {"X-Request", "first"}, two = {"X-Request", "second"}, three = {"X-Other", "third"};
	line("headers set rc=0x%08x", cellHttpRequestSetHeader(transaction, &one));
	line("headers add rc=0x%08x", cellHttpRequestAddHeader(transaction, &two));
	line("headers add other rc=0x%08x", cellHttpRequestAddHeader(transaction, &three));
	line("headers delete rc=0x%08x", cellHttpRequestDeleteHeader(transaction, "X-Other"));
	line("headers delete missing rc=0x%08x", cellHttpRequestDeleteHeader(transaction, "X-Missing"));
	char pool[512];
	size_t required = 0;
	CellHttpHeader header;
	memset(&header, 0, sizeof(header));
	rc = cellHttpRequestGetHeader(transaction, &header, "X-Request", pool, sizeof(pool), &required);
	line("headers get rc=0x%08x %s: %s", rc, header.name ? header.name : "-", header.value ? header.value : "-");
	CellHttpHeaderPtr headers = NULL;
	size_t items = 0;
	rc = cellHttpRequestGetAllHeaders(transaction, &headers, &items, pool, sizeof(pool), &required);
	line("headers all rc=0x%08x items=%u", rc, (unsigned)items);
	for (size_t i = 0; rc >= 0 && headers != NULL && i < items; ++i)
		line("headers %u %s: %s", (unsigned)i, headers[i].name, headers[i].value);
	size_t sent = 0;
	rc = cellHttpSendRequest(transaction, NULL, 0, &sent);
	line("headers send rc=0x%08x", rc);
	if (rc >= 0)
		response("headers", transaction);
	cellHttpDestroyTransaction(transaction);
}

int main(void)
{
	printf("probe: start\n");
	cellSysmoduleLoadModule(CELL_SYSMODULE_NET);
	cellSysmoduleLoadModule(CELL_SYSMODULE_HTTP);
	cellSysmoduleLoadModule(CELL_SYSMODULE_SSL);
	cellSysmoduleLoadModule(CELL_SYSMODULE_FS);
	netInitialize();
	static char ssl_pool[256 * 1024];
	line("SslInit rc=0x%08x", cellSslInit(ssl_pool, sizeof(ssl_pool)));
	void *pool = malloc(HTTP_POOL_SIZE);
	CellHttpClientId client = 0;
	line("before init CreateClient rc=0x%08x", cellHttpCreateClient(&client));
	line("before init End rc=0x%08x", cellHttpEnd());
	size_t before = UNTOUCHED;
	line("before init GetProxy rc=0x%08x", cellHttpGetProxy(NULL, NULL, 0, &before));
	CellHttpUri early = {"http", "proxy.example", "", "", "/", 8080, {0}};
	line("before init SetProxy rc=0x%08x", cellHttpSetProxy(&early));
	static char early_cookies[16 * 1024];
	line("before init InitCookie rc=0x%08x", cellHttpInitCookie(early_cookies, sizeof(early_cookies)));
	line("before init EndCookie rc=0x%08x", cellHttpEndCookie());
	{
		uint32_t entries = 0;
		line("before init AuthCacheFlush rc=0x%08x", cellHttpAuthCacheFlush());
		line("before init AuthCacheGetEntryMax rc=0x%08x", cellHttpAuthCacheGetEntryMax(&entries));
	}
	{
		CellHttpUri parsed;
		static char parsed_pool[256];
		size_t parsed_size = 0;
		int parsed_rc = cellHttpUtilParseUri(&parsed, "http://example.com/a", parsed_pool, sizeof(parsed_pool), &parsed_size);
		line("before init ParseUri rc=0x%08x required=%u host=%s", (unsigned)parsed_rc, (unsigned)parsed_size,
		     parsed_rc == 0 ? parsed.hostname : "-");
	}
	line("init NULL rc=0x%08x", cellHttpInit(NULL, HTTP_POOL_SIZE));
	line("init size 0 rc=0x%08x", cellHttpInit(pool, 0));
	line("init rc=0x%08x", cellHttpInit(pool, HTTP_POOL_SIZE));
	line("init again rc=0x%08x", cellHttpInit(pool, HTTP_POOL_SIZE));

	line("CreateClient NULL rc=0x%08x", cellHttpCreateClient(NULL));
	int rc = cellHttpCreateClient(&client);
	line("CreateClient rc=0x%08x %s", rc, client != 0 ? "id" : "no id");
	defaults(client);
	bool flag = false;
	line("bad client rc=0x%08x", cellHttpClientGetKeepAlive((CellHttpClientId)0x10, &flag));
	line("NULL client rc=0x%08x", cellHttpClientGetKeepAlive(0, &flag));
	line("NULL out rc=0x%08x", cellHttpClientGetKeepAlive(client, NULL));
	line("set UserAgent rc=0x%08x", cellHttpClientSetUserAgent(client, "ProbeAgent/1.0"));
	line("set UserAgent NULL rc=0x%08x", cellHttpClientSetUserAgent(client, NULL));
	line("set Version 1.0 rc=0x%08x", cellHttpClientSetVersion(client, 1, 0));
	line("set Version 2.0 rc=0x%08x", cellHttpClientSetVersion(client, 2, 0));
	line("set Version 1.1 rc=0x%08x", cellHttpClientSetVersion(client, 1, 1));
	line("set RecvTimeout -1 rc=0x%08x", cellHttpClientSetRecvTimeout(client, -1));
	line("set RecvTimeout 5s rc=0x%08x", cellHttpClientSetRecvTimeout(client, 5000000));
	CellHttpHeader client_header = {"X-Client", "from the client"};
	line("client header add rc=0x%08x", cellHttpClientAddHeader(client, &client_header));

	CellHttpUri uri = {"http", HOST, "", "", "/plain", PORT, {0}};
	CellHttpTransId transaction = 0;
	line("CreateTransaction NULL id rc=0x%08x", cellHttpCreateTransaction(NULL, client, "GET", &uri));
	line("CreateTransaction NULL method rc=0x%08x", cellHttpCreateTransaction(&transaction, client, NULL, &uri));
	line("CreateTransaction NULL uri rc=0x%08x", cellHttpCreateTransaction(&transaction, client, "GET", NULL));
	CellHttpUri ftp = {"ftp", HOST, "", "", "/", PORT, {0}};
	line("CreateTransaction ftp rc=0x%08x", cellHttpCreateTransaction(&transaction, client, "GET", &ftp));
	CellHttpUri nohost = {"http", "", "", "", "/", PORT, {0}};
	line("CreateTransaction no host rc=0x%08x", cellHttpCreateTransaction(&transaction, client, "GET", &nohost));

	request(client, "plain", CELL_HTTP_METHOD_GET, "/plain", NULL, 0);
	request(client, "head", "HEAD", "/plain", NULL, 0);
	request(client, "chunked", CELL_HTTP_METHOD_GET, "/chunked", NULL, 0);
	request(client, "close", CELL_HTTP_METHOD_GET, "/close", NULL, 0);
	request(client, "empty", CELL_HTTP_METHOD_GET, "/empty", NULL, 0);
	request(client, "notfound", CELL_HTTP_METHOD_GET, "/notfound", NULL, 0);
	request(client, "redirect", CELL_HTTP_METHOD_GET, "/redirect", NULL, 0);
	static const char posted[] = "a=1&b=two";
	request(client, "post", "POST", "/echo", posted, sizeof(posted) - 1);
	request(client, "echo", CELL_HTTP_METHOD_GET, "/echo", NULL, 0);
	request(client, "keepalive1", CELL_HTTP_METHOD_GET, "/keepalive", NULL, 0);
	request(client, "keepalive2", CELL_HTTP_METHOD_GET, "/keepalive", NULL, 0);
	request_headers(client);

	CellHttpUri refused = {"http", HOST, "", "", "/", 1, {0}};
	rc = cellHttpCreateTransaction(&transaction, client, CELL_HTTP_METHOD_GET, &refused);
	size_t sent = 0;
	line("refused send rc=0x%08x", rc >= 0 ? cellHttpSendRequest(transaction, NULL, 0, &sent) : rc);
	if (rc >= 0)
		cellHttpDestroyTransaction(transaction);
	CellHttpUri unknown = {"http", "nonexistent.invalid", "", "", "/", 80, {0}};
	rc = cellHttpCreateTransaction(&transaction, client, CELL_HTTP_METHOD_GET, &unknown);
	line("unknown host send rc=0x%08x", rc >= 0 ? cellHttpSendRequest(transaction, NULL, 0, &sent) : rc);
	if (rc >= 0)
		cellHttpDestroyTransaction(transaction);

	line("DestroyClient rc=0x%08x", cellHttpDestroyClient(client));
	https();
	proxies_and_cookies();
	util_probe();
	cookie_probe();
	transaction_probe();
	auth_probe();
	proxy_cache_probe();
	unnamed_probe();
	additions_probe();
	line("End rc=0x%08x", cellHttpEnd());
	line("End again rc=0x%08x", cellHttpEnd());
	line("after end AuthCacheFlush rc=0x%08x", cellHttpAuthCacheFlush());
	printf("probe: done\n");
	return 0;
}
