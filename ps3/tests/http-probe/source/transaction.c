/* The probe's transaction half: what's left of a transaction's API, as Sony's libhttp answers it.
 * The URI's getter and setter, chunked uploads, releasing, closing and polling connections, the
 * memory info, and the transaction-state, redirect and connection-state callbacks. main.c runs it
 * after the cookie half; one "probe: " line a result */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <cell/http.h>

#define HOST "127.0.0.1"
#define PORT 18080
#define FILL 0xa5
#define UNTOUCHED ((size_t)0xa5a5a5a5u)

/* Sony's, not in PS3DK's headers (the probe's stub has them) */
int cellHttpTransactionSetUri(CellHttpTransId transaction, const CellHttpUri *uri);
/* The heap's free size; the first word *info had (Sony's reads it before filling it); the heap's
 * mallinfo, 10 words */
int cellHttpGetMemoryInfo(uint32_t *free_size, uint32_t *first, uint32_t *info);
int cellHttpClientSetConnectionStateCallback(CellHttpClientId client, void *callback, void *argument);

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

static char g_pool[512];

static const char *placed(const char *text)
{
	static char out[8][160];
	static int which;
	char *line = out[which = (which + 1) & 7];
	if (text == NULL)
		return "(null)";
	if ((uintptr_t)text == (uintptr_t)0xa5a5a5a5a5a5a5a5ull) /* the 0xa5 fill, at any pointer size */
		return "(untouched)";
	if (text >= g_pool && text < g_pool + sizeof(g_pool))
		snprintf(line, 160, "@%d\"%s\"", (int)(text - g_pool), bytes(text, strlen(text)));
	else
		snprintf(line, 160, "out\"%s\"", bytes(text, strlen(text)));
	return line;
}

/* ---- callbacks ---- */

static int g_state_answer = 0, g_state_fail_at = -1;
static int state_callback(CellHttpTransId transaction, int32_t state, void *argument)
{
	(void)transaction;
	int answer = state == g_state_fail_at ? g_state_answer : 0;
	say("state callback %d argument %s -> %d", (int)state, argument == &g_state_answer ? "ok" : "wrong", answer);
	return answer;
}

static int g_redirect_answer;
static int redirect_callback(CellHttpTransId transaction, const CellHttpStatusLine *status, const CellHttpUri *from,
                             const CellHttpUri *to, void *argument)
{
	(void)transaction;
	say("redirect callback: %s %u.%u %d \"%s\" from %s://%s:%u%s to %s://%s:%u%s argument %s -> %d",
	    status != NULL && status->protocol != NULL ? status->protocol : "-", status != NULL ? (unsigned)status->majorVersion : 0,
	    status != NULL ? (unsigned)status->minorVersion : 0, status != NULL ? (int)status->statusCode : 0,
	    status != NULL && status->reasonPhrase != NULL ? status->reasonPhrase : "-",
	    from != NULL && from->scheme != NULL ? from->scheme : "-", from != NULL && from->hostname != NULL ? from->hostname : "-",
	    from != NULL ? (unsigned)from->port : 0, from != NULL && from->path != NULL ? from->path : "-",
	    to != NULL && to->scheme != NULL ? to->scheme : "-", to != NULL && to->hostname != NULL ? to->hostname : "-",
	    to != NULL ? (unsigned)to->port : 0, to != NULL && to->path != NULL ? to->path : "-",
	    argument == &g_redirect_answer ? "ok" : "wrong", g_redirect_answer);
	return g_redirect_answer;
}

/* callback(connection, transaction, state, argument), as Sony's calls it: a closed connection is
 * checked against those it reported opened (their addresses can come again, so no numbering) */
static int g_connection_calls;
static uint64_t g_connections[16];
static unsigned g_connection_count;
static uint64_t g_watched_client, g_watched_transaction;
static int connection_callback(uint64_t a, uint64_t b, uint64_t c, uint64_t d)
{
	++g_connection_calls;
	int seen = 0;
	for (unsigned i = 0; i < g_connection_count; ++i)
		seen |= g_connections[i] == a;
	if (c == 0 && g_connection_count < 16)
		g_connections[g_connection_count++] = a;
	const char *connection = a == 0 ? "0" : a < 0x10000 ? "small" : c == 0 ? "pointer" : seen ? "one opened" : "one never opened";
	const char *what = b == g_watched_client ? "client" : b == g_watched_transaction ? "transaction" :
	                   b == 0 ? "0" : b < 0x10000 ? "small" : "pointer";
	say("connection callback %d: connection %s, %s, state %llu, %s", g_connection_calls, connection, what,
	    (unsigned long long)c, d == (uint64_t)(uintptr_t)&g_connection_calls ? "argument" : "wrong argument");
	return 0;
}

/* ---- a request ---- */

/* A request on transaction (made already), its status and body (one line, at most 160 characters) */
static void run(const char *name, CellHttpTransId transaction, const void *data, size_t size)
{
	size_t sent = 0;
	int rc = cellHttpSendRequest(transaction, data, size, &sent);
	say("%s send rc=0x%08x sent=%u", name, (unsigned)rc, (unsigned)sent);
	if (rc < 0)
		return;
	int32_t code = 0;
	rc = cellHttpResponseGetStatusCode(transaction, &code);
	say("%s status rc=0x%08x %d", name, (unsigned)rc, (int)code);
	char body[1024];
	size_t have = 0;
	while (rc >= 0 && have < sizeof(body) - 1) {
		size_t got = 0;
		rc = cellHttpRecvResponse(transaction, body + have, sizeof(body) - 1 - have, &got);
		if (rc < 0 || got == 0)
			break;
		have += got;
	}
	/* For /echo, what follows its headers: the request's body */
	const char *shown = body;
	size_t shown_length = have;
	body[have] = '\0';
	const char *blank = strstr(body, "\n\n");
	if (strncmp(body, "POST ", 5) == 0 && blank != NULL) {
		shown = blank + 2;
		shown_length = have - (size_t)(shown - body);
	}
	say("%s rc=0x%08x HTTP %d body \"%s\"", name, (unsigned)rc, (int)code, bytes(shown, shown_length));
}

static CellHttpTransId make(CellHttpClientId client, const char *method, const char *path)
{
	CellHttpUri uri = {"http", HOST, "", "", path, PORT, {0}};
	CellHttpTransId transaction = 0;
	if (cellHttpCreateTransaction(&transaction, client, method, &uri) < 0)
		return 0;
	return transaction;
}

static void get_uri(const char *name, CellHttpTransId transaction)
{
	size_t required = UNTOUCHED;
	int rc = cellHttpTransactionGetUri(transaction, NULL, NULL, 0, &required);
	say("%s GetUri size rc=0x%08x required=%u", name, (unsigned)rc, required == UNTOUCHED ? 0xa5a5a5a5u : (unsigned)required);
	size_t need = required;
	CellHttpUri uri;
	memset(&uri, FILL, sizeof(uri));
	memset(g_pool, FILL, sizeof(g_pool));
	required = UNTOUCHED;
	rc = cellHttpTransactionGetUri(transaction, &uri, g_pool, sizeof(g_pool), &required);
	if (rc != 0)
		say("%s GetUri rc=0x%08x required=%u", name, (unsigned)rc, required == UNTOUCHED ? 0xa5a5a5a5u : (unsigned)required);
	else
		say("%s GetUri rc=0x%08x required=%u scheme=%s host=%s user=%s password=%s path=%s port=%u", name, (unsigned)rc,
		    required == UNTOUCHED ? 0xa5a5a5a5u : (unsigned)required, placed(uri.scheme), placed(uri.hostname),
		    placed(uri.username), placed(uri.password), placed(uri.path), (unsigned)uri.port);
	if (rc == 0 && need != UNTOUCHED && need > 1) {
		required = UNTOUCHED;
		rc = cellHttpTransactionGetUri(transaction, &uri, g_pool, need - 1, &required);
		say("%s GetUri short rc=0x%08x required=%u", name, (unsigned)rc, required == UNTOUCHED ? 0xa5a5a5a5u : (unsigned)required);
	}
}

void transaction_probe(void)
{
	CellHttpClientId client = 0;
	cellHttpCreateClient(&client);

	/* GetUri and SetUri */
	CellHttpUri full = {"http", HOST, "user", "secret", "/echo?q=1", PORT, {0}};
	CellHttpTransId t = 0;
	say("uri create rc=0x%08x", (unsigned)cellHttpCreateTransaction(&t, client, "GET", &full));
	get_uri("created", t);
	say("GetUri nothing rc=0x%08x", (unsigned)cellHttpTransactionGetUri(t, NULL, NULL, 0, NULL));
	say("GetUri bad rc=0x%08x", (unsigned)cellHttpTransactionGetUri((CellHttpTransId)0x10, NULL, NULL, 0, NULL));
	CellHttpUri moved = {"http", HOST, "", "", "/plain", PORT, {0}};
	say("SetUri rc=0x%08x", (unsigned)cellHttpTransactionSetUri(t, &moved));
	get_uri("set", t);
	CellHttpHeader host_header = {NULL, NULL};
	size_t required = 0;
	say("set Host rc=0x%08x", (unsigned)cellHttpRequestGetHeader(t, &host_header, "Host", g_pool, sizeof(g_pool), &required));
	say("set Host value %s", host_header.value != NULL ? host_header.value : "-");
	CellHttpUri other_port = {"http", "localhost", "", "", "/echo", 18081, {0}};
	say("SetUri other host rc=0x%08x", (unsigned)cellHttpTransactionSetUri(t, &other_port));
	say("other Host rc=0x%08x", (unsigned)cellHttpRequestGetHeader(t, &host_header, "Host", g_pool, sizeof(g_pool), &required));
	say("other Host value %s", host_header.value != NULL ? host_header.value : "-");
	CellHttpUri nohost = {"http", "", "", "", "/", PORT, {0}};
	say("SetUri no host rc=0x%08x", (unsigned)cellHttpTransactionSetUri(t, &nohost));
	say("SetUri NULL rc=0x%08x", (unsigned)cellHttpTransactionSetUri(t, NULL));
	say("SetUri bad rc=0x%08x", (unsigned)cellHttpTransactionSetUri((CellHttpTransId)0x10, &moved));
	CellHttpUri secure = {"https", HOST, "", "", "/", 18443, {0}};
	say("SetUri https rc=0x%08x", (unsigned)cellHttpTransactionSetUri(t, &secure));
	get_uri("after bad sets", t);
	say("SetUri back rc=0x%08x", (unsigned)cellHttpTransactionSetUri(t, &moved));
	run("set", t, NULL, 0);
	say("SetUri after send rc=0x%08x", (unsigned)cellHttpTransactionSetUri(t, &full));
	get_uri("after send", t);
	cellHttpDestroyTransaction(t);

	t = make(client, "GET", "/redirect");
	run("redirected", t, NULL, 0);
	get_uri("redirected", t);
	cellHttpDestroyTransaction(t);

	/* Chunked uploads */
	t = make(client, "POST", "/echo");
	bool chunked = true;
	say("chunked default rc=0x%08x %d", (unsigned)cellHttpRequestGetChunkedTransferStatus(t, &chunked), chunked ? 1 : 0);
	say("chunked set rc=0x%08x", (unsigned)cellHttpRequestSetChunkedTransferStatus(t, true));
	say("chunked get rc=0x%08x %d", (unsigned)cellHttpRequestGetChunkedTransferStatus(t, &chunked), chunked ? 1 : 0);
	say("chunked NULL rc=0x%08x", (unsigned)cellHttpRequestGetChunkedTransferStatus(t, NULL));
	say("chunked bad rc=0x%08x", (unsigned)cellHttpRequestSetChunkedTransferStatus((CellHttpTransId)0x10, true));
	CellHttpHeaderPtr headers = NULL;
	size_t items = 0;
	int rc = cellHttpRequestGetAllHeaders(t, &headers, &items, g_pool, sizeof(g_pool), &required);
	char names[200] = "";
	for (size_t i = 0; rc == 0 && i < items; ++i) {
		strncat(names, headers[i].name, sizeof(names) - strlen(names) - 2);
		strcat(names, ",");
	}
	say("chunked headers rc=0x%08x %s", (unsigned)rc, names);
	size_t sent = 0;
	say("chunked send 1 rc=0x%08x sent=%u", (unsigned)cellHttpSendRequest(t, "hello ", 6, &sent), (unsigned)sent);
	say("chunked send 2 rc=0x%08x sent=%u", (unsigned)cellHttpSendRequest(t, "chunked", 7, &sent), (unsigned)sent);
	say("chunked set after send rc=0x%08x", (unsigned)cellHttpRequestSetChunkedTransferStatus(t, false));
	run("chunked end", t, NULL, 0);
	cellHttpDestroyTransaction(t);

	t = make(client, "POST", "/echo");
	cellHttpRequestSetChunkedTransferStatus(t, true);
	cellHttpRequestSetContentLength(t, 5);
	run("chunked with length", t, "abcde", 5);
	cellHttpDestroyTransaction(t);

	t = make(client, "POST", "/echo");
	cellHttpRequestSetContentLength(t, 5);
	say("length then chunked rc=0x%08x", (unsigned)cellHttpRequestSetChunkedTransferStatus(t, true));
	run("length then chunked", t, "abcde", 5);
	cellHttpDestroyTransaction(t);

	t = make(client, "POST", "/echo");
	cellHttpRequestSetChunkedTransferStatus(t, true);
	run("chunked empty", t, NULL, 0);
	cellHttpDestroyTransaction(t);

	/* ReleaseConnection, CloseConnections, PollConnections */
	CellHttpClientId kept = 0;
	cellHttpCreateClient(&kept);
	t = make(kept, "GET", "/keepalive");
	run("kept 1", t, NULL, 0);
	int sid = -7;
	say("release rc=0x%08x sid %s", (unsigned)cellHttpTransactionReleaseConnection(t, &sid), sid >= 0 ? "a socket" : sid == -7 ? "untouched" : "negative");
	say("release again rc=0x%08x", (unsigned)cellHttpTransactionReleaseConnection(t, &sid));
	size_t got = 0;
	char buffer[64];
	say("recv after release rc=0x%08x", (unsigned)cellHttpRecvResponse(t, buffer, sizeof(buffer), &got));
	cellHttpDestroyTransaction(t);
	t = make(kept, "GET", "/keepalive");
	run("after release", t, NULL, 0);
	cellHttpDestroyTransaction(t);
	t = make(kept, "GET", "/keepalive");
	say("release before send rc=0x%08x", (unsigned)cellHttpTransactionReleaseConnection(t, &sid));
	say("release NULL rc=0x%08x", (unsigned)cellHttpTransactionReleaseConnection(t, NULL));
	say("release bad rc=0x%08x", (unsigned)cellHttpTransactionReleaseConnection((CellHttpTransId)0x10, &sid));
	run("kept 2", t, NULL, 0);
	cellHttpDestroyTransaction(t);
	CellHttpUri other_host = {"http", "other.example", "", "", "/", 80, {0}};
	say("close other host rc=0x%08x", (unsigned)cellHttpClientCloseConnections(kept, &other_host));
	t = make(kept, "GET", "/keepalive");
	run("after closing other host", t, NULL, 0);
	cellHttpDestroyTransaction(t);
	CellHttpUri same_host = {"http", HOST, "", "", "/", PORT, {0}};
	say("close host rc=0x%08x", (unsigned)cellHttpClientCloseConnections(kept, &same_host));
	t = make(kept, "GET", "/keepalive");
	run("after closing host", t, NULL, 0);
	cellHttpDestroyTransaction(t);
	say("close NULL rc=0x%08x", (unsigned)cellHttpClientCloseConnections(kept, NULL));
	t = make(kept, "GET", "/keepalive");
	run("after closing NULL", t, NULL, 0);
	cellHttpDestroyTransaction(t);
	say("close bad rc=0x%08x", (unsigned)cellHttpClientCloseConnections((CellHttpClientId)0x10, NULL));

	CellHttpTransId polled = (CellHttpTransId)0x77;
	say("poll idle rc=0x%08x %s", (unsigned)cellHttpClientPollConnections(kept, &polled, 100000),
	    polled == (CellHttpTransId)0x77 ? "untouched" : polled == 0 ? "0" : "an id");
	t = make(kept, "GET", "/plain");
	cellHttpSendRequest(t, NULL, 0, &sent);
	polled = (CellHttpTransId)0x77;
	rc = cellHttpClientPollConnections(kept, &polled, 2000000);
	say("poll sent rc=0x%08x %s", (unsigned)rc, polled == t ? "this one" : polled == (CellHttpTransId)0x77 ? "untouched" : polled == 0 ? "0" : "another");
	say("poll NULL rc=0x%08x", (unsigned)cellHttpClientPollConnections(kept, NULL, 1000));
	say("poll bad rc=0x%08x", (unsigned)cellHttpClientPollConnections((CellHttpClientId)0x10, &polled, 1000));
	cellHttpDestroyTransaction(t);
	cellHttpDestroyClient(kept);

	/* GetMemoryInfo */
	/* The numbers depend on how much each allocation takes: only how they relate is shown */
	uint32_t free_size = 0xa5a5a5a5u, first = 0x12345678u, info[10];
	memset(info, 0xa5, sizeof(info));
	rc = cellHttpGetMemoryInfo(&free_size, &first, info);
	say("memory rc=0x%08x free %s first %s info written %s", (unsigned)rc,
	    free_size == 0xa5a5a5a5u ? "untouched" : free_size > 256 * 1024 && free_size <= 512 * 1024 ? "most of the pool" : "other",
	    first == 0xa5a5a5a5u ? "info's old word" : first == 0x12345678u ? "untouched" : "other",
	    info[0] != 0xa5a5a5a5u && info[9] != 0xa5a5a5a5u ? "all" : "not all");
	say("memory NULLs rc=0x%08x", (unsigned)cellHttpGetMemoryInfo(NULL, NULL, NULL));
	free_size = 0xa5a5a5a5u;
	say("memory free only rc=0x%08x %s", (unsigned)cellHttpGetMemoryInfo(&free_size, NULL, NULL),
	    free_size == 0xa5a5a5a5u ? "untouched" : "written");

	/* The transaction-state callback: each state of a request, then its answers */
	CellHttpClientId watched = 0;
	cellHttpCreateClient(&watched);
	say("state callback set rc=0x%08x",
	    (unsigned)cellHttpClientSetTransactionStateCallback(watched, state_callback, &g_state_answer));
	t = make(watched, "GET", "/plain");
	run("states plain", t, NULL, 0);
	cellHttpDestroyTransaction(t);
	t = make(watched, "GET", "/plain");
	run("states kept", t, NULL, 0);
	cellHttpDestroyTransaction(t);
	t = make(watched, "POST", "/echo");
	cellHttpRequestSetContentLength(t, 4);
	run("states post", t, "ab", 2);
	run("states post rest", t, "cd", 2);
	cellHttpDestroyTransaction(t);
	t = make(watched, "GET", "/redirect");
	run("states redirect", t, NULL, 0);
	cellHttpDestroyTransaction(t);
	CellHttpUri refused = {"http", HOST, "", "", "/", 1, {0}};
	t = 0;
	cellHttpCreateTransaction(&t, watched, "GET", &refused);
	run("states refused", t, NULL, 0);
	cellHttpDestroyTransaction(t);
	for (int state = 1; state <= 7; ++state) {
		cellHttpClientCloseConnections(watched, NULL);
		g_state_fail_at = state;
		g_state_answer = -1;
		char name[32];
		snprintf(name, sizeof(name), "states -1 at %d", state);
		t = make(watched, "GET", state == 7 ? "/redirect" : "/plain");
		run(name, t, NULL, 0);
		cellHttpDestroyTransaction(t);
	}
	g_state_fail_at = 1;
	g_state_answer = 1;
	t = make(watched, "GET", "/plain");
	run("states 1 at 1", t, NULL, 0);
	cellHttpDestroyTransaction(t);
	g_state_fail_at = -1;
	g_state_answer = 0;
	cellHttpClientSetTransactionStateCallback(watched, NULL, NULL);

	/* The redirect callback */
	say("redirect callback set rc=0x%08x",
	    (unsigned)cellHttpClientSetRedirectCallback(watched, redirect_callback, &g_redirect_answer));
	t = make(watched, "GET", "/redirect");
	run("redirect 0", t, NULL, 0);
	cellHttpDestroyTransaction(t);
	g_redirect_answer = -1;
	t = make(watched, "GET", "/redirect");
	run("redirect -1", t, NULL, 0);
	cellHttpDestroyTransaction(t);
	g_redirect_answer = 1;
	t = make(watched, "GET", "/redirect");
	run("redirect 1", t, NULL, 0);
	cellHttpDestroyTransaction(t);
	g_redirect_answer = 0;
	cellHttpClientSetAutoRedirect(watched, false);
	t = make(watched, "GET", "/redirect");
	run("redirect off", t, NULL, 0);
	cellHttpDestroyTransaction(t);
	cellHttpClientSetAutoRedirect(watched, true);
	cellHttpClientSetRedirectCallback(watched, NULL, NULL);

	/* The connection-state callback */
	say("connection callback set rc=0x%08x",
	    (unsigned)cellHttpClientSetConnectionStateCallback(watched, (void *)connection_callback, &g_connection_calls));
	say("connection callback bad rc=0x%08x",
	    (unsigned)cellHttpClientSetConnectionStateCallback((CellHttpClientId)0x10, (void *)connection_callback, NULL));
	cellHttpDestroyClient(watched);

	/* Its calls, on a client of its own: a step's calls are printed as they come */
	CellHttpClientId watcher = 0;
	cellHttpCreateClient(&watcher);
	cellHttpClientSetConnectionStateCallback(watcher, (void *)connection_callback, &g_connection_calls);
	g_watched_client = (uint64_t)(uintptr_t)watcher;
	static const char *const steps[] = {"open", "kept", "server closes", "after close", "release",
	                                    "close connection", "close host", "close all", "destroy client"};
	for (unsigned step = 0; step < sizeof(steps) / sizeof(steps[0]); ++step) {
		say("connection step %s", steps[step]);
		t = make(watcher, "GET", step == 2 ? "/close" : "/plain");
		g_watched_transaction = (uint64_t)(uintptr_t)t;
		run("connection", t, NULL, 0);
		int released = -7;
		if (step == 4)
			say("connection release rc=0x%08x", (unsigned)cellHttpTransactionReleaseConnection(t, &released));
		if (step == 5)
			say("connection close rc=0x%08x", (unsigned)cellHttpTransactionCloseConnection(t));
		say("connection destroy transaction");
		cellHttpDestroyTransaction(t);
		if (step == 6) {
			CellHttpUri same_host = {"http", HOST, "", "", "/", PORT, {0}};
			say("connection close host rc=0x%08x", (unsigned)cellHttpClientCloseConnections(watcher, &same_host));
		}
		if (step == 7)
			say("connection close all rc=0x%08x", (unsigned)cellHttpClientCloseAllConnections(watcher));
		if (step == 8) {
			cellHttpDestroyClient(watcher);
			say("connection client destroyed");
		}
	}
	say("connection callback calls: %d", g_connection_calls);
	cellHttpDestroyClient(client);
}
