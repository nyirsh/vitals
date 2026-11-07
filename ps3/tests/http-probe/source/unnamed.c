/* The probe's unnamed half: the exports Sony's libhttp has no published name for (or names found
 * by hashing, tools/names), as their code shows them: further client settings in the same tables
 * as the named ones (flags 5, 6, 8, 9; sizes 4 to 7 and 10; buffer values 1 to 3; the
 * connection-wait table's 0), the transaction's method and credentials, gzip, the external cache,
 * and a subsystem of its own (0x80710061, 0x80710062). main.c runs it after the proxy and cache
 * half; one "probe: " line a result */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <cell/http.h>

#define HOST "127.0.0.1"
#define PORT 18080
#define BAD ((CellHttpClientId)0x10)

typedef int (*SetFlag)(CellHttpClientId, bool);
typedef int (*GetFlag)(CellHttpClientId, bool *);
typedef int (*SetValue)(CellHttpClientId, size_t);
typedef int (*GetValue)(CellHttpClientId, size_t *);

int cellHttp_6869A969(CellHttpClientId, bool);
int cellHttp_0DE7B221(CellHttpClientId, bool *);
int cellHttp_C0C891E3(CellHttpClientId, bool);
int cellHttp_F764FD69(CellHttpClientId, bool *);
int cellHttpClientSetExternalCacheStatus(CellHttpClientId, bool);
int cellHttpClientGetExternalCacheStatus(CellHttpClientId, bool *);
int cellHttpClientSetDiskCacheStatus(CellHttpClientId, bool);
int cellHttpClientGetDiskCacheStatus(CellHttpClientId, bool *);
int cellHttpClientSetGzipEncoding(CellHttpClientId, bool);
int cellHttpClientGetGzipEncoding(CellHttpClientId, bool *);
int cellHttpClientGetCacheStatus(CellHttpClientId, bool *);
int cellHttpClientSetCacheStatus(CellHttpClientId, bool);
int cellHttp_E1DDBD73(CellHttpClientId, bool);
int cellHttp_15CD67D8(CellHttpClientId, bool *);
int cellHttp_9C902AB4(CellHttpClientId, size_t);
int cellHttp_9823EB7D(CellHttpClientId, size_t *);
int cellHttp_104E9662(CellHttpClientId, size_t);
int cellHttp_9FE6021B(CellHttpClientId, size_t *);
int cellHttp_561BE85B(CellHttpClientId, size_t);
int cellHttp_923D3BD9(CellHttpClientId, size_t *);
int cellHttp_E9A53480(CellHttpClientId, size_t);
int cellHttp_CCFB621A(CellHttpClientId, size_t *);
int cellHttp_9ED1C0B5(CellHttpClientId, size_t);
int cellHttp_2A9BD960(CellHttpClientId, size_t *);
int cellHttp_42D600B1(CellHttpClientId, size_t);
int cellHttp_D5C9C1DF(CellHttpClientId, size_t *);
int cellHttp_D5198360(CellHttpClientId, size_t);
int cellHttp_415087D1(CellHttpClientId, size_t *);
int cellHttp_9619B961(CellHttpClientId, size_t);
int cellHttp_44A86F38(CellHttpClientId, size_t *);
int cellHttpTransactionGetMethod(CellHttpTransId, char *, size_t, size_t *);
int cellHttp_15C1FD80(CellHttpTransId, char *, char *);
int cellHttpInitExternalCache(uint32_t, uint32_t);
int cellHttpFlushExternalCache(void);
int cellHttpEndExternalCache(void);
int cellHttpCloseDiskCache(void);
int cellHttpsGetRootCaEntryCount(uint32_t *count);
int cellHttp_F799F3EF(uint32_t index, int (*callback)(void *, void *), void *argument);
int cellHttp_003F88AE(int (*callback)(void *, void *), void *argument);
int cellHttp_9BF4365D(int (*callback)(void *, void *), void *argument);
int cellHttp_EBF753AB(int (*callback)(void *, void *), void *argument);
int cellHttp_E0CAF386(CellHttpTransId, uint8_t *);
int cellHttp_8633468C(CellHttpTransId, uint32_t *);
int cellHttp_313D80D5(CellHttpTransId, const CellHttpHeader *);
int cellHttp_3E30440C(CellHttpTransId);
int cellHttp_DCD9D484(CellHttpTransId, const void *, size_t, size_t *);
int cellHttp_DE6475BF(uint32_t);
int cellHttp_F1374828(uint32_t *);
int cellHttpGetExternalCacheInfo(uint32_t *);
int cellHttpInitCache(uint32_t);
int cellHttpEndCache(void);
int cellHttpInitDiskCache(void *, uint32_t);
int cellHttpEndDiskCache(void);
int cellHttpFlushDiskCache(void);
int cellHttpGetDiskCacheInfo(uint32_t *);
int cellHttp_E9BE8A88(const char *);
int cellHttp_419C41D2(uint32_t);
int cellHttp_4558639F(uint32_t);
int cellHttp_ABC0EB57(uint32_t);
int cellHttp_E55FE254(void);

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

static void flag(const char *name, SetFlag set, GetFlag get)
{
	CellHttpClientId client = 0;
	cellHttpCreateClient(&client);
	bool value = true;
	int rc = get(client, &value);
	say("%s default rc=0x%08x %d", name, (unsigned)rc, value ? 1 : 0);
	int on = set(client, true);
	rc = get(client, &value);
	say("%s on rc=0x%08x get rc=0x%08x %d", name, (unsigned)on, (unsigned)rc, value ? 1 : 0);
	int off = set(client, false);
	rc = get(client, &value);
	say("%s off rc=0x%08x get rc=0x%08x %d", name, (unsigned)off, (unsigned)rc, value ? 1 : 0);
	say("%s NULL rc=0x%08x bad set rc=0x%08x bad get rc=0x%08x", name, (unsigned)get(client, NULL),
	    (unsigned)set(BAD, true), (unsigned)get(BAD, &value));
	cellHttpDestroyClient(client);
}

static void value(const char *name, SetValue set, GetValue get)
{
	CellHttpClientId client = 0;
	cellHttpCreateClient(&client);
	size_t number = 0xa5a5a5a5u;
	int rc = get(client, &number);
	say("%s default rc=0x%08x %u", name, (unsigned)rc, (unsigned)number);
	static const size_t tries[] = {0, 1, 7, 100, 65536, 0x7fffffff};
	for (unsigned i = 0; set != NULL && i < sizeof(tries) / sizeof(tries[0]); ++i) {
		int rc_set = set(client, tries[i]);
		number = 0xa5a5a5a5u;
		rc = get(client, &number);
		say("%s set %u rc=0x%08x get rc=0x%08x %u", name, (unsigned)tries[i], (unsigned)rc_set, (unsigned)rc,
		    (unsigned)number);
	}
	say("%s NULL rc=0x%08x bad get rc=0x%08x", name, (unsigned)get(client, NULL), (unsigned)get(BAD, &number));
	if (set != NULL)
		say("%s bad set rc=0x%08x", name, (unsigned)set(BAD, 1));
	cellHttpDestroyClient(client);
}

static void credentials(const char *name, CellHttpTransId transaction)
{
	char user[256], password[256];
	memset(user, 0xa5, sizeof(user));
	memset(password, 0xa5, sizeof(password));
	int rc = cellHttp_15C1FD80(transaction, user, password);
	user[255] = password[255] = '\0';
	say("%s credentials rc=0x%08x \"%s\" \"%s\"", name, (unsigned)rc, rc == 0 ? user : "-", rc == 0 ? password : "-");
}

static int g_calls;
static int count_callback(void *item, void *argument)
{
	(void)argument;
	++g_calls;
	return item != NULL ? 0 : 1;
}

static int ca_callback(void *certificate, void *argument)
{
	say("root CA callback: certificate %s, argument %s", certificate != NULL ? "given" : "NULL",
	    argument == &g_calls ? "ok" : "wrong");
	return 0;
}

/* The root CA list, while cellHttpsInit holds (main.c's https half calls it) */
void unnamed_https_probe(void)
{
	uint32_t count = 0xa5a5a5a5u;
	say("root CA count rc=0x%08x %u", (unsigned)cellHttpsGetRootCaEntryCount(&count), (unsigned)count);
	say("root CA count NULL rc=0x%08x", (unsigned)cellHttpsGetRootCaEntryCount(NULL));
	say("root CA 0 rc=0x%08x", (unsigned)cellHttp_F799F3EF(0, ca_callback, &g_calls));
	say("root CA %u rc=0x%08x", (unsigned)count, (unsigned)cellHttp_F799F3EF(count, ca_callback, &g_calls));
	say("root CA 99 rc=0x%08x", (unsigned)cellHttp_F799F3EF(99, ca_callback, &g_calls));
}

static void keepalive(const char *name, CellHttpClientId client)
{
	CellHttpUri uri = {"http", HOST, "", "", "/keepalive", PORT, {0}};
	CellHttpTransId transaction = 0;
	cellHttpCreateTransaction(&transaction, client, "GET", &uri);
	size_t sent = 0, got = 0, have = 0;
	cellHttpSendRequest(transaction, NULL, 0, &sent);
	char body[128];
	while (have < sizeof(body) - 1 && cellHttpRecvResponse(transaction, body + have, sizeof(body) - 1 - have, &got) == 0 && got != 0)
		have += got;
	body[have] = '\0';
	char *end = strchr(body, '\n');
	if (end != NULL)
		*end = '\0';
	say("%s \"%s\"", name, body);
	cellHttpDestroyTransaction(transaction);
}

void unnamed_probe(void)
{
	uint32_t external_info[2] = {0xa5a5a5a5u, 0xa5a5a5a5u};
	flag("flag 5", cellHttp_6869A969, cellHttp_0DE7B221);
	flag("flag 6", cellHttp_C0C891E3, cellHttp_F764FD69);
	flag("flag 8", cellHttpClientSetExternalCacheStatus, cellHttpClientGetExternalCacheStatus);
	flag("flag 9", cellHttpClientSetDiskCacheStatus, cellHttpClientGetDiskCacheStatus);
	flag("gzip", cellHttpClientSetGzipEncoding, cellHttpClientGetGzipEncoding);
	flag("cache status", cellHttpClientSetCacheStatus, cellHttpClientGetCacheStatus);
	flag("wait 0", cellHttp_E1DDBD73, cellHttp_15CD67D8);
	value("size 4", cellHttp_9C902AB4, cellHttp_9823EB7D);
	value("size 5", cellHttp_104E9662, cellHttp_9FE6021B);
	value("size 6", cellHttp_561BE85B, cellHttp_923D3BD9);
	value("size 7", cellHttp_E9A53480, cellHttp_CCFB621A);
	value("size 10", cellHttp_9ED1C0B5, cellHttp_2A9BD960);
	value("buffer 1", cellHttp_42D600B1, cellHttp_D5C9C1DF);
	value("buffer 2", cellHttp_D5198360, cellHttp_415087D1);
	value("buffer 3", cellHttp_9619B961, cellHttp_44A86F38);

	/* The transaction's method, and its credentials */
	CellHttpClientId client = 0;
	cellHttpCreateClient(&client);
	CellHttpUri uri = {"http", HOST, "", "", "/plain", PORT, {0}};
	CellHttpTransId transaction = 0;
	cellHttpCreateTransaction(&transaction, client, "PROPFIND", &uri);
	char method[32];
	size_t required = 0xa5a5a5a5u;
	int rc = cellHttpTransactionGetMethod(transaction, NULL, 0, &required);
	say("method size rc=0x%08x required=%u", (unsigned)rc, (unsigned)required);
	memset(method, 0xa5, sizeof(method));
	required = 0xa5a5a5a5u;
	rc = cellHttpTransactionGetMethod(transaction, method, sizeof(method), &required);
	say("method rc=0x%08x required=%u \"%s\"", (unsigned)rc, (unsigned)required, rc == 0 ? method : "-");
	required = 0xa5a5a5a5u;
	rc = cellHttpTransactionGetMethod(transaction, method, 8, &required);
	say("method short rc=0x%08x required=%u", (unsigned)rc, (unsigned)required);
	say("method no required rc=0x%08x", (unsigned)cellHttpTransactionGetMethod(transaction, method, sizeof(method), NULL));
	say("method nothing rc=0x%08x", (unsigned)cellHttpTransactionGetMethod(transaction, NULL, 0, NULL));
	say("method bad rc=0x%08x", (unsigned)cellHttpTransactionGetMethod((CellHttpTransId)0x10, method, sizeof(method), &required));
	credentials("no credentials", transaction);
	cellHttpDestroyTransaction(transaction);
	CellHttpUri with_user = {"http", HOST, "uuser", "upass", "/plain", PORT, {0}};
	cellHttpCreateTransaction(&transaction, client, "GET", &with_user);
	credentials("uri credentials", transaction);
	char user[8];
	say("credentials NULL rc=0x%08x rc=0x%08x", (unsigned)cellHttp_15C1FD80(transaction, NULL, user),
	    (unsigned)cellHttp_15C1FD80(transaction, user, NULL));
	say("credentials bad rc=0x%08x", (unsigned)cellHttp_15C1FD80((CellHttpTransId)0x10, user, user));
	cellHttpDestroyTransaction(transaction);
	CellHttpUri basic = {"http", HOST, "user", "pass", "/basic", PORT, {0}};
	cellHttpCreateTransaction(&transaction, client, "GET", &basic);
	size_t sent = 0;
	cellHttpSendRequest(transaction, NULL, 0, &sent);
	credentials("after basic", transaction);
	cellHttpDestroyTransaction(transaction);

	/* gzip on: what the request asks for */
	cellHttpClientSetGzipEncoding(client, true);
	CellHttpUri echo = {"http", HOST, "", "", "/echo", PORT, {0}};
	cellHttpCreateTransaction(&transaction, client, "GET", &echo);
	CellHttpHeader header = {NULL, NULL};
	char pool[512]; /* the header list's, room for 64-bit pointers in the host run */
	rc = cellHttpRequestGetHeader(transaction, &header, "Accept-Encoding", pool, sizeof(pool), &required);
	say("gzip Accept-Encoding rc=0x%08x %s", (unsigned)rc, rc == 0 ? header.value : "-");
	cellHttpSendRequest(transaction, NULL, 0, &sent);
	char body[1024];
	size_t have = 0, got = 0;
	while (have < sizeof(body) - 1 && cellHttpRecvResponse(transaction, body + have, sizeof(body) - 1 - have, &got) == 0 && got != 0)
		have += got;
	body[have] = '\0';
	const char *encoding = strstr(body, "Accept-Encoding:");
	char line[96] = "-";
	if (encoding != NULL)
		sscanf(encoding, "%95[^\n]", line);
	say("gzip sent %s", line);
	cellHttpDestroyTransaction(transaction);
	cellHttpDestroyClient(client);

	/* A gzip response, with gzip on */
	cellHttpCreateClient(&client);
	cellHttpClientSetGzipEncoding(client, true);
	CellHttpUri zipped = {"http", HOST, "", "", "/gzip", PORT, {0}};
	cellHttpCreateTransaction(&transaction, client, "GET", &zipped);
	cellHttpSendRequest(transaction, NULL, 0, &sent);
	uint64_t length = 0;
	rc = cellHttpResponseGetContentLength(transaction, &length);
	say("gzip response length rc=0x%08x %u", (unsigned)rc, (unsigned)length);
	rc = cellHttpResponseGetHeader(transaction, &header, "Content-Encoding", pool, sizeof(pool), &required);
	say("gzip response encoding rc=0x%08x %s", (unsigned)rc, rc == 0 ? header.value : "-");
	have = 0;
	while (have < sizeof(body) - 1 && cellHttpRecvResponse(transaction, body + have, sizeof(body) - 1 - have, &got) == 0 && got != 0)
		have += got;
	char shown[200] = "";
	for (size_t i = 0; i < have && strlen(shown) < 180; ++i)
		snprintf(shown + strlen(shown), sizeof(shown) - strlen(shown), body[i] >= 32 && body[i] < 127 ? "%c" : "\\x%02x",
		         (unsigned char)body[i]);
	say("gzip response body (%u) \"%s\"", (unsigned)have, shown);
	cellHttpDestroyTransaction(transaction);
	cellHttpDestroyClient(client);

	/* Where the size values stop */
	static const struct {
		const char *name;
		SetValue set;
		GetValue get;
	} sized[] = {{"TotalPoolSize", (SetValue)cellHttpClientSetTotalPoolSize, (GetValue)cellHttpClientGetTotalPoolSize},
	             {"PerHostPoolSize", (SetValue)cellHttpClientSetPerHostPoolSize, (GetValue)cellHttpClientGetPerHostPoolSize},
	             {"PerHostKeepAliveMax", (SetValue)cellHttpClientSetPerHostKeepAliveMax,
	              (GetValue)cellHttpClientGetPerHostKeepAliveMax},
	             {"PerPipelineMax", (SetValue)cellHttpClientSetPerPipelineMax, (GetValue)cellHttpClientGetPerPipelineMax},
	             {"size 4", cellHttp_9C902AB4, cellHttp_9823EB7D},
	             {"size 5", cellHttp_104E9662, cellHttp_9FE6021B},
	             {"size 6", cellHttp_561BE85B, cellHttp_923D3BD9},
	             {"size 7", cellHttp_E9A53480, cellHttp_CCFB621A}};
	for (unsigned i = 0; i < sizeof(sized) / sizeof(sized[0]); ++i) {
		cellHttpCreateClient(&client);
		size_t highest = 0;
		for (size_t number = 0; number <= 300; ++number)
			if (sized[i].set(client, number) == 0)
				highest = number;
		size_t now = 0;
		sized[i].get(client, &now);
		say("%s highest taken %u, last %u", sized[i].name, (unsigned)highest, (unsigned)now);
		cellHttpDestroyClient(client);
	}
	{
		cellHttpCreateClient(&client);
		cellHttpClientSetPerHostPoolSize(client, 3);
		say("PerHostKeepAliveMax over PerHostPoolSize 3 rc=0x%08x rc=0x%08x", (unsigned)cellHttpClientSetPerHostKeepAliveMax(client, 3),
		    (unsigned)cellHttpClientSetPerHostKeepAliveMax(client, 4));
		say("PerHostPoolSize over TotalPoolSize rc=0x%08x", (unsigned)cellHttpClientSetPerHostPoolSize(client, 25));
		cellHttpDestroyClient(client);
	}

	/* The external cache */
	static char external[64 * 1024];
	say("external init rc=0x%08x", (unsigned)cellHttpInitExternalCache((uint32_t)(uintptr_t)external, sizeof(external)));
	say("external init again rc=0x%08x", (unsigned)cellHttpInitExternalCache((uint32_t)(uintptr_t)external, sizeof(external)));
	cellHttpCreateClient(&client);
	say("flag 8 with external rc=0x%08x", (unsigned)cellHttpClientSetExternalCacheStatus(client, true));
	cellHttpDestroyClient(client);
	external_info[0] = external_info[1] = 0xa5a5a5a5u;
	say("external info rc=0x%08x %u %u", (unsigned)cellHttpGetExternalCacheInfo(external_info), (unsigned)external_info[0],
	    (unsigned)external_info[1]);
	g_calls = 0;
	say("external walk rc=0x%08x calls %d", (unsigned)cellHttp_9BF4365D(count_callback, NULL), g_calls);
	say("external flush rc=0x%08x", (unsigned)cellHttpFlushExternalCache());
	say("external end rc=0x%08x", (unsigned)cellHttpEndExternalCache());
	say("external end again rc=0x%08x", (unsigned)cellHttpEndExternalCache());

	/* Two transaction flags, a header set's variant, a close's variant, a send's variant */
	cellHttpCreateClient(&client);
	cellHttpCreateTransaction(&transaction, client, "GET", &echo);
	uint8_t byte = 0xa5;
	uint32_t word[4] = {0xa5a5a5a5u, 0xa5a5a5a5u, 0xa5a5a5a5u, 0xa5a5a5a5u};
	say("E0CAF386 before send rc=0x%08x %u", (unsigned)cellHttp_E0CAF386(transaction, &byte), (unsigned)byte);
	say("8633468C before send rc=0x%08x %s", (unsigned)cellHttp_8633468C(transaction, word),
	    word[0] == 0xa5a5a5a5u ? "untouched" : "written");
	say("E0CAF386 NULL rc=0x%08x bad rc=0x%08x", (unsigned)cellHttp_E0CAF386(transaction, NULL),
	    (unsigned)cellHttp_E0CAF386((CellHttpTransId)0x10, &byte));
	say("8633468C NULL rc=0x%08x bad rc=0x%08x", (unsigned)cellHttp_8633468C(transaction, NULL),
	    (unsigned)cellHttp_8633468C((CellHttpTransId)0x10, word));
	CellHttpHeader twice = {"X-Twice", "first"};
	cellHttpRequestAddHeader(transaction, &twice);
	CellHttpHeader again = {"X-Twice", "second"};
	say("313D80D5 existing rc=0x%08x", (unsigned)cellHttp_313D80D5(transaction, &again));
	CellHttpHeader fresh = {"X-Fresh", "new"};
	say("313D80D5 new rc=0x%08x", (unsigned)cellHttp_313D80D5(transaction, &fresh));
	say("313D80D5 NULL rc=0x%08x", (unsigned)cellHttp_313D80D5(transaction, NULL));
	CellHttpHeaderPtr all = NULL;
	size_t items = 0;
	rc = cellHttpRequestGetAllHeaders(transaction, &all, &items, pool, sizeof(pool), &required);
	char names[200] = "";
	for (size_t i = 0; rc == 0 && i < items; ++i)
		if (strncmp(all[i].name, "X-", 2) == 0)
			snprintf(names + strlen(names), sizeof(names) - strlen(names), "%s=%s,", all[i].name, all[i].value);
	say("313D80D5 headers %s", names);
	rc = cellHttpSendRequest(transaction, NULL, 0, &sent);
	byte = 0xa5;
	memset(word, 0xa5, sizeof(word));
	say("E0CAF386 after send rc=0x%08x %u", (unsigned)cellHttp_E0CAF386(transaction, &byte), (unsigned)byte);
	say("8633468C after send rc=0x%08x %s", (unsigned)cellHttp_8633468C(transaction, word),
	    word[0] == 0xa5a5a5a5u ? "untouched" : word[0] == 0 ? "0" : "nonzero");
	have = 0;
	while (have < sizeof(body) - 1 && cellHttpRecvResponse(transaction, body + have, sizeof(body) - 1 - have, &got) == 0 && got != 0)
		have += got;
	byte = 0xa5;
	say("E0CAF386 after body rc=0x%08x %u", (unsigned)cellHttp_E0CAF386(transaction, &byte), (unsigned)byte);
	cellHttpDestroyTransaction(transaction);
	keepalive("close variant first", client);
	cellHttpCreateTransaction(&transaction, client, "GET", &echo);
	cellHttpSendRequest(transaction, NULL, 0, &sent);
	have = 0;
	while (have < sizeof(body) - 1 && cellHttpRecvResponse(transaction, body + have, sizeof(body) - 1 - have, &got) == 0 && got != 0)
		have += got;
	say("3E30440C rc=0x%08x", (unsigned)cellHttp_3E30440C(transaction));
	say("3E30440C again rc=0x%08x bad rc=0x%08x", (unsigned)cellHttp_3E30440C(transaction),
	    (unsigned)cellHttp_3E30440C((CellHttpTransId)0x10));
	cellHttpDestroyTransaction(transaction);
	keepalive("after close variant", client);
	CellHttpUri post = {"http", HOST, "", "", "/echo", PORT, {0}};
	cellHttpCreateTransaction(&transaction, client, "POST", &post);
	cellHttpRequestSetContentLength(transaction, 4);
	rc = cellHttp_DCD9D484(transaction, "ab", 2, &sent);
	say("DCD9D484 first rc=0x%08x sent=%u", (unsigned)rc, (unsigned)sent);
	rc = cellHttp_DCD9D484(transaction, "cd", 2, &sent);
	say("DCD9D484 rest rc=0x%08x sent=%u", (unsigned)rc, (unsigned)sent);
	int32_t code = 0;
	rc = cellHttpResponseGetStatusCode(transaction, &code);
	have = 0;
	while (have < sizeof(body) - 1 && cellHttpRecvResponse(transaction, body + have, sizeof(body) - 1 - have, &got) == 0 && got != 0)
		have += got;
	body[have] = '\0';
	const char *blank = strstr(body, "\n\n");
	say("DCD9D484 status rc=0x%08x %d body \"%s\"", (unsigned)rc, (int)code, blank != NULL ? blank + 2 : "-");
	say("DCD9D484 bad rc=0x%08x", (unsigned)cellHttp_DCD9D484((CellHttpTransId)0x10, NULL, 0, &sent));
	cellHttpDestroyTransaction(transaction);
	cellHttpDestroyClient(client);

	/* A libhttp-wide value */
	uint32_t global = 0xa5a5a5a5u;
	say("global default rc=0x%08x %u", (unsigned)cellHttp_F1374828(&global), (unsigned)global);
	say("global set rc=0x%08x", (unsigned)cellHttp_DE6475BF(1234));
	say("global get rc=0x%08x %u", (unsigned)cellHttp_F1374828(&global), (unsigned)global);
	say("global set 0 rc=0x%08x", (unsigned)cellHttp_DE6475BF(0));
	say("global NULL rc=0x%08x", (unsigned)cellHttp_F1374828(NULL));

	/* The HTTP cache's and the external cache's walks */
	g_calls = 0;
	say("cache walk before init rc=0x%08x", (unsigned)cellHttp_003F88AE(count_callback, NULL));
	cellHttpInitCache(64 * 1024);
	cellHttpCreateClient(&client);
	cellHttpClientSetCacheStatus(client, true);
	CellHttpUri cacheable = {"http", HOST, "", "", "/cache/lm", PORT, {0}};
	cellHttpCreateTransaction(&transaction, client, "GET", &cacheable);
	cellHttpSendRequest(transaction, NULL, 0, &sent);
	have = 0;
	while (have < sizeof(body) - 1 && cellHttpRecvResponse(transaction, body + have, sizeof(body) - 1 - have, &got) == 0 && got != 0)
		have += got;
	cellHttpDestroyTransaction(transaction);
	cellHttpDestroyClient(client);
	g_calls = 0;
	say("cache walk rc=0x%08x calls %d", (unsigned)cellHttp_003F88AE(count_callback, NULL), g_calls);
	cellHttpEndCache();
	say("external walk before init rc=0x%08x", (unsigned)cellHttp_9BF4365D(count_callback, NULL));
	external_info[0] = external_info[1] = 0xa5a5a5a5u;
	say("external info before init rc=0x%08x", (unsigned)cellHttpGetExternalCacheInfo(external_info));

	/* The external cache */
	say("external flush before rc=0x%08x", (unsigned)cellHttpFlushExternalCache());
	say("external end before rc=0x%08x", (unsigned)cellHttpEndExternalCache());

	/* The disk cache, before its init */
	say("disk cache flush before rc=0x%08x", (unsigned)cellHttpFlushDiskCache());
	say("disk cache end before rc=0x%08x", (unsigned)cellHttpEndDiskCache());
	uint32_t disk[32];
	memset(disk, 0xa5, sizeof(disk));
	say("disk cache info before rc=0x%08x", (unsigned)cellHttpGetDiskCacheInfo(disk));
	say("disk cache walk before rc=0x%08x", (unsigned)cellHttp_EBF753AB(count_callback, NULL));
	say("disk cache E9BE8A88 before rc=0x%08x", (unsigned)cellHttp_E9BE8A88("/dev_hdd0/vitals-probe/nothing-here"));
	say("subsystem end rc=0x%08x", (unsigned)cellHttpCloseDiskCache());
	say("subsystem 419C41D2 rc=0x%08x", (unsigned)cellHttp_419C41D2(80));
	say("subsystem 4558639F rc=0x%08x", (unsigned)cellHttp_4558639F(1));
	say("subsystem ABC0EB57 rc=0x%08x", (unsigned)cellHttp_ABC0EB57(80));
	say("subsystem E55FE254 rc=0x%08x", (unsigned)cellHttp_E55FE254());

	/* The disk cache, made (cellHttpOpenDiskCache isn't called: two of its arguments aren't known) */
	static char disk_block[256 * 1024];
	say("disk cache init rc=0x%08x", (unsigned)cellHttpInitDiskCache(disk_block, sizeof(disk_block)));
	say("disk cache init again rc=0x%08x", (unsigned)cellHttpInitDiskCache(disk_block, sizeof(disk_block)));
	say("disk cache E9BE8A88 after init rc=0x%08x", (unsigned)cellHttp_E9BE8A88("/dev_hdd0/vitals-probe/nothing-here"));
	say("disk cache ABC0EB57 rc=0x%08x", (unsigned)cellHttp_ABC0EB57(11));
	say("disk cache 419C41D2 rc=0x%08x", (unsigned)cellHttp_419C41D2(22));
	say("disk cache 4558639F rc=0x%08x", (unsigned)cellHttp_4558639F(33));
	say("disk cache E55FE254 rc=0x%08x", (unsigned)cellHttp_E55FE254());
	memset(disk, 0xa5, sizeof(disk));
	rc = cellHttpGetDiskCacheInfo(disk);
	/* Word 5 is its heap's free size, which depends on what it takes: only how it relates */
	char words[400] = "";
	for (int i = 0; i < 16; ++i)
		if (i == 5)
			snprintf(words + strlen(words), sizeof(words) - strlen(words), " %s",
			         disk[5] > 0 && disk[5] < disk[4] ? "(free, under the size)" : "(free?)");
		else
			snprintf(words + strlen(words), sizeof(words) - strlen(words), " %08x", (unsigned)disk[i]);
	say("disk cache info rc=0x%08x%s", (unsigned)rc, words);
	g_calls = 0;
	say("disk cache walk rc=0x%08x calls %d", (unsigned)cellHttp_EBF753AB(count_callback, NULL), g_calls);
	say("disk cache flush rc=0x%08x", (unsigned)cellHttpFlushDiskCache());
	cellHttpCreateClient(&client);
	say("disk cache status on rc=0x%08x", (unsigned)cellHttpClientSetDiskCacheStatus(client, true));
	cellHttpDestroyClient(client);
	say("disk cache close rc=0x%08x", (unsigned)cellHttpCloseDiskCache());
	say("disk cache end rc=0x%08x", (unsigned)cellHttpEndDiskCache());
	say("disk cache end again rc=0x%08x", (unsigned)cellHttpEndDiskCache());
}
