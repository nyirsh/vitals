/* The probe's authentication half: Basic and Digest against server.py's /basic and /digest paths,
 * credentials from the URI and from the game's callback (its arguments, its answers, its save
 * flag), automatic authentication and the cache turned off, the authentication cache's
 * functions. main.c runs it after the transaction half; one "probe: " line a result */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <cell/cell_fs.h>
#include <cell/http.h>

#define HOST "127.0.0.1"
#define PORT 18080
#define UNTOUCHED ((size_t)0xa5a5a5a5u)

/* Sony's, not in PS3DK's headers (the probe's stub has them) */
int cellHttpAuthCacheExport(void *buffer, size_t size, size_t *exported);
int cellHttpAuthCacheImport(const void *buffer, size_t size);
int cellHttpAuthCacheFlush(void);
int cellHttpAuthCacheGetEntryMax(uint32_t *max);
int cellHttpAuthCacheSetEntryMax(uint32_t max);

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

/* ---- callbacks ---- */

static int g_answer, g_calls, g_save, g_wrong;
static const char *g_user = "user", *g_password = "pass";

static int auth_callback(CellHttpTransId transaction, const char *realm, const CellHttpUri *uri, char *username,
                         char *password, bool *save, void *argument)
{
	(void)transaction;
	++g_calls;
	char given_user[40], given_password[40];
	snprintf(given_user, sizeof(given_user), "%s", username != NULL ? username : "(null)");
	snprintf(given_password, sizeof(given_password), "%s", password != NULL ? password : "(null)");
	say("auth callback %d: realm \"%s\" %s://%s:%u%s user \"%s\" password \"%s\" save %s argument %s -> %d", g_calls,
	    realm != NULL ? realm : "(null)", uri != NULL && uri->scheme != NULL ? uri->scheme : "-",
	    uri != NULL && uri->hostname != NULL ? uri->hostname : "-", uri != NULL ? (unsigned)uri->port : 0,
	    uri != NULL && uri->path != NULL ? uri->path : "-", bytes(given_user, strlen(given_user)),
	    bytes(given_password, strlen(given_password)), save == NULL ? "NULL" : *save ? "1" : "0",
	    argument == &g_answer ? "ok" : "wrong", g_answer);
	if (username != NULL)
		strcpy(username, g_wrong ? "nobody" : g_user);
	if (password != NULL)
		strcpy(password, g_wrong ? "wrong" : g_password);
	if (save != NULL && g_save >= 0)
		*save = g_save != 0;
	return g_answer;
}

static int state_callback(CellHttpTransId transaction, int32_t state, void *argument)
{
	(void)transaction, (void)argument;
	if (state == CELL_HTTP_TRANSACTION_STATE_SETTING_AUTHENTICATION)
		say("auth state 8");
	return 0;
}

/* ---- requests ---- */

static void fetch(const char *name, CellHttpClientId client, const char *path, const char *user, const char *password)
{
	CellHttpUri uri = {"http", HOST, user, password, path, PORT, {0}};
	CellHttpTransId transaction = 0;
	int rc = cellHttpCreateTransaction(&transaction, client, "GET", &uri);
	size_t sent = 0;
	if (rc >= 0)
		rc = cellHttpSendRequest(transaction, NULL, 0, &sent);
	int send_rc = rc;
	int32_t code = 0;
	if (rc >= 0)
		rc = cellHttpResponseGetStatusCode(transaction, &code);
	char body[512];
	size_t have = 0;
	while (rc >= 0 && have < sizeof(body) - 1) {
		size_t got = 0;
		rc = cellHttpRecvResponse(transaction, body + have, sizeof(body) - 1 - have, &got);
		if (rc < 0 || got == 0)
			break;
		have += got;
	}
	while (have > 0 && body[have - 1] == '\n')
		--have;
	say("%s %s send rc=0x%08x rc=0x%08x HTTP %d \"%s\"", name, path, (unsigned)send_rc, (unsigned)rc, (int)code,
	    bytes(body, have));
	if (transaction != 0)
		cellHttpDestroyTransaction(transaction);
}

static size_t export_cache(const char *name, unsigned char *buffer, size_t size)
{
	size_t exported = UNTOUCHED;
	int rc = cellHttpAuthCacheExport(NULL, 0, &exported);
	say("%s size rc=0x%08x exported=%u", name, (unsigned)rc, exported == UNTOUCHED ? 0xa5a5a5a5u : (unsigned)exported);
	size_t need = exported;
	if (need != UNTOUCHED && need > 1 && need < size) {
		exported = UNTOUCHED;
		rc = cellHttpAuthCacheExport(buffer, need - 1, &exported);
		say("%s short rc=0x%08x exported=%u", name, (unsigned)rc, exported == UNTOUCHED ? 0xa5a5a5a5u : (unsigned)exported);
	}
	memset(buffer, 0xa5, size);
	exported = UNTOUCHED;
	rc = cellHttpAuthCacheExport(buffer, size, &exported);
	say("%s rc=0x%08x exported=%u", name, (unsigned)rc, exported == UNTOUCHED ? 0xa5a5a5a5u : (unsigned)exported);
	if (rc == 0 && exported != UNTOUCHED)
		for (size_t at = 0; at < exported && at < 800; at += 100)
			say("%s %u: \"%s\"", name, (unsigned)at, bytes(buffer + at, exported - at < 100 ? exported - at : 100));
	return rc == 0 && exported != UNTOUCHED ? exported : 0;
}

void auth_probe(void)
{
	uint32_t max = 0xa5a5a5a5u;
	say("auth entry max rc=0x%08x %u", (unsigned)cellHttpAuthCacheGetEntryMax(&max), (unsigned)max);
	say("auth entry max NULL rc=0x%08x", (unsigned)cellHttpAuthCacheGetEntryMax(NULL));

	CellHttpClientId plain = 0;
	cellHttpCreateClient(&plain);
	bool flag = false;
	cellHttpClientGetAutoAuthentication(plain, &flag);
	say("auth defaults auto %d", flag ? 1 : 0);
	cellHttpClientGetAuthenticationCacheStatus(plain, &flag);
	say("auth defaults cache %d", flag ? 1 : 0);

	/* No callback: the URI's credentials, or none */
	fetch("no callback", plain, "/basic", "", "");
	fetch("uri credentials", plain, "/basic", "user", "pass");
	fetch("after uri credentials", plain, "/basic", "", "");
	fetch("uri wrong", plain, "/basic", "user", "nope");
	fetch("uri digest", plain, "/digest", "user", "pass");
	fetch("uri digest no qop", plain, "/digestnoqop", "user", "pass");
	cellHttpAuthCacheFlush();

	/* The callback */
	CellHttpClientId client = 0;
	cellHttpCreateClient(&client);
	say("auth callback set rc=0x%08x", (unsigned)cellHttpClientSetAuthenticationCallback(client, auth_callback, &g_answer));
	cellHttpClientSetTransactionStateCallback(client, state_callback, NULL);
	g_save = -1;
	fetch("callback", client, "/basic", "", "");
	fetch("callback again", client, "/basic", "", "");
	fetch("callback uri credentials", client, "/basic", "given", "secret");
	g_save = 1;
	fetch("callback saved", client, "/basic", "", "");
	fetch("after saved", client, "/basic", "", "");
	fetch("after saved sub", client, "/basic/sub", "", "");
	fetch("after saved other realm", client, "/basic2", "", "");
	fetch("after saved digest", client, "/digest", "", "");
	fetch("after saved digest again", client, "/digest", "", "");
	fetch("after saved digest no qop", client, "/digestnoqop", "", "");
	fetch("other client after saved", plain, "/basic", "", "");

	/* The cache's functions */
	static unsigned char saved[2048];
	size_t saved_size = export_cache("auth export", saved, sizeof(saved));
	/* The whole export, for working its layout out on the host */
	int fd = -1;
	if (cellFsOpen("/dev_hdd0/vitals-probe/auth-export.bin", CELL_FS_O_WRONLY | CELL_FS_O_CREAT | CELL_FS_O_TRUNC, &fd, NULL, 0) == 0) {
		uint64_t written = 0;
		cellFsWrite(fd, saved, saved_size, &written);
		cellFsClose(fd);
	}
	say("auth export NULL size rc=0x%08x", (unsigned)cellHttpAuthCacheExport(saved, sizeof(saved), NULL));
	say("auth export tiny rc=0x%08x", (unsigned)cellHttpAuthCacheExport(saved + 1024, 4, &saved_size));
	say("auth flush rc=0x%08x", (unsigned)cellHttpAuthCacheFlush());
	g_save = 0;
	fetch("after flush", client, "/basic", "", "");
	say("auth import rc=0x%08x", (unsigned)cellHttpAuthCacheImport(saved, saved_size));
	fetch("after import", client, "/basic", "", "");
	say("auth import garbage rc=0x%08x", (unsigned)cellHttpAuthCacheImport("not an export at all", 20));
	fetch("after garbage import", client, "/basic", "", "");
	say("auth import NULL rc=0x%08x", (unsigned)cellHttpAuthCacheImport(NULL, 10));
	cellHttpAuthCacheFlush();
	say("auth entry max set 1 rc=0x%08x", (unsigned)cellHttpAuthCacheSetEntryMax(1));
	say("auth entry max get rc=0x%08x %u", (unsigned)cellHttpAuthCacheGetEntryMax(&max), (unsigned)max);
	g_save = 1;
	fetch("max 1 first", client, "/basic", "", "");
	fetch("max 1 second", client, "/basic2", "", "");
	g_save = 0;
	fetch("max 1 first again", client, "/basic", "", "");
	fetch("max 1 second again", client, "/basic2", "", "");
	say("auth entry max set 0 rc=0x%08x", (unsigned)cellHttpAuthCacheSetEntryMax(0));
	say("auth entry max get rc=0x%08x %u", (unsigned)cellHttpAuthCacheGetEntryMax(&max), (unsigned)max);
	say("auth entry max set 1000 rc=0x%08x", (unsigned)cellHttpAuthCacheSetEntryMax(1000));
	say("auth entry max get rc=0x%08x %u", (unsigned)cellHttpAuthCacheGetEntryMax(&max), (unsigned)max);
	cellHttpAuthCacheSetEntryMax(32);
	cellHttpAuthCacheFlush();

	/* The callback's answers, wrong credentials, the cache and automatic authentication off */
	g_save = 0;
	g_answer = -1;
	fetch("callback -1", client, "/basic", "", "");
	g_answer = 1;
	fetch("callback 1", client, "/basic", "", "");
	g_answer = 0;
	g_wrong = 1;
	fetch("callback wrong", client, "/basic", "", "");
	g_wrong = 0;
	fetch("always refused", client, "/basicfail", "", "");
	cellHttpClientSetAuthenticationCacheStatus(client, false);
	g_save = 1;
	fetch("cache off saved", client, "/basic", "", "");
	fetch("cache off after", client, "/basic", "", "");
	cellHttpClientSetAuthenticationCacheStatus(client, true);
	cellHttpAuthCacheFlush();
	cellHttpClientSetAutoAuthentication(client, false);
	fetch("auto off", client, "/basic", "", "");
	fetch("auto off uri credentials", client, "/basic", "user", "pass");
	cellHttpClientSetAutoAuthentication(client, true);
	g_save = 0;
	fetch("digest callback", client, "/digest", "", "");
	fetch("digest callback no qop", client, "/digestnoqop", "", "");
	say("auth callback clear rc=0x%08x", (unsigned)cellHttpClientSetAuthenticationCallback(client, NULL, NULL));
	say("auth calls %d", g_calls);
	cellHttpAuthCacheFlush();
	cellHttpDestroyClient(client);
	cellHttpDestroyClient(plain);
}
