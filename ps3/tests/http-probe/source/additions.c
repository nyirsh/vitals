/* The probe's half for vitals' additions (vitals-http/src/redirect.c): tools/http_probe.sh puts a
 * redirects.txt sending REDIRECTED to 127.0.0.1 and a useragent.txt in /dev_hdd0/vitals/ for the
 * run. Sony's libhttp reads neither, so these lines are where vitals' differs on purpose
 * (vitals-differences.txt): Sony's can't resolve REDIRECTED, and sends its own agent */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <cell/http.h>

#define PORT 18080
#define REDIRECTED "old.vitals-probe.invalid"

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

/* A request to REDIRECTED: its send, status and the URI read back, and for /echo the Host and
 * User-Agent lines the server got */
static void fetch(const char *name, CellHttpClientId client, const char *scheme, unsigned port, const char *path)
{
	CellHttpUri uri = {scheme, REDIRECTED, "", "", path, port, {0}};
	CellHttpTransId transaction = 0;
	int rc = cellHttpCreateTransaction(&transaction, client, "GET", &uri);
	if (rc < 0) {
		say("%s create rc=0x%08x", name, (unsigned)rc);
		return;
	}
	CellHttpUri back;
	static char pool[512];
	size_t required = 0;
	memset(&back, 0, sizeof(back));
	rc = cellHttpTransactionGetUri(transaction, &back, pool, sizeof(pool), &required);
	say("%s uri rc=0x%08x host %s", name, (unsigned)rc, rc == 0 && back.hostname != NULL ? back.hostname : "-");
	size_t sent = 0;
	rc = cellHttpSendRequest(transaction, NULL, 0, &sent);
	say("%s send rc=0x%08x", name, (unsigned)rc);
	if (rc >= 0) {
		int32_t code = 0;
		cellHttpResponseGetStatusCode(transaction, &code);
		char body[1024];
		size_t have = 0, got = 0;
		while (have < sizeof(body) - 1 && cellHttpRecvResponse(transaction, body + have, sizeof(body) - 1 - have, &got) == 0 &&
		       got != 0)
			have += got;
		body[have] = '\0';
		say("%s status %d, %u bytes", name, (int)code, (unsigned)have);
		for (char *line = body; line != NULL && *line != '\0';) {
			char *end = strchr(line, '\n');
			if (end != NULL)
				*end = '\0';
			if (strncmp(line, "Host: ", 6) == 0 || strncmp(line, "User-Agent: ", 12) == 0)
				say("%s | %s", name, line);
			line = end != NULL ? end + 1 : NULL;
		}
	}
	cellHttpDestroyTransaction(transaction);
}

void additions_probe(void)
{
	CellHttpClientId client = 0;
	cellHttpCreateClient(&client);
	char agent[256];
	size_t required = 0;
	int rc = cellHttpClientGetUserAgent(client, agent, sizeof(agent), &required);
	say("additions default agent rc=0x%08x \"%s\"", (unsigned)rc, rc == 0 ? agent : "-");
	fetch("additions redirected", client, "http", PORT, "/echo");
	fetch("additions redirected again", client, "http", PORT, "/echo");
	/* The kept connection is the new host's: the old host's name closes it too */
	CellHttpUri old = {"http", REDIRECTED, "", "", "/", PORT, {0}};
	say("additions close old host rc=0x%08x", (unsigned)cellHttpClientCloseConnections(client, &old));
	cellHttpClientSetUserAgent(client, "ProbeAgent/1.0");
	fetch("additions own agent", client, "http", PORT, "/echo");
	cellHttpDestroyClient(client);
}

/* With cellHttpsInit holding the probe's CA: the certificate checked against the new host */
void additions_https_probe(void)
{
	CellHttpClientId client = 0;
	cellHttpCreateClient(&client);
	fetch("additions redirected https", client, "https", PORT + 363, "/plain");
	cellHttpDestroyClient(client);
}
