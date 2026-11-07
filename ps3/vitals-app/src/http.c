/* HTTPS through Sony's libhttp: the network, then libhttp and libssl with Sony's CAs as games load
 * them (cellSslCertificateLoader, cellHttpsInit), then one fresh connection a request */

#include "http.h"
#include "check_model.h"

#include <cell/http.h>
#include <cell/libnetctl.h>
#include <cell/ssl.h>
#include <cell/sysmodule.h>
#include <net/net.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mutex.h>
#include <sys/sys_time.h>
#include <sys/timer.h>

#define SSL_POOL_SIZE (512 * 1024)
#define HTTP_POOL_SIZE (512 * 1024)
#define USER_AGENT "vitals/" VITALS_VERSION " (PS3)"

static int network_ready, libraries_ready;
static void *ssl_pool, *http_pool;
static char *ca_list;

/* The request in progress, which http_cancel aborts */
static sys_mutex_t guard;
static int guard_ready;
static volatile int cancelled;
static CellHttpTransId current;

uint64_t http_now_ms(void)
{
	return (uint64_t)sys_time_get_system_time() / 1000;
}

int http_network_start(void)
{
	return http_network_wait(NULL);
}

int http_network_wait(int (*stop)(void))
{
	int rc;
	if (!network_ready) {
		if ((rc = cellSysmoduleLoadModule(CELL_SYSMODULE_NET)) < 0)
			return rc;
		if ((rc = netInitialize()) < 0)
			return rc;
		if ((rc = cellNetCtlInit()) < 0)
			return rc;
		network_ready = 1;
	}
	uint64_t deadline = http_now_ms() + 10000;
	for (;;) {
		int state = 0;
		if ((rc = cellNetCtlGetState(&state)) < 0)
			return rc;
		if (state == CELL_NET_CTL_STATE_IPObtained)
			return 0;
		if (stop != NULL && stop())
			return (int)0x80130106;
		if (http_now_ms() > deadline)
			return (int)0x80130106; /* CELL_NET_CTL_ERROR_NOT_CONNECTED */
		sys_timer_usleep(100 * 1000);
	}
}

int http_open(void)
{
	if (libraries_ready)
		return 0;
	int rc = http_network_start();
	if (rc < 0)
		return rc;
	if (!guard_ready) {
		sys_mutex_attr_t attributes;
		memset(&attributes, 0, sizeof(attributes));
		attributes.attr_protocol = SYS_MUTEX_PROTOCOL_PRIO;
		attributes.attr_recursive = SYS_MUTEX_ATTR_NOT_RECURSIVE;
		attributes.attr_pshared = SYS_MUTEX_ATTR_NOT_PSHARED;
		attributes.attr_adaptive = SYS_MUTEX_ATTR_NOT_ADAPTIVE;
		snprintf(attributes.name, sizeof(attributes.name), "vhttp");
		if ((rc = sysMutexCreate(&guard, &attributes)) != 0)
			return rc;
		guard_ready = 1;
	}
	if ((rc = cellSysmoduleLoadModule(CELL_SYSMODULE_HTTP)) < 0 || (rc = cellSysmoduleLoadModule(CELL_SYSMODULE_SSL)) < 0)
		return rc;
	ssl_pool = malloc(SSL_POOL_SIZE);
	http_pool = malloc(HTTP_POOL_SIZE);
	if (ssl_pool == NULL || http_pool == NULL)
		return (int)0x80710003;
	if ((rc = cellSslInit(ssl_pool, SSL_POOL_SIZE)) < 0)
		return rc;
	if ((rc = cellHttpInit(http_pool, HTTP_POOL_SIZE)) < 0) {
		cellSslEnd();
		return rc;
	}
	/* Sony's CAs as a game loads them; vitals' libssl then also looks issuers up in Mozilla's
	 * bundle */
	uint64_t flags = (UINT64_C(1) << 59) - 1;
	size_t required = 0;
	if ((rc = cellSslCertificateLoader(flags, NULL, 0, &required)) < 0 ||
	    (ca_list = malloc(required + 1)) == NULL ||
	    (rc = cellSslCertificateLoader(flags, ca_list, required + 1, &required)) < 0) {
		cellHttpEnd();
		cellSslEnd();
		return rc < 0 ? rc : (int)0x80710003;
	}
	CellHttpsData list = {ca_list, required};
	if ((rc = cellHttpsInit(1, &list)) < 0) {
		cellHttpEnd();
		cellSslEnd();
		return rc;
	}
	libraries_ready = 1;
	return 0;
}

void http_close(void)
{
	if (libraries_ready) {
		cellHttpsEnd();
		cellHttpEnd();
		cellSslEnd();
		libraries_ready = 0;
	}
	free(ca_list);
	free(http_pool);
	free(ssl_pool);
	ca_list = NULL;
	http_pool = ssl_pool = NULL;
}

void http_cancel(void)
{
	if (!guard_ready)
		return;
	sysMutexLock(guard, 0);
	cancelled = 1;
	if (current != 0)
		cellHttpTransactionAbortConnection(current);
	sysMutexUnlock(guard);
}

/* libhttp's certificate check: its flags kept for the result, and the server refused when there
 * are any, as libhttp does without a callback */
static int certificate_check(uint32_t verify_error, CellSslCert const certificates[], int count, const char *host,
                             CellHttpSslId id, void *argument)
{
	(void)certificates, (void)count, (void)host, (void)id;
	HttpResult *result = argument;
	result->verify_error = verify_error;
	return verify_error == 0 ? 0 : -1;
}

/* "https://host[:port]/path" into its parts; 0, or -1 */
static int parse(const char *url, char *host, size_t host_size, unsigned *port, const char **path)
{
	static const char prefix[] = "https://";
	if (strncmp(url, prefix, sizeof(prefix) - 1) != 0)
		return -1;
	const char *start = url + sizeof(prefix) - 1, *end = start;
	while (*end != '\0' && *end != '/' && *end != ':')
		++end;
	if (end == start || (size_t)(end - start) >= host_size)
		return -1;
	memcpy(host, start, (size_t)(end - start));
	host[end - start] = '\0';
	*port = 443;
	if (*end == ':') {
		*port = (unsigned)strtoul(end + 1, (char **)&end, 10);
		if (*port == 0 || *port > 65535)
			return -1;
	}
	*path = *end == '/' ? end : "/";
	return 0;
}

const char *http_protocol_name(int ssl_version, const char *cipher)
{
	if (cipher != NULL && strncmp(cipher, "TLS1-3-", 7) == 0)
		return "TLS 1.3";
	return ssl_version == 0 ? "TLS" : ssl_version == 1 ? "SSL 3.0" : "none";
}

static int fetch_once(const char *url, char *body, size_t capacity, HttpResult *result)
{
	memset(result, 0, sizeof(*result));
	result->ssl_version = -1;
	if (capacity != 0)
		body[0] = '\0';
	char host[256];
	unsigned port;
	const char *path;
	if (parse(url, host, sizeof(host), &port, &path) != 0)
		return result->error = (int)0x80710007;
	uint64_t started = http_now_ms();
	CellHttpClientId client = 0;
	CellHttpTransId transaction = 0;
	int rc = cellHttpCreateClient(&client);
	if (rc < 0)
		return result->error = rc;
	cellHttpClientSetUserAgent(client, USER_AGENT);
	cellHttpClientSetKeepAlive(client, false);
	/* As the Vita's: redirects not followed, 5 seconds to connect, send and receive */
	cellHttpClientSetAutoRedirect(client, false);
	cellHttpClientSetConnTimeout(client, 5 * 1000 * 1000);
	cellHttpClientSetSendTimeout(client, 5 * 1000 * 1000);
	cellHttpClientSetRecvTimeout(client, 5 * 1000 * 1000);
	cellHttpClientSetSslCallback(client, certificate_check, result);
	CellHttpUri uri = {"https", host, "", "", path, port, {0}};
	rc = cellHttpCreateTransaction(&transaction, client, CELL_HTTP_METHOD_GET, &uri);
	if (rc >= 0) {
		CellHttpHeader no_cache = {"Cache-Control", "no-cache"};
		(void)cellHttpRequestAddHeader(transaction, &no_cache);
	}
	if (rc >= 0) {
		sysMutexLock(guard, 0);
		if (cancelled)
			rc = (int)0x80710024;
		else
			current = transaction;
		sysMutexUnlock(guard);
	}
	size_t sent = 0;
	if (rc >= 0)
		rc = cellHttpSendRequest(transaction, NULL, 0, &sent);
	int32_t status = 0;
	if (rc >= 0)
		rc = cellHttpResponseGetStatusCode(transaction, &status);
	if (rc >= 0) {
		result->http_code = status;
		int32_t version = 0;
		if (cellHttpTransactionGetSslVersion(transaction, &version) >= 0)
			result->ssl_version = version;
		size_t needed = 0;
		if (cellHttpTransactionGetSslCipherName(transaction, result->cipher, sizeof(result->cipher), &needed) < 0)
			result->cipher[0] = '\0';
		while (capacity != 0 && result->length + 1 < capacity) {
			size_t received = 0;
			int read = cellHttpRecvResponse(transaction, body + result->length, capacity - 1 - result->length, &received);
			if (read < 0) {
				rc = read;
				break;
			}
			if (received == 0)
				break;
			result->length += received;
		}
		if (capacity != 0)
			body[result->length] = '\0';
	}
	sysMutexLock(guard, 0);
	current = 0;
	if (cancelled && rc >= 0 && result->http_code == 0)
		rc = (int)0x80710024;
	sysMutexUnlock(guard);
	if (transaction != 0)
		cellHttpDestroyTransaction(transaction);
	cellHttpDestroyClient(client);
	result->elapsed_ms = (unsigned)(http_now_ms() - started);
	if (rc < 0) {
		result->error = rc;
		return rc;
	}
	return 0;
}

void http_reset_cancel(void)
{
	if (!guard_ready)
		return;
	sysMutexLock(guard, 0);
	cancelled = 0;
	sysMutexUnlock(guard);
}

/* fetch_once, made again while it times out: servers and the network are slow at times, which says
 * nothing about TLS; the result is the last attempt's, with every attempt's time, as the Vita's */
int http_get(const char *url, char *body, size_t capacity, HttpResult *result)
{
	unsigned elapsed = 0, attempts = 0;
	int rc;
	do {
		rc = fetch_once(url, body, capacity, result);
		elapsed += result->elapsed_ms;
		++attempts;
		sysMutexLock(guard, 0);
		int stop = cancelled;
		sysMutexUnlock(guard);
		if (stop)
			break;
	} while (rc < 0 && check_timed_out(rc) && attempts < HTTP_ATTEMPTS);
	result->elapsed_ms = elapsed;
	result->attempts = attempts;
	return rc;
}
