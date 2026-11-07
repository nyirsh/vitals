/* Proxies: libhttp's (cellHttpSetProxy, cellHttpGetProxy) and each client's, which starts as
 * libhttp's when the client is made. As Sony's libhttp gives them (the probe, tests/http-probe):
 * - 0x80710002 before cellHttpInit; a proxy without a host is refused with 0x80710007 and the one
 *   before stays; NULL clears it;
 * - with none set, the getters give 0 and *required 0, and leave the URI as it was. The XMB asks
 *   so at every start of its browser (silk): a getter that leaves *required alone sends it
 *   reading whatever was there;
 * - with one, the URI's strings are copied into the caller's pool as cellHttpUtilCopyUri does:
 *   scheme, host, path, user, password, each with its NUL (missing ones as ""), *required their
 *   size; a pool too small gives 0x80711001 and leaves *required alone; asking for nothing at all
 *   0x80711002.
 * Requests don't go through the proxy yet (README, plan step 5.4) */

#include "vh.h"

#include <cell/http.h>
#include <string.h>

static VhProxy g_proxy;

void vh_proxy_clear(VhProxy *proxy)
{
	vh_free(proxy->scheme), vh_free(proxy->host), vh_free(proxy->path), vh_free(proxy->username),
	    vh_free(proxy->password);
	memset(proxy, 0, sizeof(*proxy));
}

static int copy_proxy(VhProxy *to, const VhProxy *from)
{
	VhProxy copy;
	memset(&copy, 0, sizeof(copy));
	if (from->set) {
		copy.scheme = vh_strdup(from->scheme);
		copy.host = vh_strdup(from->host);
		copy.path = vh_strdup(from->path);
		copy.username = vh_strdup(from->username);
		copy.password = vh_strdup(from->password);
		copy.port = from->port;
		copy.set = 1;
		if (copy.scheme == NULL || copy.host == NULL || copy.path == NULL || copy.username == NULL ||
		    copy.password == NULL) {
			vh_proxy_clear(&copy);
			return VH_ERROR_NO_MEMORY;
		}
	}
	vh_proxy_clear(to);
	*to = copy;
	return 0;
}

/* proxy (the game's) into to: 0x80710007 without a host, leaving to as it was; NULL clears it */
static int set_proxy(VhProxy *to, const CellHttpUri *proxy)
{
	if (proxy == NULL) {
		vh_proxy_clear(to);
		return 0;
	}
	if (proxy->hostname == NULL || proxy->hostname[0] == '\0')
		return VH_ERROR_INVALID_URI;
	VhProxy given = {1,
	                 (char *)(proxy->scheme != NULL ? proxy->scheme : ""),
	                 (char *)proxy->hostname,
	                 (char *)(proxy->path != NULL ? proxy->path : ""),
	                 (char *)(proxy->username != NULL ? proxy->username : ""),
	                 (char *)(proxy->password != NULL ? proxy->password : ""),
	                 proxy->port};
	return copy_proxy(to, &given);
}

/* One string into the pool at *at */
static const char *put(char *pool, size_t *at, const char *text)
{
	size_t length = strlen(text) + 1;
	char *where = pool + *at;
	memcpy(where, text, length);
	*at += length;
	return where;
}

static int get_proxy(const VhProxy *from, CellHttpUri *out, void *pool, size_t size, size_t *required)
{
	if (!from->set) {
		if (required != NULL)
			*required = 0;
		return 0;
	}
	size_t need = strlen(from->scheme) + strlen(from->host) + strlen(from->path) + strlen(from->username) +
	              strlen(from->password) + 5;
	if (pool == NULL || out == NULL) {
		if (required == NULL)
			return VH_UTIL_ERROR_NO_BUFFER;
		*required = need;
		return 0;
	}
	if (size < need)
		return VH_UTIL_ERROR_NO_MEMORY;
	size_t at = 0;
	out->scheme = put(pool, &at, from->scheme);
	out->hostname = put(pool, &at, from->host);
	out->path = put(pool, &at, from->path);
	out->username = put(pool, &at, from->username);
	out->password = put(pool, &at, from->password);
	out->port = from->port;
	if (required != NULL)
		*required = need;
	return 0;
}

int vh_proxy_inherit(VhProxy *proxy)
{
	vh_lock();
	int rc = copy_proxy(proxy, &g_proxy);
	vh_unlock();
	return rc;
}

void vh_proxy_end(void)
{
	vh_proxy_clear(&g_proxy);
}

#if VITALS_DEBUG >= 1
static void log_proxy(const char *call, const void *id, const CellHttpUri *proxy)
{
	if (proxy == NULL)
		VH_LOG("%s %p none", call, id);
	else
		VH_LOG("%s %p %s://%s:%u", call, id, proxy->scheme != NULL ? proxy->scheme : "-",
		       proxy->hostname != NULL ? proxy->hostname : "-", (unsigned)proxy->port);
}
#else
#define log_proxy(call, id, proxy) ((void)0)
#endif

int cellHttpSetProxy(const CellHttpUri *proxy)
{
	log_proxy(__func__, NULL, proxy);
	if (!vh_initialized())
		return VH_ERROR_NOT_INITIALIZED;
	vh_lock();
	int rc = set_proxy(&g_proxy, proxy);
	vh_unlock();
	return rc;
}

int cellHttpGetProxy(CellHttpUri *proxy, void *pool, size_t size, size_t *required)
{
	VH_LOG2("cellHttpGetProxy %p %u", pool, (unsigned)size);
	if (!vh_initialized())
		return VH_ERROR_NOT_INITIALIZED;
	vh_lock();
	int rc = get_proxy(&g_proxy, proxy, pool, size, required);
	vh_unlock();
	return rc;
}

int cellHttpClientSetProxy(CellHttpClientId id, const CellHttpUri *proxy)
{
	log_proxy(__func__, (void *)id, proxy);
	if (!vh_initialized())
		return VH_ERROR_NOT_INITIALIZED;
	VhClient *client = vh_client((void *)id);
	if (client == NULL)
		return VH_ERROR_BAD_CLIENT;
	vh_lock();
	int rc = set_proxy(&client->proxy, proxy);
	vh_unlock();
	return rc;
}

int cellHttpClientGetProxy(CellHttpClientId id, CellHttpUri *proxy, void *pool, size_t size, size_t *required)
{
	VH_LOG2("cellHttpClientGetProxy %p", (void *)id);
	if (!vh_initialized())
		return VH_ERROR_NOT_INITIALIZED;
	VhClient *client = vh_client((void *)id);
	if (client == NULL)
		return VH_ERROR_BAD_CLIENT;
	vh_lock();
	int rc = get_proxy(&client->proxy, proxy, pool, size, required);
	vh_unlock();
	return rc;
}
