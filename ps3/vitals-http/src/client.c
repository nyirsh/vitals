/* Clients: their settings, headers and the connections they keep open. The defaults are what Sony's
 * libhttp reports for a new client (the probe, in RPCS3): HTTP/1.1, keep-alive, redirects,
 * authentication and its cache on, pipelining and cookies off; timeouts of 30 s to connect, 120 s to
 * send and receive and 150 s to wait for a connection; pools of 24 connections, 8 a host, 2 kept
 * alive a host, 4 a pipeline; a 5000-byte response buffer and 65535-byte socket buffers; and the
 * user agent "PS3Application libhttp/4.9.3-000 (CellOS)", its last part useragent.txt's when there's
 * one (redirect.c). Each getter and setter gives 0x80710002
 * before cellHttpInit, 0x80710010 for an ID that isn't a client and 0x80710004 without its pointer */

#include "vh.h"

#include <cell/http.h>
#include <string.h>

/* The checks every client function starts with, as Sony's: initialized, then the client */
#define WITH_CLIENT(id, client)                         \
	if (!vh_initialized())                          \
		return VH_ERROR_NOT_INITIALIZED;        \
	VhClient *client = vh_client((void *)(id));     \
	if (client == NULL)                             \
		return VH_ERROR_BAD_CLIENT

int cellHttpCreateClient(CellHttpClientId *id)
{
	if (!vh_initialized())
		return VH_ERROR_NOT_INITIALIZED;
	if (id == NULL)
		return VH_ERROR_NO_BUFFER;
	VhClient *client = vh_calloc(sizeof(*client));
	char *agent = vh_strdup(vh_default_user_agent());
	if (client == NULL || agent == NULL) {
		vh_free(client);
		vh_free(agent);
		return VH_ERROR_NO_MEMORY;
	}
	client->magic = VH_CLIENT_MAGIC;
	client->self = client;
	client->major = client->minor = 1;
	client->keep_alive = client->auto_redirect = client->auto_authentication = client->authentication_cache = 1;
	client->conn_timeout = 30000000;
	client->recv_timeout = client->send_timeout = 120000000;
	client->connection_wait_timeout = 150000000;
	client->total_pool_size = 24;
	client->per_host_pool_size = 8;
	client->per_host_keep_alive_max = 2;
	client->per_pipeline_max = 4;
	client->response_buffer_max = 5000;
	client->recv_buffer_size = client->send_buffer_size = 65535;
	client->user_agent = agent;
	client->flag5 = 1;
	client->size4 = 5, client->size5 = 4, client->size6 = 2, client->size7 = 4, client->size10 = 1024;
	client->buffer1 = 5;
	if (vh_proxy_inherit(&client->proxy) != 0) {
		vh_free(client);
		vh_free(agent);
		return VH_ERROR_NO_MEMORY;
	}
	vh_lock();
	vh_clients_add(client);
	vh_unlock();
	*id = (CellHttpClientId)client;
	VITALS_LOG("cellHttpCreateClient -> %p", (void *)client);
	return 0;
}

void vh_client_free(VhClient *client)
{
	while (client->idle != NULL) {
		VhIdle *idle = client->idle;
		client->idle = idle->next;
		vh_connection_close(client, idle->fd, idle->ssl);
		vh_free(idle->host);
		vh_free(idle);
	}
	vh_tls_client_free(client);
	vh_proxy_clear(&client->proxy);
	vh_headers_clear(&client->headers);
	vh_free(client->user_agent);
	client->magic = 0;
	client->self = NULL;
	vh_free(client);
}

int cellHttpDestroyClient(CellHttpClientId id)
{
	VITALS_LOG("cellHttpDestroyClient %p", (void *)id);
	WITH_CLIENT(id, client);
	vh_lock();
	vh_clients_remove(client);
	vh_client_free(client);
	vh_unlock();
	return 0;
}

/* The game's SslIdDestroy callback hears of a TLS connection before it goes */
/* The game's connection-state callback, as Sony's calls it:
 * callback(connection, transaction, state, argument), state 0 for a connection opened and 1 for one
 * closed for a transaction (its own, or 0 for cellHttpClientCloseConnections). Sony's connection
 * is its own object; vitals' gives a pointer of its own per socket */
typedef int (*ConnectionStateCallback)(void *connection, CellHttpTransId transaction, uint32_t state, void *argument);
static char g_connection_handles[1024];

void vh_connection_state(VhClient *client, int fd, const VhTransaction *t, uint32_t state)
{
	if (client == NULL || fd < 0 || client->callbacks[VH_CALLBACK_CONNECTION_STATE] == NULL)
		return;
	ConnectionStateCallback callback = (ConnectionStateCallback)client->callbacks[VH_CALLBACK_CONNECTION_STATE];
	VITALS_VERBOSE("client %p: connection-state callback, socket %d, state %u", (void *)client, fd, (unsigned)state);
	(void)callback(&g_connection_handles[(unsigned)fd % sizeof(g_connection_handles)], (CellHttpTransId)t, state,
	               client->callback_arguments[VH_CALLBACK_CONNECTION_STATE]);
}

void vh_connection_closed(VhClient *client, const VhTransaction *t, int fd, void *ssl)
{
	vh_connection_state(client, fd, t, 1);
	vh_connection_close(client, fd, ssl);
}

void vh_connection_close(VhClient *client, int fd, void *ssl)
{
	VITALS_VERBOSE("client %p closes socket %d%s", (void *)client, fd, ssl != NULL ? " (TLS)" : "");
	if (ssl != NULL && client != NULL && client->callbacks[VH_CALLBACK_SSL_ID_DESTROY] != NULL) {
		CellHttpSslIdDestroyCallback callback = (CellHttpSslIdDestroyCallback)client->callbacks[VH_CALLBACK_SSL_ID_DESTROY];
		(void)callback((CellHttpSslId)ssl, client->callback_arguments[VH_CALLBACK_SSL_ID_DESTROY]);
	}
	vh_tls_close(ssl);
	vh_platform_close(fd);
}

int vh_client_take_idle(VhClient *client, const char *host, unsigned port, int https, void **ssl)
{
	int fd = -1;
	*ssl = NULL;
	vh_lock();
	for (VhIdle **at = &client->idle; *at != NULL; at = &(*at)->next) {
		VhIdle *idle = *at;
		if (idle->port == port && (idle->ssl != NULL) == (https != 0) && vh_equal_nocase(idle->host, host)) {
			*at = idle->next;
			fd = idle->fd;
			*ssl = idle->ssl;
			VITALS_VERBOSE("client %p reuses socket %d to %s:%u%s", (void *)client, fd, host, port, *ssl != NULL ? " (TLS)" : "");
			vh_free(idle->host);
			vh_free(idle);
			break;
		}
	}
	vh_unlock();
	return fd;
}

/* Kept for the next request there, unless the client keeps enough for that host already */
void vh_client_keep_idle(VhClient *client, const char *host, unsigned port, int fd, void *ssl)
{
	vh_lock();
	unsigned kept = 0;
	for (VhIdle *idle = client->idle; idle != NULL; idle = idle->next)
		kept += idle->port == port && vh_equal_nocase(idle->host, host);
	VhIdle *idle = kept < client->per_host_keep_alive_max ? vh_calloc(sizeof(*idle)) : NULL;
	char *copy = idle != NULL ? vh_strdup(host) : NULL;
	if (copy == NULL) {
		vh_free(idle);
		vh_unlock();
		vh_connection_close(client, fd, ssl);
		return;
	}
	idle->host = copy;
	idle->port = port;
	idle->fd = fd;
	idle->ssl = ssl;
	VITALS_VERBOSE("client %p keeps socket %d to %s:%u", (void *)client, fd, host, port);
	idle->next = client->idle;
	client->idle = idle;
	vh_unlock();
}

/* The kept connections to the URI's host and port; nothing for no URI, as Sony's */
int cellHttpClientCloseConnections(CellHttpClientId id, const CellHttpUri *uri)
{
	VITALS_LOG("cellHttpClientCloseConnections %p %s", (void *)id, uri != NULL && uri->hostname != NULL ? uri->hostname : "-");
	WITH_CLIENT(id, client);
	if (uri == NULL || uri->hostname == NULL)
		return 0;
	const char *host = vh_redirect_host(uri->hostname);
	unsigned port = uri->port != 0 ? uri->port : uri->scheme != NULL && vh_equal_nocase(uri->scheme, "https") ? 443 : 80;
	vh_lock();
	for (VhIdle **at = &client->idle; *at != NULL;) {
		VhIdle *idle = *at;
		if (idle->port == port && vh_equal_nocase(idle->host, host)) {
			*at = idle->next;
			vh_connection_closed(client, NULL, idle->fd, idle->ssl);
			vh_free(idle->host);
			vh_free(idle);
		} else
			at = &idle->next;
	}
	vh_unlock();
	return 0;
}

/* A transaction of the client's whose response is there to read, waiting up to usec for one:
 * 0x80710012 when none is waiting for one, 0x80710093 when none came in time */
int cellHttpClientPollConnections(CellHttpClientId id, CellHttpTransId *out, int64_t usec)
{
	VITALS_VERBOSE("cellHttpClientPollConnections %p", (void *)id);
	WITH_CLIENT(id, client);
	if (out == NULL)
		return VH_ERROR_NO_BUFFER;
	int fds[64];
	VhTransaction *waiting[64];
	unsigned count = 0;
	vh_lock();
	for (VhTransaction *t = client->transactions; t != NULL; t = t->next_in_client) {
		if (!t->head_sent || t->body_done || t->released)
			continue;
		if (t->response_read || t->at < t->have) {
			vh_unlock();
			*out = (CellHttpTransId)t;
			return 0;
		}
		if (t->fd >= 0 && count < 64) {
			fds[count] = t->fd;
			waiting[count++] = t;
		}
	}
	vh_unlock();
	if (count == 0)
		return VH_ERROR_NO_CONNECTION;
	int ready = vh_platform_wait_readable(fds, count, usec);
	if (ready < 0)
		return ready == -1 ? VH_ERROR_TIMEOUT : ready;
	*out = (CellHttpTransId)waiting[ready];
	return 0;
}

int cellHttpClientCloseAllConnections(CellHttpClientId id)
{
	VITALS_LOG("cellHttpClientCloseAllConnections %p", (void *)id);
	WITH_CLIENT(id, client);
	vh_lock();
	while (client->idle != NULL) {
		VhIdle *idle = client->idle;
		client->idle = idle->next;
		vh_connection_close(client, idle->fd, idle->ssl);
		vh_free(idle->host);
		vh_free(idle);
	}
	vh_unlock();
	return 0;
}

/* ---- settings ---- */

#define FLAG(Name, field)                                                \
	int cellHttpClientSet##Name(CellHttpClientId id, bool enable)    \
	{                                                                \
		VITALS_LOG("cellHttpClientSet" #Name " %p %d", (void *)id, enable ? 1 : 0); \
		WITH_CLIENT(id, client);                                 \
		client->field = enable ? 1 : 0;                          \
		return 0;                                                \
	}                                                                \
	int cellHttpClientGet##Name(CellHttpClientId id, bool *enable)   \
	{                                                                \
		VITALS_VERBOSE("cellHttpClientGet" #Name " %p", (void *)id);  \
		WITH_CLIENT(id, client);                                 \
		if (enable == NULL)                                      \
			return VH_ERROR_NO_BUFFER;                       \
		*enable = client->field != 0;                            \
		return 0;                                                \
	}
FLAG(KeepAlive, keep_alive)
FLAG(Pipeline, pipeline)
FLAG(AutoRedirect, auto_redirect)
FLAG(AutoAuthentication, auto_authentication)
FLAG(AuthenticationCacheStatus, authentication_cache)
FLAG(CookieStatus, cookies)
FLAG(ConnectionWaitStatus, connection_wait)

/* With a highest value (0 for none): above it 0x80710027, the value kept, as Sony's */
#define VALUE_MAX(Name, field, type, max)                                \
	int cellHttpClientSet##Name(CellHttpClientId id, type value)     \
	{                                                                \
		VITALS_LOG("cellHttpClientSet" #Name " %p %ld", (void *)id, (long)value); \
		WITH_CLIENT(id, client);                                 \
		if ((max) != 0 && (uint64_t)value > (uint64_t)(max))     \
			return VH_ERROR_INVALID_VALUE;                   \
		client->field = value;                                   \
		return 0;                                                \
	}                                                                \
	int cellHttpClientGet##Name(CellHttpClientId id, type *value)    \
	{                                                                \
		VITALS_VERBOSE("cellHttpClientGet" #Name " %p", (void *)id);  \
		WITH_CLIENT(id, client);                                 \
		if (value == NULL)                                       \
			return VH_ERROR_NO_BUFFER;                       \
		*value = client->field;                                  \
		return 0;                                                \
	}
#define VALUE(Name, field, type) VALUE_MAX(Name, field, type, 0)
VALUE(ConnTimeout, conn_timeout, int64_t)
VALUE(RecvTimeout, recv_timeout, int64_t)
VALUE(SendTimeout, send_timeout, int64_t)
VALUE(ConnectionWaitTimeout, connection_wait_timeout, int64_t)
VALUE_MAX(TotalPoolSize, total_pool_size, size_t, 64)
VALUE_MAX(PerHostPoolSize, per_host_pool_size, size_t, 16)
VALUE_MAX(PerHostKeepAliveMax, per_host_keep_alive_max, size_t, 8)
VALUE_MAX(PerPipelineMax, per_pipeline_max, size_t, 8)
VALUE(ResponseBufferMax, response_buffer_max, size_t)
VALUE(RecvBufferSize, recv_buffer_size, int)
VALUE(SendBufferSize, send_buffer_size, int)
VALUE(SslVersion, ssl_version, int32_t)
VALUE(MinSslVersion, min_ssl_version, int32_t)

int cellHttpClientSetVersion(CellHttpClientId id, uint32_t major, uint32_t minor)
{
	VITALS_LOG("cellHttpClientSetVersion %p %u.%u", (void *)id, (unsigned)major, (unsigned)minor);
	WITH_CLIENT(id, client);
	client->major = major;
	client->minor = minor;
	return 0;
}

int cellHttpClientGetVersion(CellHttpClientId id, uint32_t *major, uint32_t *minor)
{
	VITALS_VERBOSE("cellHttpClientGetVersion %p", (void *)id);
	WITH_CLIENT(id, client);
	if (major == NULL || minor == NULL)
		return VH_ERROR_NO_BUFFER;
	*major = client->major;
	*minor = client->minor;
	return 0;
}

int cellHttpClientSetUserAgent(CellHttpClientId id, const char *agent)
{
	VITALS_LOG("cellHttpClientSetUserAgent %p \"%s\"", (void *)id, agent != NULL ? agent : "-");
	WITH_CLIENT(id, client);
	if (agent == NULL)
		return VH_ERROR_NO_BUFFER;
	char *copy = vh_strdup(agent);
	if (copy == NULL)
		return VH_ERROR_NO_MEMORY;
	vh_free(client->user_agent);
	client->user_agent = copy;
	return 0;
}

/* *required is the agent with its NUL; without a buffer that's all, and 0x80710006 for one too
 * small (the probe) */
int cellHttpClientGetUserAgent(CellHttpClientId id, char *agent, size_t size, size_t *required)
{
	VITALS_VERBOSE("cellHttpClientGetUserAgent %p", (void *)id);
	WITH_CLIENT(id, client);
	size_t need = strlen(client->user_agent) + 1;
	if (required != NULL)
		*required = need;
	if (agent == NULL)
		return required != NULL ? 0 : VH_ERROR_NO_BUFFER;
	if (size < need)
		return VH_ERROR_INSUFFICIENT;
	memcpy(agent, client->user_agent, need);
	return 0;
}

/* ---- the client's own headers, which every request starts with after Sony's ---- */

/* A header a game sets, for the log, its value hidden when it's a secret */
#if VITALS_DEBUG >= 1
static void log_header(const char *call, const void *id, const CellHttpHeader *header)
{
	/* The call and the header's name; its value only at level 2 */
#if VITALS_DEBUG >= 2
	char hidden[24];
	VITALS_VERBOSE("%s %p %s: %s", call, id, header != NULL && header->name != NULL ? header->name : "-",
	       header != NULL ? vh_log_header(header->name, header->value, hidden, sizeof(hidden)) : "-");
#else
	VITALS_LOG("%s %p %s", call, id, header != NULL && header->name != NULL ? header->name : "-");
#endif
}
#else
#define log_header(call, id, header) ((void)0)
#endif

int cellHttpClientSetHeader(CellHttpClientId id, const CellHttpHeader *header)
{
	log_header(__func__, (void *)id, header);
	WITH_CLIENT(id, client);
	if (header == NULL)
		return VH_ERROR_NO_BUFFER;
	return vh_headers_set(&client->headers, header->name, header->value);
}

int cellHttpClientAddHeader(CellHttpClientId id, const CellHttpHeader *header)
{
	log_header(__func__, (void *)id, header);
	WITH_CLIENT(id, client);
	if (header == NULL)
		return VH_ERROR_NO_BUFFER;
	return vh_headers_add(&client->headers, header->name, header->value);
}

int cellHttpClientDeleteHeader(CellHttpClientId id, const char *name)
{
	VITALS_LOG("cellHttpClientDeleteHeader %p %s", (void *)id, name != NULL ? name : "-");
	WITH_CLIENT(id, client);
	return vh_headers_delete(&client->headers, name);
}

int cellHttpClientGetHeader(CellHttpClientId id, CellHttpHeader *header, const char *name, void *pool, size_t size,
                            size_t *required)
{
	VITALS_VERBOSE("cellHttpClientGetHeader %p", (void *)id);
	WITH_CLIENT(id, client);
	return vh_headers_get(&client->headers, header, name, pool, size, required);
}

int cellHttpClientGetAllHeaders(CellHttpClientId id, CellHttpHeaderPtr *headers, size_t *items, void *pool,
                                size_t size, size_t *required)
{
	VITALS_VERBOSE("cellHttpClientGetAllHeaders %p", (void *)id);
	WITH_CLIENT(id, client);
	return vh_headers_get_all(&client->headers, headers, items, pool, size, required);
}

/* ---- callbacks: kept for the steps that call them (authentication, redirects, cookies, SSL) ---- */

#define CALLBACK(Name, type, slot)                                                         \
	int cellHttpClientSet##Name(CellHttpClientId id, type callback, void *argument)     \
	{                                                                                  \
		VITALS_LOG("cellHttpClientSet" #Name " %p %p", (void *)id, (void *)callback);   \
		WITH_CLIENT(id, client);                                                   \
		client->callbacks[slot] = (void *)callback;                                \
		client->callback_arguments[slot] = argument;                               \
		return 0;                                                                  \
	}
CALLBACK(AuthenticationCallback, CellHttpAuthenticationCallback, VH_CALLBACK_AUTHENTICATION)
CALLBACK(TransactionStateCallback, CellHttpTransactionStateCallback, VH_CALLBACK_STATE)
CALLBACK(RedirectCallback, CellHttpRedirectCallback, VH_CALLBACK_REDIRECT)
CALLBACK(CookieSendCallback, CellHttpCookieSendCallback, VH_CALLBACK_COOKIE_SEND)
CALLBACK(CookieRecvCallback, CellHttpCookieRecvCallback, VH_CALLBACK_COOKIE_RECV)
/* Given every handshake's findings (tls.c) */
CALLBACK(SslCallback, CellHttpsSslCallback, VH_CALLBACK_SSL)
CALLBACK(SslIdDestroyCallback, CellHttpSslIdDestroyCallback, VH_CALLBACK_SSL_ID_DESTROY)
/* Called by vh_connection_state */
CALLBACK(ConnectionStateCallback, void *, VH_CALLBACK_CONNECTION_STATE)
