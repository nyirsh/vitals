/* Transactions: a request and its response, over a connection the client keeps or a new one, as
 * Sony's libhttp does them (the probe, tests/http-probe):
 * - created with Sony's headers, in its order: Host (with the port when it isn't the scheme's),
 *   User-Agent, Connection: Keep-Alive, Accept-Encoding: identity, then the client's headers;
 *   Content-Length, once set, goes after Connection;
 * - the first cellHttpSendRequest connects (or takes a kept connection) and sends the head; each
 *   call sends its body bytes and gives them in *sent;
 * - the response is read when something asks for it: its status line and headers, then the body,
 *   by its length, in chunks, until the server closes, or none (HEAD, 1xx, 204, 304);
 * - redirects are followed when the client says so, at most 10;
 * - a connection whose response ended cleanly goes back to the client for its next request */

#include "vh.h"

#include <cell/http.h>
#include <stdio.h>
#include <string.h>

#define MAX_REDIRECTS 10

#define WITH_TRANSACTION(id, t)                         \
	VH_LOG2("%s %p", __func__, (void *)(id));       \
	if (!vh_initialized())                          \
		return VH_ERROR_NOT_INITIALIZED;        \
	VhTransaction *t = vh_transaction((void *)(id)); \
	if (t == NULL)                                  \
		return VH_ERROR_BAD_TRANS

/* A decimal number at text, *end after it */
static unsigned long long decimal(const char *text, const char **end)
{
	unsigned long long value = 0;
	while (*text >= '0' && *text <= '9')
		value = value * 10 + (unsigned)(*text++ - '0');
	if (end != NULL)
		*end = text;
	return value;
}

/* The game's transaction-state callback (CELL_HTTP_TRANSACTION_STATE_*); its answer is ignored, as
 * Sony's */
void vh_notify_state(VhTransaction *t, int32_t state)
{
	VhClient *client = t->client;
	if (client->callbacks[VH_CALLBACK_STATE] != NULL) {
		CellHttpTransactionStateCallback callback = (CellHttpTransactionStateCallback)client->callbacks[VH_CALLBACK_STATE];
		(void)callback((CellHttpTransId)t, state, client->callback_arguments[VH_CALLBACK_STATE]);
	}
}

#define notify vh_notify_state

static unsigned default_port(const char *scheme)
{
	return vh_equal_nocase(scheme, "https") ? 443 : 80;
}

static int host_header(VhTransaction *t)
{
	char host[300];
	if (t->port == default_port(t->scheme))
		snprintf(host, sizeof(host), "%s", t->host);
	else
		snprintf(host, sizeof(host), "%s:%u", t->host, t->port);
	return vh_headers_set(&t->request, "Host", host);
}

/* Sony's headers, then the client's */
static int default_headers(VhTransaction *t)
{
	VhClient *client = t->client;
	int rc = host_header(t);
	if (rc == 0)
		rc = vh_headers_add(&t->request, "User-Agent", client->user_agent);
	if (rc == 0)
		rc = vh_headers_add(&t->request, "Connection", client->keep_alive ? "Keep-Alive" : "close");
	if (rc == 0)
		rc = vh_headers_add(&t->request, "Accept-Encoding", client->gzip ? "gzip" : "identity");
	for (unsigned i = 0; rc == 0 && i < client->headers.count; ++i)
		rc = vh_headers_add(&t->request, client->headers.items[i].name, client->headers.items[i].value);
	return rc;
}

static void free_transaction(VhTransaction *t)
{
	if (vh_client(t->client) != NULL) {
		vh_lock();
		for (VhTransaction **at = &t->client->transactions; *at != NULL; at = &(*at)->next_in_client)
			if (*at == t) {
				*at = t->next_in_client;
				break;
			}
		vh_unlock();
	}
	vh_headers_clear(&t->request);
	vh_headers_clear(&t->response);
	vh_free(t->method);
	vh_free(t->scheme);
	vh_free(t->host);
	vh_free(t->path);
	vh_free(t->username);
	vh_free(t->password);
	vh_free(t->reason);
	vh_free(t->captured);
	vh_free(t->cached_body);
	t->magic = 0;
	t->self = NULL;
	vh_free(t);
}

/* The URI's parts into t: 0x80710007 without a host, or for https before cellHttpsInit (Sony's) */
static int take_uri(VhTransaction *t, const CellHttpUri *uri)
{
	if (uri->hostname == NULL || uri->hostname[0] == '\0')
		return VH_ERROR_INVALID_URI;
	int https = uri->scheme != NULL && vh_equal_nocase(uri->scheme, "https");
	if (https && !vh_tls_initialized())
		return VH_ERROR_INVALID_URI;
	char *scheme = vh_strdup(uri->scheme != NULL ? uri->scheme : "http");
	/* The host redirect list's host, when it has one for this one (redirect.c) */
	char *host = vh_strdup(vh_redirect_host(uri->hostname));
	char *path = vh_strdup(uri->path != NULL && uri->path[0] != '\0' ? uri->path : "/");
	char *username = vh_strdup(uri->username != NULL ? uri->username : "");
	char *password = vh_strdup(uri->password != NULL ? uri->password : "");
	if (scheme == NULL || host == NULL || path == NULL || username == NULL || password == NULL) {
		vh_free(scheme), vh_free(host), vh_free(path), vh_free(username), vh_free(password);
		return VH_ERROR_NO_MEMORY;
	}
	vh_free(t->scheme), vh_free(t->host), vh_free(t->path), vh_free(t->username), vh_free(t->password);
	t->scheme = scheme;
	t->host = host;
	t->path = path;
	t->username = username;
	t->password = password;
	t->https = https;
	t->port = uri->port != 0 ? uri->port : default_port(scheme);
	return 0;
}

/* 0x80710004 without an ID, 0x80710010 for a client that isn't one, 0x80710009 without a method,
 * 0x80710007 without a URI or a host; any scheme is taken, as Sony's does */
static int create_transaction(CellHttpTransId *id, CellHttpClientId client_id, const char *method,
                              const CellHttpUri *uri)
{
	if (!vh_initialized())
		return VH_ERROR_NOT_INITIALIZED;
	if (id == NULL)
		return VH_ERROR_NO_BUFFER;
	VhClient *client = vh_client((void *)client_id);
	if (client == NULL)
		return VH_ERROR_BAD_CLIENT;
	if (method == NULL || method[0] == '\0')
		return VH_ERROR_BAD_METHOD;
	if (uri == NULL)
		return VH_ERROR_INVALID_URI;
	VhTransaction *t = vh_calloc(sizeof(*t));
	if (t == NULL)
		return VH_ERROR_NO_MEMORY;
	t->magic = VH_TRANS_MAGIC;
	t->self = t;
	t->client = client;
	t->fd = -1;
	t->content_length = -1;
	t->method = vh_strdup(method);
	int rc = t->method != NULL ? take_uri(t, uri) : VH_ERROR_NO_MEMORY;
	if (rc == 0)
		rc = default_headers(t);
	if (rc != 0) {
		free_transaction(t);
		return rc;
	}
	vh_lock();
	t->next_in_client = client->transactions;
	client->transactions = t;
	vh_unlock();
	*id = (CellHttpTransId)t;
	return 0;
}

int cellHttpCreateTransaction(CellHttpTransId *id, CellHttpClientId client_id, const char *method,
                              const CellHttpUri *uri)
{
	int rc = create_transaction(id, client_id, method, uri);
#if VITALS_DEBUG >= 1
	char path[96];
	VH_LOG("cellHttpCreateTransaction %p %s %s://%s:%u%s -> %p, 0x%08x", (void *)client_id, method != NULL ? method : "-",
	       uri != NULL && uri->scheme != NULL ? uri->scheme : "-", uri != NULL && uri->hostname != NULL ? uri->hostname : "-",
	       uri != NULL ? (unsigned)uri->port : 0, uri != NULL ? vh_log_path(uri->path, path, sizeof(path)) : "",
	       rc == 0 && id != NULL ? (void *)*id : NULL, (unsigned)rc);
#endif
	return rc;
}

/* Whether the transaction goes through its client's proxy */
static int proxied(const VhTransaction *t)
{
	const VhProxy *proxy = &t->client->proxy;
	return proxy->set && proxy->host != NULL && proxy->host[0] != '\0';
}

/* The key a kept connection goes by: the host, and the proxy in front of it when it's one to the
 * proxy, so a direct request never takes a proxy's connection or the other way round */
static const char *idle_key(const VhTransaction *t, char *key, size_t size)
{
	if (!t->via_proxy)
		return t->host;
	const VhProxy *proxy = &t->client->proxy;
	snprintf(key, size, "%s:%s@%s:%u|%s", proxy->username != NULL ? proxy->username : "",
	         proxy->password != NULL ? proxy->password : "", proxy->host, proxy->port, t->host);
	return key;
}

/* The connection back to the client when its response ended cleanly and both ends keep it, else
 * closed */
/* keep: 0 closes it, 1 keeps it when it can be kept and closes it otherwise, KEEP_OR_LEAVE (a body's
 * end) leaves one that can't be kept open, to be closed with the transaction, as Sony's: its
 * connection-state callback hears of the close then */
#define KEEP_OR_LEAVE 2

static void release_connection(VhTransaction *t, int keep)
{
	if (t->fd < 0)
		return;
	int keepable = t->client->keep_alive && !t->server_closes && t->body != VH_BODY_CLOSE && t->at == t->have &&
	               vh_client(t->client) != NULL;
	if (keep && keepable) {
		char key[600];
		vh_client_keep_idle(t->client, idle_key(t, key, sizeof(key)), t->port, t->fd, t->ssl);
	} else if (keep == KEEP_OR_LEAVE)
		return;
	else
		vh_connection_closed(t->client, t, t->fd, t->ssl);
	t->fd = -1;
	t->ssl = NULL;
}

int cellHttpDestroyTransaction(CellHttpTransId id)
{
	VH_LOG("cellHttpDestroyTransaction %p", (void *)id);
	WITH_TRANSACTION(id, t);
	release_connection(t, t->response_read && t->body_done);
	free_transaction(t);
	return 0;
}

/* ---- the request ---- */

int cellHttpRequestSetContentLength(CellHttpTransId id, uint64_t length)
{
	VH_LOG("cellHttpRequestSetContentLength %p %llu", (void *)id, (unsigned long long)length);
	WITH_TRANSACTION(id, t);
	char text[24];
	snprintf(text, sizeof(text), "%llu", (unsigned long long)length);
	int rc;
	if (vh_headers_find(&t->request, "Content-Length") >= 0)
		rc = vh_headers_set(&t->request, "Content-Length", text);
	else {
		int connection = vh_headers_find(&t->request, "Connection");
		rc = vh_headers_insert(&t->request, connection >= 0 ? (unsigned)connection + 1 : t->request.count,
		                       "Content-Length", text);
	}
	if (rc == 0)
		t->content_length = (int64_t)length;
	return rc;
}

int cellHttpRequestGetContentLength(CellHttpTransId id, uint64_t *length)
{
	WITH_TRANSACTION(id, t);
	if (length == NULL)
		return VH_ERROR_NO_BUFFER;
	if (t->content_length < 0)
		return VH_ERROR_NO_CONTENT_LENGTH;
	*length = (uint64_t)t->content_length;
	return 0;
}

#if VITALS_DEBUG >= 1
static void log_header(const char *call, const void *id, const CellHttpHeader *header)
{
	char hidden[24];
	VH_LOG("%s %p %s: %s", call, id, header != NULL && header->name != NULL ? header->name : "-",
	       header != NULL ? vh_log_header(header->name, header->value, hidden, sizeof(hidden)) : "-");
}
#else
#define log_header(call, id, header) ((void)0)
#endif

/* As Sony's: a header the request has already goes, and the new one comes last. The XMB's PSN
 * sign-in sets User-Agent so, and Sony's sends it after Content-Type, not second where the default
 * was; the CDN in front of sign-in refused the request with it second */
int cellHttpRequestSetHeader(CellHttpTransId id, const CellHttpHeader *header)
{
	log_header(__func__, (void *)id, header);
	WITH_TRANSACTION(id, t);
	if (header == NULL || header->name == NULL || header->value == NULL)
		return VH_ERROR_NO_BUFFER;
	if (vh_headers_find(&t->request, header->name) >= 0)
		(void)vh_headers_delete(&t->request, header->name);
	return vh_headers_add(&t->request, header->name, header->value);
}

int cellHttpRequestAddHeader(CellHttpTransId id, const CellHttpHeader *header)
{
	log_header(__func__, (void *)id, header);
	WITH_TRANSACTION(id, t);
	if (header == NULL)
		return VH_ERROR_NO_BUFFER;
	return vh_headers_add(&t->request, header->name, header->value);
}

int cellHttpRequestDeleteHeader(CellHttpTransId id, const char *name)
{
	VH_LOG("cellHttpRequestDeleteHeader %p %s", (void *)id, name != NULL ? name : "-");
	WITH_TRANSACTION(id, t);
	return vh_headers_delete(&t->request, name);
}

int cellHttpRequestGetHeader(CellHttpTransId id, CellHttpHeader *header, const char *name, void *pool, size_t size,
                             size_t *required)
{
	WITH_TRANSACTION(id, t);
	return vh_headers_get(&t->request, header, name, pool, size, required);
}

int cellHttpRequestGetAllHeaders(CellHttpTransId id, CellHttpHeaderPtr *headers, size_t *items, void *pool, size_t size,
                                 size_t *required)
{
	WITH_TRANSACTION(id, t);
	return vh_headers_get_all(&t->request, headers, items, pool, size, required);
}

/* ---- the connection ---- */

static int send_all(VhTransaction *t, const void *data, size_t size)
{
	size_t done = 0;
	while (done < size) {
		const char *at = (const char *)data + done;
		int sent = t->ssl != NULL ? vh_tls_send(t->ssl, at, size - done) : vh_platform_send(t->fd, at, size - done);
		if (sent < 0)
			return sent;
		if (sent == 0)
			return VH_NET_ERROR(VH_NET_SEND, 0);
		done += (size_t)sent;
	}
	return 0;
}

/* The request line and headers, as one write; the store's cookies (cookie.c) in a Cookie header
 * before Accept-Encoding, where Sony's puts it */
static int send_head(VhTransaction *t)
{
	notify(t, CELL_HTTP_TRANSACTION_STATE_PREPARING_REQUEST);
	char *cookie = NULL;
	int rc = vh_cookie_header(t, &cookie);
	if (rc != 0)
		return rc;
	size_t size = strlen(t->method) + strlen(t->path) + 32 + (cookie != NULL ? strlen(cookie) + 12 : 0);
	for (unsigned i = 0; i < t->request.count; ++i)
		size += strlen(t->request.items[i].name) + strlen(t->request.items[i].value) + 4;
	/* What else goes in, counted before the buffer is made */
	int absolute = t->via_proxy && !t->https;
	char condition[40];
	t->cache_revalidating = vh_cache_condition(t, condition);
	if (t->cache_revalidating)
		size += sizeof(condition) + 24;
	if (absolute)
		size += strlen(t->scheme) + strlen(t->host) + 16;
	char *text = vh_alloc(size);
	if (text == NULL) {
		vh_free(cookie);
		return VH_ERROR_NO_MEMORY;
	}
	/* To a proxy, plain http asks for the whole URL (the port only when it isn't 80), and
	 * Proxy-Connection stands for Connection, as Sony's sends them */
	char port[12] = "";
	if (absolute && t->port != 80)
		snprintf(port, sizeof(port), ":%u", t->port);
	int used = absolute ? snprintf(text, size, "%s %s://%s%s%s HTTP/%u.%u\r\n", t->method, t->scheme, t->host, port,
	                               t->path, (unsigned)t->client->major, (unsigned)t->client->minor)
	                    : snprintf(text, size, "%s %s HTTP/%u.%u\r\n", t->method, t->path, (unsigned)t->client->major,
	                               (unsigned)t->client->minor);
	int cookie_at = vh_headers_find(&t->request, "Accept-Encoding");
	if (cookie_at < 0)
		cookie_at = (int)t->request.count;
	for (unsigned i = 0; i <= t->request.count; ++i) {
		if ((int)i == cookie_at && cookie != NULL)
			used += snprintf(text + used, size - (size_t)used, "Cookie: %s\r\n", cookie);
		if (i < t->request.count) {
			const char *name = t->request.items[i].name;
			if (absolute && vh_equal_nocase(name, "Connection"))
				name = "Proxy-Connection";
			used += snprintf(text + used, size - (size_t)used, "%s: %s\r\n", name, t->request.items[i].value);
		}
	}
	if (t->cache_revalidating)
		used += snprintf(text + used, size - (size_t)used, "If-Modified-Since: %s\r\n", condition);
	if (t->cache_revalidating)
		VH_LOG2("transaction %p > If-Modified-Since: %s", (void *)t, condition);
	used += snprintf(text + used, size - (size_t)used, "\r\n");
#if VITALS_DEBUG >= 2
	{
		char path[96], hidden[24];
		VH_LOG2("transaction %p sends %s %s HTTP/%u.%u", (void *)t, t->method, vh_log_path(t->path, path, sizeof(path)),
		        (unsigned)t->client->major, (unsigned)t->client->minor);
		for (unsigned i = 0; i < t->request.count; ++i)
			VH_LOG2("transaction %p > %s: %s", (void *)t, t->request.items[i].name,
			        vh_log_header(t->request.items[i].name, t->request.items[i].value, hidden, sizeof(hidden)));
	}
#endif
	if (cookie != NULL)
		VH_LOG2("transaction %p > Cookie: (%u bytes)", (void *)t, (unsigned)strlen(cookie));
	vh_free(cookie);
	notify(t, CELL_HTTP_TRANSACTION_STATE_SENDING_REQUEST);
	rc = send_all(t, text, (size_t)used);
	vh_free(text);
	return rc;
}

static int read_line(VhTransaction *t, char *line, size_t size);

/* A tunnel through the proxy to the transaction's host, for https: CONNECT as Sony's sends it,
 * then its answer's head read; anything but a 2xx fails the request as a refused TLS connection */
static int tunnel(VhTransaction *t)
{
	char text[600];
	int length = snprintf(text, sizeof(text), "CONNECT %s:%u HTTP/%u.%u\r\nHost: %s:%u\r\nProxy-Connection: Keep-Alive\r\n\r\n",
	                      t->host, t->port, (unsigned)t->client->major, (unsigned)t->client->minor, t->host, t->port);
	VH_LOG("transaction %p: CONNECT %s:%u through the proxy", (void *)t, t->host, t->port);
	int rc = send_all(t, text, (size_t)length);
	if (rc != 0)
		return rc;
	char line[1024];
	t->have = t->at = 0;
	if ((rc = read_line(t, line, sizeof(line))) != 0)
		return rc;
	int ok = strncmp(line, "HTTP/", 5) == 0 && strchr(line, ' ') != NULL && strchr(line, ' ')[1] == '2';
	do {
		if ((rc = read_line(t, line, sizeof(line))) != 0)
			return rc;
	} while (line[0] != '\0');
	t->have = t->at = 0;
	if (!ok) {
		VH_LOG("transaction %p: the proxy refused the tunnel", (void *)t);
		return VH_ERROR_SSL_REFUSED;
	}
	return 0;
}

/* A kept connection to the transaction's host, or a new one, and the head on it; a kept one the
 * server closed meanwhile is replaced once */
static int open_and_send_head(VhTransaction *t)
{
	VhClient *client = t->client;
	notify(t, CELL_HTTP_TRANSACTION_STATE_GETTING_CONNECTION);
	void *ssl = NULL;
	t->via_proxy = proxied(t);
	char key[600];
	int fd = vh_client_take_idle(client, idle_key(t, key, sizeof(key)), t->port, t->https, &ssl);
	if (fd >= 0) {
		t->fd = fd;
		t->ssl = ssl;
		vh_tls_resume(t);
		int sent = send_head(t);
		if (sent == 0)
			return 0;
		/* A kept connection the server closed meanwhile is replaced once; any other failure
		 * (the game's cookie callback refusing) is the request's */
		unsigned kind = (unsigned)sent & 0xffffff00u;
		if (kind != VH_NET_SEND && kind != VH_NET_TLS_SEND) {
			vh_connection_closed(client, t, fd, ssl);
			t->fd = -1;
			t->ssl = NULL;
			return sent;
		}
		VH_LOG("transaction %p: the kept socket %d is gone, connecting again", (void *)t, fd);
		vh_connection_closed(client, t, fd, ssl);
		t->fd = -1;
		t->ssl = NULL;
	}
	const char *to = t->via_proxy ? client->proxy.host : t->host;
	unsigned to_port = t->via_proxy ? client->proxy.port : t->port;
	/* A redirected host gets 30 seconds at least to answer, as on the Vita */
	int64_t recv_timeout = client->recv_timeout;
	if (recv_timeout > 0 && recv_timeout < VH_REDIRECT_RECV_TIMEOUT && vh_redirect_is_target(t->host))
		recv_timeout = VH_REDIRECT_RECV_TIMEOUT;
	fd = vh_platform_connect(to, to_port, client->conn_timeout, client->send_timeout, recv_timeout);
	VH_LOG(fd >= 0 ? "transaction %p connects to %s:%u: socket %d" : "transaction %p connects to %s:%u: error 0x%08x", (void *)t, t->host, t->port,
	       fd);
	if (fd < 0)
		return fd;
	t->fd = fd;
	int rc = t->https && t->via_proxy ? tunnel(t) : 0;
	if (rc == 0 && t->https)
		rc = vh_tls_open(t);
	int opened = rc == 0;
	if (opened)
		vh_connection_state(client, t->fd, t, 0);
	if (rc == 0)
		rc = send_head(t);
	if (rc != 0) {
		if (opened)
			vh_connection_closed(client, t, t->fd, t->ssl);
		else
			vh_connection_close(client, t->fd, t->ssl);
		t->fd = -1;
		t->ssl = NULL;
	}
	return rc;
}

static int ensure_response(VhTransaction *t);

static int send_request(CellHttpTransId id, const void *data, size_t size, size_t *sent)
{
	WITH_TRANSACTION(id, t);
	if (sent != NULL)
		*sent = 0;
	if (t->aborted)
		return VH_ERROR_TRANS_ABORTED;
	if (!t->head_sent) {
		int rc = open_and_send_head(t);
		if (rc != 0)
			return rc;
		t->head_sent = 1;
	}
	if (data != NULL && size != 0) {
		notify(t, CELL_HTTP_TRANSACTION_STATE_SENDING_BODY);
		int rc = 0;
		if (t->chunked) {
			char line[24];
			int length = snprintf(line, sizeof(line), "%x\r\n", (unsigned)size);
			rc = send_all(t, line, (size_t)length);
			if (rc == 0)
				rc = send_all(t, data, size);
			if (rc == 0)
				rc = send_all(t, "\r\n", 2);
		} else
			rc = send_all(t, data, size);
		if (rc != 0)
			return rc;
		t->body_sent += size;
		if (sent != NULL)
			*sent = size;
	} else if (t->chunked && !t->request_complete) {
		/* A send of nothing ends a chunked body */
		int rc = send_all(t, "0\r\n\r\n", 5);
		if (rc != 0)
			return rc;
		t->request_complete = 1;
	}
	if (!t->chunked && (t->content_length < 0 || t->body_sent >= (uint64_t)t->content_length))
		t->request_complete = 1;
	/* A complete request has its response's head read here, as Sony's (which follows redirects,
	 * and calls the redirect callback, inside cellHttpSendRequest) */
	if (t->request_complete && !t->response_read) {
		notify(t, CELL_HTTP_TRANSACTION_STATE_WAITING_FOR_REPLY);
		return ensure_response(t);
	}
	return 0;
}

int cellHttpSendRequest(CellHttpTransId id, const void *data, size_t size, size_t *sent)
{
	int rc = send_request(id, data, size, sent);
	VH_LOG("cellHttpSendRequest %p %u bytes: 0x%08x", (void *)id, (unsigned)size, (unsigned)rc);
	return rc;
}

/* ---- reading ---- */

static int fill(VhTransaction *t)
{
	if (t->at == t->have)
		t->at = t->have = 0;
	if (t->have == sizeof(t->buffer)) {
		memmove(t->buffer, t->buffer + t->at, t->have - t->at);
		t->have -= t->at;
		t->at = 0;
	}
	unsigned char *at = t->buffer + t->have;
	size_t room = sizeof(t->buffer) - t->have;
	int got = t->ssl != NULL ? vh_tls_recv(t->ssl, at, room) : vh_platform_recv(t->fd, at, room);
	VH_LOG2("transaction %p read %d of %u", (void *)t, got, (unsigned)room);
	if (got > 0)
		t->have += (unsigned)got;
	return got;
}

/* A line without its CRLF into line (size bytes, cut there): 0, or the network's error, or
 * 0x80710059 when the connection ends first */
static int read_line(VhTransaction *t, char *line, size_t size)
{
	size_t length = 0;
	for (;;) {
		while (t->at < t->have) {
			char c = (char)t->buffer[t->at++];
			if (c == '\n') {
				if (length > 0 && line[length - 1] == '\r')
					--length;
				line[length] = '\0';
				return 0;
			}
			if (length + 1 < size)
				line[length++] = c;
		}
		int got = fill(t);
		if (got < 0)
			return got;
		if (got == 0)
			return VH_ERROR_INVALID_DATA;
	}
}

/* "HTTP/1.1 200 OK" */
static int parse_status(VhTransaction *t, const char *line)
{
	if (strncmp(line, "HTTP/", 5) != 0)
		return VH_ERROR_INVALID_DATA;
	const char *at = line + 5;
	unsigned major = (unsigned)decimal(at, &at);
	if (*at++ != '.')
		return VH_ERROR_INVALID_DATA;
	unsigned minor = (unsigned)decimal(at, &at);
	if (*at != ' ')
		return VH_ERROR_INVALID_DATA;
	while (*at == ' ')
		++at;
	const char *digits = at;
	int code = (int)decimal(at, &at);
	if (at == digits)
		return VH_ERROR_INVALID_DATA;
	const char *reason = at;
	while (*reason == ' ')
		++reason;
	char *copy = vh_strdup(reason);
	if (copy == NULL)
		return VH_ERROR_NO_MEMORY;
	vh_free(t->reason);
	t->reason = copy;
	t->major = major;
	t->minor = minor;
	t->status = code;
	return 0;
}

/* The status line and headers; 1xx responses are skipped */
static int read_head(VhTransaction *t)
{
	char line[1024];
	for (;;) {
		int rc = read_line(t, line, sizeof(line));
		if (rc != 0)
			return rc;
		if ((rc = parse_status(t, line)) != 0)
			return rc;
		vh_headers_clear(&t->response);
		for (;;) {
			if ((rc = read_line(t, line, sizeof(line))) != 0)
				return rc;
			if (line[0] == '\0')
				break;
			char *colon = strchr(line, ':');
			if (colon == NULL)
				continue;
			*colon = '\0';
			char *value = colon + 1;
			while (*value == ' ' || *value == '\t')
				++value;
			size_t end = strlen(value);
			while (end > 0 && (value[end - 1] == ' ' || value[end - 1] == '\t'))
				value[--end] = '\0';
			if ((rc = vh_headers_add(&t->response, line, value)) != 0)
				return rc;
		}
#if VITALS_DEBUG >= 1
		VH_LOG("transaction %p: HTTP %u.%u %d, %u headers", (void *)t, (unsigned)t->major, (unsigned)t->minor,
		       (int)t->status, t->response.count);
#if VITALS_DEBUG >= 2
		for (unsigned i = 0; i < t->response.count; ++i) {
			char hidden[24];
			VH_LOG2("transaction %p < %s: %s", (void *)t, t->response.items[i].name,
			        vh_log_header(t->response.items[i].name, t->response.items[i].value, hidden, sizeof(hidden)));
		}
#endif
#endif
		if (t->status < 100 || t->status >= 200) {
			/* The cookies it sets, for a client with cookies on (cookie.c) */
			for (unsigned i = 0; t->client->cookies && i < t->response.count; ++i)
				if (vh_equal_nocase(t->response.items[i].name, "Set-Cookie") &&
				    (rc = vh_cookie_receive(t, t->response.items[i].value)) != 0)
					return rc;
			return 0;
		}
	}
}

static const char *response_header(VhTransaction *t, const char *name)
{
	int at = vh_headers_find(&t->response, name);
	return at >= 0 ? t->response.items[at].value : NULL;
}

static int contains_nocase(const char *text, const char *word)
{
	size_t length = strlen(word);
	for (; *text != '\0'; ++text) {
		size_t i = 0;
		while (i < length && text[i] != '\0' &&
		       (text[i] | 32) == (word[i] | 32))
			++i;
		if (i == length)
			return 1;
	}
	return 0;
}

/* How the body ends, and whether the server closes after it */
static void body_kind(VhTransaction *t)
{
	const char *connection = response_header(t, "Connection");
	/* "Connection: close", or HTTP/1.0 without keep-alive */
	t->server_closes = connection != NULL && contains_nocase(connection, "close");
	if (t->major == 1 && t->minor == 0 && (connection == NULL || !contains_nocase(connection, "keep-alive")))
		t->server_closes = 1;
	const char *encoding = response_header(t, "Transfer-Encoding");
	const char *length = response_header(t, "Content-Length");
	t->chunk_crlf = 0;
	t->left = 0;
	if (vh_equal_nocase(t->method, "HEAD") || t->status == 204 || t->status == 304)
		t->body = VH_BODY_NONE;
	else if (encoding != NULL && contains_nocase(encoding, "chunked"))
		t->body = VH_BODY_CHUNKED;
	else if (length != NULL) {
		t->body = VH_BODY_LENGTH;
		t->left = decimal(length, NULL);
	} else
		t->body = VH_BODY_CLOSE;
	t->body_done = t->body == VH_BODY_NONE || (t->body == VH_BODY_LENGTH && t->left == 0);
}

static int read_body(VhTransaction *t, void *data, size_t size, size_t *got);

#define SCHEME_SIZE 16
#define HOST_SIZE 256
#define PATH_SIZE 1024

/* Where a redirect goes, as a URI in the buffers: an absolute URI, or a path on the same host */
static int resolve(VhTransaction *t, const char *location, CellHttpUri *out, char scheme[SCHEME_SIZE],
                   char host[HOST_SIZE], char path[PATH_SIZE])
{
	CellHttpUri uri;
	memset(&uri, 0, sizeof(uri));
	unsigned port = 0;
	const char *rest = strstr(location, "://");
	if (rest != NULL) {
		size_t length = (size_t)(rest - location);
		if (length >= SCHEME_SIZE)
			return VH_ERROR_INVALID_URI;
		memcpy(scheme, location, length);
		scheme[length] = '\0';
		rest += 3;
		size_t host_length = strcspn(rest, ":/?");
		if (host_length == 0 || host_length >= HOST_SIZE)
			return VH_ERROR_INVALID_URI;
		memcpy(host, rest, host_length);
		host[host_length] = '\0';
		rest += host_length;
		if (*rest == ':')
			port = (unsigned)decimal(rest + 1, &rest);
		snprintf(path, PATH_SIZE, "%s", *rest != '\0' ? rest : "/");
		uri.scheme = scheme;
		uri.hostname = host;
		uri.port = port != 0 ? port : default_port(scheme);
	} else {
		snprintf(scheme, SCHEME_SIZE, "%s", t->scheme);
		snprintf(host, HOST_SIZE, "%s", t->host);
		if (location[0] == '/')
			snprintf(path, PATH_SIZE, "%s", location);
		else {
			/* Next to the current path: its directory, then the location */
			const char *slash = strrchr(t->path, '/');
			size_t keep = slash != NULL ? (size_t)(slash - t->path) + 1 : 0, length = strlen(location);
			if (keep + length + 1 > PATH_SIZE)
				return VH_ERROR_INVALID_URI;
			memcpy(path, t->path, keep);
			memcpy(path + keep, location, length + 1);
		}
		uri.scheme = scheme;
		uri.hostname = host;
		uri.port = t->port;
	}
	uri.path = path;
	uri.username = uri.password = "";
	*out = uri;
	return 0;
}

static int follow(VhTransaction *t, const char *location)
{
	CellHttpUri uri;
	char scheme[SCHEME_SIZE], host[HOST_SIZE], path[PATH_SIZE];
	int rc = resolve(t, location, &uri, scheme, host, path);
	if (rc == 0)
		rc = take_uri(t, &uri);
	if (rc == 0)
		rc = host_header(t);
	return rc;
}

/* The response's head, once the request is sent, following redirects */
static int read_response(VhTransaction *t)
{
	if (t->response_read)
		return 0;
	if (!t->head_sent || t->fd < 0)
		return VH_ERROR_NO_CONNECTION;
	if (!t->request_complete)
		return VH_ERROR_REQUEST_INCOMPLETE;
	for (int redirects = 0;; ++redirects) {
		int rc = read_head(t);
		if (rc != 0)
			return rc;
		body_kind(t);
		const char *location = response_header(t, "Location");
		int moved = t->status == 301 || t->status == 302 || t->status == 303 || t->status == 307 || t->status == 308;
		if (!moved || location == NULL || !t->client->auto_redirect) {
			/* A 401 answered with credentials (auth.c), asked again on the same transaction */
			const char *challenge = response_header(t, "WWW-Authenticate");
			if (t->status != 401 || challenge == NULL || !t->client->auto_authentication)
				break;
			char copy[1024];
			snprintf(copy, sizeof(copy), "%s", challenge);
			if ((rc = vh_auth_answer(t, copy)) != 0)
				return rc;
			unsigned char drain[512];
			size_t got = 0;
			while (!t->body_done && (rc = read_body(t, drain, sizeof(drain), &got)) == 0 && got != 0)
				;
			if (rc != 0)
				return rc;
			release_connection(t, 1);
			if ((rc = open_and_send_head(t)) != 0)
				return rc;
			notify(t, CELL_HTTP_TRANSACTION_STATE_WAITING_FOR_REPLY);
			continue;
		}
		if (redirects == MAX_REDIRECTS)
			return VH_ERROR_TOO_MANY_REDIRECTS;
		char target[1024];
		snprintf(target, sizeof(target), "%s", location);
		notify(t, CELL_HTTP_TRANSACTION_STATE_SETTING_REDIRECTION);
		VhClient *client = t->client;
		if (client->callbacks[VH_CALLBACK_REDIRECT] != NULL) {
			CellHttpUri from, to;
			char scheme[16], host[256], path[1024];
			memset(&from, 0, sizeof(from));
			from.scheme = t->scheme, from.hostname = t->host, from.username = t->username;
			from.password = t->password, from.path = t->path, from.port = t->port;
			if ((rc = resolve(t, target, &to, scheme, host, path)) != 0)
				return rc;
			CellHttpStatusLine line;
			memset(&line, 0, sizeof(line));
			line.protocol = "HTTP";
			line.majorVersion = t->major;
			line.minorVersion = t->minor;
			line.statusCode = t->status;
			line.reasonPhrase = t->reason != NULL ? t->reason : "";
			CellHttpRedirectCallback callback = (CellHttpRedirectCallback)client->callbacks[VH_CALLBACK_REDIRECT];
			int answer = callback((CellHttpTransId)t, &line, &from, &to, client->callback_arguments[VH_CALLBACK_REDIRECT]);
			if (answer != 0) {
				VH_LOG("transaction %p: the game's redirect callback said %d", (void *)t, answer);
				return VH_ERROR_REDIRECT_REFUSED;
			}
		}
		/* The rest of this response, then the connection back, before asking again */
		notify(t, CELL_HTTP_TRANSACTION_STATE_GETTING_CONNECTION);
		notify(t, CELL_HTTP_TRANSACTION_STATE_READING_REPLY);
		unsigned char drain[512];
		size_t got = 0;
		while (!t->body_done && (rc = read_body(t, drain, sizeof(drain), &got)) == 0 && got != 0)
			;
		if (rc != 0)
			return rc;
		release_connection(t, 1);
		if (t->status == 303 || ((t->status == 301 || t->status == 302) && vh_equal_nocase(t->method, "POST"))) {
			char *get = vh_strdup("GET");
			if (get == NULL)
				return VH_ERROR_NO_MEMORY;
			vh_free(t->method);
			t->method = get;
			vh_headers_delete(&t->request, "Content-Length");
			t->content_length = -1;
		}
#if VITALS_DEBUG >= 1
		{
			char path[96];
			VH_LOG("transaction %p: redirect %d to %s", (void *)t, (int)t->status, vh_log_path(target, path, sizeof(path)));
		}
#endif
		if ((rc = follow(t, target)) != 0 || (rc = open_and_send_head(t)) != 0)
			return rc;
		notify(t, CELL_HTTP_TRANSACTION_STATE_WAITING_FOR_REPLY);
	}
	t->response_read = 1;
	/* gzip on (unnamed.c's flag): a gzip body read whole and given decoded, without its
	 * Content-Length, as Sony's (its Content-Encoding stays) */
	const char *encoding = response_header(t, "Content-Encoding");
	if (t->client->gzip && encoding != NULL && contains_nocase(encoding, "gzip") && !t->body_done) {
		unsigned char *raw = NULL, chunk[1024];
		size_t length = 0, capacity = 0, got = 0;
		int rc = 0;
		while (!t->body_done && (rc = read_body(t, chunk, sizeof(chunk), &got)) == 0 && got != 0) {
			if (length + got > capacity) {
				size_t grown_size = capacity != 0 ? capacity * 2 : 8192;
				while (grown_size < length + got)
					grown_size *= 2;
				unsigned char *grown = vh_alloc(grown_size);
				if (grown == NULL) {
					vh_free(raw);
					return VH_ERROR_NO_MEMORY;
				}
				if (length > 0)
					memcpy(grown, raw, length);
				vh_free(raw);
				raw = grown;
				capacity = grown_size;
			}
			memcpy(raw + length, chunk, got);
			length += got;
		}
		if (rc != 0) {
			vh_free(raw);
			return rc;
		}
		unsigned char *decoded = NULL;
		size_t decoded_size = 0;
		int bad = vh_gunzip(raw, length, &decoded, &decoded_size);
		vh_free(raw);
		if (bad)
			return VH_ERROR_INVALID_DATA;
		(void)vh_headers_delete(&t->response, "Content-Length");
		vh_free(t->cached_body);
		t->cached_body = decoded;
		t->cached_length = decoded_size;
		t->cached_at = 0;
		t->body_done = decoded_size == 0;
		return 0;
	}
	/* The cache (cache.c): a 304 to its If-Modified-Since is what it kept; a 200 may be kept */
	if (t->cache_revalidating && t->status == 304) {
		release_connection(t, KEEP_OR_LEAVE);
		if (vh_cache_serve(t))
			return 0;
	} else if (t->status == 200)
		vh_cache_consider(t);
	if (t->body_done) {
		vh_cache_store(t);
		release_connection(t, KEEP_OR_LEAVE);
	}
	return 0;
}

/* Any getter may be what reads the response: its failure at level 1, whichever asked */
static int ensure_response(VhTransaction *t)
{
	int rc = read_response(t);
	if (rc != 0)
		VH_LOG("transaction %p: no response, 0x%08x", (void *)t, (unsigned)rc);
	return rc;
}

static unsigned long long hex_value(const char *text, int *ok)
{
	unsigned long long value = 0;
	int digits = 0;
	for (; *text != '\0' && *text != ';' && *text != ' '; ++text, ++digits) {
		char c = *text;
		int digit = c >= '0' && c <= '9' ? c - '0' : (c | 32) >= 'a' && (c | 32) <= 'f' ? (c | 32) - 'a' + 10 : -1;
		if (digit < 0) {
			*ok = 0;
			return 0;
		}
		value = value * 16 + (unsigned)digit;
	}
	*ok = digits > 0;
	return value;
}

/* Up to size bytes of the body into data: *got 0 at its end */
static int read_body(VhTransaction *t, void *data, size_t size, size_t *got)
{
	*got = 0;
	if (t->cached_body != NULL) {
		size_t take = t->cached_length - t->cached_at;
		if (take > size)
			take = size;
		memcpy(data, t->cached_body + t->cached_at, take);
		t->cached_at += take;
		*got = take;
		t->body_done = t->cached_at == t->cached_length;
		return 0;
	}
	while (!t->body_done && size != 0) {
		if (t->body == VH_BODY_CHUNKED && t->left == 0) {
			char line[128];
			int rc;
			if (t->chunk_crlf) {
				if ((rc = read_line(t, line, sizeof(line))) != 0)
					return rc;
				t->chunk_crlf = 0;
			}
			if ((rc = read_line(t, line, sizeof(line))) != 0)
				return rc;
			int ok = 0;
			t->left = hex_value(line, &ok);
			if (!ok)
				return VH_ERROR_BROKEN_CHUNK;
			if (t->left == 0) {
				/* The trailer, to its blank line */
				do {
					if ((rc = read_line(t, line, sizeof(line))) != 0)
						return rc;
				} while (line[0] != '\0');
				t->body_done = 1;
				break;
			}
			t->chunk_crlf = 1;
		}
		if (t->at == t->have) {
			int rc = fill(t);
			if (rc < 0)
				return rc;
			if (rc == 0) {
				if (t->body == VH_BODY_CLOSE) {
					t->body_done = 1;
					break;
				}
				return VH_ERROR_INVALID_DATA;
			}
		}
		size_t take = t->have - t->at;
		if (take > size)
			take = size;
		if (t->body != VH_BODY_CLOSE && take > t->left)
			take = (size_t)t->left;
		memcpy(data, t->buffer + t->at, take);
		vh_cache_capture(t, data, take);
		t->at += (unsigned)take;
		*got = take;
		if (t->body != VH_BODY_CLOSE) {
			t->left -= take;
			if (t->body == VH_BODY_LENGTH && t->left == 0)
				t->body_done = 1;
		}
		break;
	}
	if (t->body_done) {
		vh_cache_store(t);
		release_connection(t, KEEP_OR_LEAVE);
	}
	return 0;
}

static int recv_response(CellHttpTransId id, void *data, size_t size, size_t *received)
{
	WITH_TRANSACTION(id, t);
	if (received != NULL)
		*received = 0;
	if (t->aborted)
		return VH_ERROR_TRANS_ABORTED;
	int rc = ensure_response(t);
	if (rc == 0)
		notify(t, CELL_HTTP_TRANSACTION_STATE_READING_REPLY);
	if (rc != 0)
		return rc;
	if (data == NULL && size != 0)
		return VH_ERROR_NO_BUFFER;
	size_t got = 0;
	rc = read_body(t, data, size, &got);
	if (received != NULL)
		*received = got;
	return rc;
}

/* Level 1 logs a read's errors and the body's end, level 2 every read */
int cellHttpRecvResponse(CellHttpTransId id, void *data, size_t size, size_t *received)
{
	size_t got = 0;
	int rc = recv_response(id, data, size, &got);
	if (received != NULL)
		*received = got;
#if VITALS_DEBUG >= 1
	if (rc != 0 || got == 0)
		VH_LOG("cellHttpRecvResponse %p: %u bytes, 0x%08x%s", (void *)id, (unsigned)got, (unsigned)rc,
		       rc == 0 ? " (the end)" : "");
	else
		VH_LOG2("cellHttpRecvResponse %p: %u of %u bytes", (void *)id, (unsigned)got, (unsigned)size);
#endif
	return rc;
}

/* ---- the response ---- */

int cellHttpResponseGetStatusCode(CellHttpTransId id, int32_t *code)
{
	WITH_TRANSACTION(id, t);
	if (code == NULL)
		return VH_ERROR_NO_BUFFER;
	int rc = ensure_response(t);
	if (rc != 0)
		return rc;
	*code = t->status;
	return 0;
}

int cellHttpResponseGetContentLength(CellHttpTransId id, uint64_t *length)
{
	WITH_TRANSACTION(id, t);
	if (length == NULL)
		return VH_ERROR_NO_BUFFER;
	int rc = ensure_response(t);
	if (rc != 0)
		return rc;
	const char *value = response_header(t, "Content-Length");
	if (value == NULL)
		return VH_ERROR_NO_CONTENT_LENGTH;
	*length = decimal(value, NULL);
	return 0;
}

int cellHttpResponseGetHeader(CellHttpTransId id, CellHttpHeader *header, const char *name, void *pool, size_t size,
                              size_t *required)
{
	WITH_TRANSACTION(id, t);
	int rc = ensure_response(t);
	if (rc != 0)
		return rc;
	return vh_headers_get(&t->response, header, name, pool, size, required);
}

int cellHttpResponseGetAllHeaders(CellHttpTransId id, CellHttpHeaderPtr *headers, size_t *items, void *pool,
                                  size_t size, size_t *required)
{
	WITH_TRANSACTION(id, t);
	int rc = ensure_response(t);
	if (rc != 0)
		return rc;
	return vh_headers_get_all(&t->response, headers, items, pool, size, required);
}

/* The protocol ("HTTP") and reason with a NUL each in the pool: "OK" takes 8 (the probe) */
int cellHttpResponseGetStatusLine(CellHttpTransId id, CellHttpStatusLine *status, void *pool, size_t size,
                                  size_t *required)
{
	WITH_TRANSACTION(id, t);
	if (status == NULL)
		return VH_ERROR_NO_BUFFER;
	int rc = ensure_response(t);
	if (rc != 0)
		return rc;
	size_t reason = strlen(t->reason) + 1, need = sizeof("HTTP") + reason;
	if (required != NULL)
		*required = need;
	if (pool == NULL)
		return 0;
	if (size < need)
		return VH_ERROR_INSUFFICIENT;
	char *text = pool;
	memcpy(text, "HTTP", sizeof("HTTP"));
	memcpy(text + sizeof("HTTP"), t->reason, reason);
	status->protocol = text;
	status->reasonPhrase = text + sizeof("HTTP");
	status->majorVersion = t->major;
	status->minorVersion = t->minor;
	status->statusCode = t->status;
	return 0;
}

/* The transaction's connection closed: its own, or the one it gave back to be kept, as Sony's */
static void close_own_connection(VhTransaction *t)
{
	if (t->fd >= 0)
		release_connection(t, 0);
	else if (t->head_sent && !t->released) {
		char key[600];
		void *ssl = NULL;
		int fd = vh_client_take_idle(t->client, idle_key(t, key, sizeof(key)), t->port, t->https, &ssl);
		if (fd >= 0)
			vh_connection_closed(t->client, t, fd, ssl);
	}
}

int cellHttpTransactionCloseConnection(CellHttpTransId id)
{
	VH_LOG("cellHttpTransactionCloseConnection %p", (void *)id);
	WITH_TRANSACTION(id, t);
	close_own_connection(t);
	return 0;
}

int cellHttpTransactionAbortConnection(CellHttpTransId id)
{
	VH_LOG("cellHttpTransactionAbortConnection %p", (void *)id);
	WITH_TRANSACTION(id, t);
	t->aborted = 1;
	release_connection(t, 0);
	return 0;
}

/* ---- the URI, chunked bodies, the connection handed over ---- */

/* The URI the transaction asks (where a redirect led), as cellHttpUtilCopyUri gives one */
int cellHttpTransactionGetUri(CellHttpTransId id, CellHttpUri *uri, void *pool, size_t size, size_t *required)
{
	WITH_TRANSACTION(id, t);
	CellHttpUri current;
	memset(&current, 0, sizeof(current));
	current.scheme = t->scheme, current.hostname = t->host, current.username = t->username;
	current.password = t->password, current.path = t->path, current.port = t->port;
	return cellHttpUtilCopyUri(uri, &current, pool, size, required);
}

/* Before the request is sent (0x80710015 after): the URI, and the Host header with it; checked as
 * cellHttpCreateTransaction checks one */
int cellHttpTransactionSetUri(CellHttpTransId id, const CellHttpUri *uri)
{
	WITH_TRANSACTION(id, t);
	if (t->head_sent)
		return VH_ERROR_ALREADY_SENT;
	if (uri == NULL)
		return VH_ERROR_INVALID_URI;
	int rc = take_uri(t, uri);
	if (rc == 0)
		rc = host_header(t);
	return rc;
}

int cellHttpRequestGetChunkedTransferStatus(CellHttpTransId id, bool *enable)
{
	WITH_TRANSACTION(id, t);
	if (enable == NULL)
		return VH_ERROR_NO_BUFFER;
	*enable = t->chunked != 0;
	return 0;
}

/* Before the request is sent; not with a Content-Length (0x80710026). Its header, as Sony's puts
 * it, right after Connection; each send is then a chunk, and a send of nothing ends the body */
int cellHttpRequestSetChunkedTransferStatus(CellHttpTransId id, bool enable)
{
	VH_LOG("cellHttpRequestSetChunkedTransferStatus %p %d", (void *)id, enable ? 1 : 0);
	WITH_TRANSACTION(id, t);
	if (t->head_sent)
		return VH_ERROR_ALREADY_SENT;
	if (enable && t->content_length >= 0)
		return VH_ERROR_CHUNKED_WITH_LENGTH;
	int rc = 0;
	if (enable && !t->chunked) {
		int connection = vh_headers_find(&t->request, "Connection");
		rc = vh_headers_insert(&t->request, connection >= 0 ? (unsigned)connection + 1 : t->request.count,
		                       "Transfer-Encoding", "chunked");
	} else if (!enable && t->chunked)
		(void)vh_headers_delete(&t->request, "Transfer-Encoding");
	if (rc == 0)
		t->chunked = enable ? 1 : 0;
	return rc;
}

/* The connection's socket, the game's from now on: the client won't use it again. Once a request
 * was sent (0x80710020 before), once (0x80710054 again) */
int cellHttpTransactionReleaseConnection(CellHttpTransId id, int *sid)
{
	VH_LOG("cellHttpTransactionReleaseConnection %p", (void *)id);
	WITH_TRANSACTION(id, t);
	if (sid == NULL)
		return VH_ERROR_NO_BUFFER;
	if (t->released)
		return VH_ERROR_RELEASED;
	if (!t->head_sent)
		return VH_ERROR_NOT_SENT;
	int fd = t->fd;
	if (fd < 0)
	{
		char key[600];
		fd = vh_client_take_idle(t->client, idle_key(t, key, sizeof(key)), t->port, t->https, &t->ssl);
	}
	if (fd < 0)
		return VH_ERROR_NO_CONNECTION;
	/* TLS state goes; the socket stays open for the game */
	vh_tls_close_quietly(t->ssl);
	t->ssl = NULL;
	t->fd = -1;
	t->released = 1;
	*sid = fd;
	return 0;
}

/* ---- unnamed variants and getters ---- */

/* cellHttpRequestSetHeader's own function with its flag the other way; in every case the probe
 * tried, the same as cellHttpRequestSetHeader */
int cellHttp_313D80D5(CellHttpTransId id, const CellHttpHeader *header)
{
	return cellHttpRequestSetHeader(id, header);
}

/* cellHttpSendRequest's own function with its flag the other way; as cellHttpSendRequest in the
 * probe's cases */
int cellHttp_DCD9D484(CellHttpTransId id, const void *data, size_t size, size_t *sent)
{
	return cellHttpSendRequest(id, data, size, sent);
}

/* cellHttpTransactionCloseConnection's own function with its flag the other way: the
 * transaction's connection closed, a kept one included; 0x80710054 a second time */
int cellHttp_3E30440C(CellHttpTransId id)
{
	VH_LOG("cellHttp_3E30440C %p", (void *)id);
	WITH_TRANSACTION(id, t);
	if (t->released)
		return VH_ERROR_RELEASED;
	close_own_connection(t);
	t->released = 1;
	return 0;
}

/* A byte of the transaction's, 0 in every case the probe saw, once its request is complete
 * (0x80710013 before) */
int cellHttp_E0CAF386(CellHttpTransId id, uint8_t *out)
{
	WITH_TRANSACTION(id, t);
	if (out == NULL)
		return VH_ERROR_NO_BUFFER;
	if (!t->request_complete)
		return VH_ERROR_REQUEST_INCOMPLETE;
	*out = 0;
	return 0;
}

/* Something of the transaction's connection, nonzero, once it was sent (0x80710020 before):
 * vitals' gives its socket */
int cellHttp_8633468C(CellHttpTransId id, uint32_t *out)
{
	WITH_TRANSACTION(id, t);
	if (out == NULL)
		return VH_ERROR_NO_BUFFER;
	if (!t->head_sent)
		return VH_ERROR_NOT_SENT;
	*out = t->fd >= 0 ? (uint32_t)t->fd : 1;
	return 0;
}
