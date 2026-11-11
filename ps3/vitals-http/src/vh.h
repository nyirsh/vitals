#ifndef VITALS_HTTP_VH_H
#define VITALS_HTTP_VH_H

/* vitals' libhttp: its objects and what the platform gives it. The API is Sony's cellHttp (PS3DK's
 * <cell/http.h>); what each function does is checked against Sony's libhttp running in RPCS3 with
 * the probe (tests/http-probe) */

#include <stddef.h>
#include <stdint.h>

/* Sony's error codes (CELL_HTTP_ERROR_*), and the network ones: a class, then the system's errno or
 * the resolver's in the low byte, as Sony's libhttp makes them (0x10c4 and 0x5e4): 0x100 the
 * resolver, 0x300 a socket option, 0x500 connect, 0x600 send, 0x700 receive, 0x800 select, and
 * 0x80710093 a wait that timed out. In RPCS3 a refused connection shows as 0x80710316: the receive
 * timeout's option failing (EINVAL) on the dead socket, after connect's EINPROGRESS */
#define VH_ERROR_ALREADY_INITIALIZED ((int)0x80710001)
#define VH_ERROR_NOT_INITIALIZED ((int)0x80710002)
#define VH_ERROR_NO_MEMORY ((int)0x80710003)
#define VH_ERROR_NO_BUFFER ((int)0x80710004)
#define VH_ERROR_INSUFFICIENT ((int)0x80710006)
#define VH_ERROR_INVALID_URI ((int)0x80710007)
#define VH_ERROR_BAD_METHOD ((int)0x80710009)
#define VH_ERROR_BAD_CLIENT ((int)0x80710010)
#define VH_ERROR_BAD_TRANS ((int)0x80710011)
#define VH_ERROR_NO_CONNECTION ((int)0x80710012)
#define VH_ERROR_REQUEST_INCOMPLETE ((int)0x80710013) /* the request's body isn't all sent */
#define VH_ERROR_ALREADY_SENT ((int)0x80710015)
#define VH_ERROR_NOT_SENT ((int)0x80710020)
#define VH_ERROR_REDIRECT_REFUSED ((int)0x80710021) /* the game's redirect callback */
#define VH_ERROR_CHUNKED_WITH_LENGTH ((int)0x80710026)
#define VH_ERROR_RELEASED ((int)0x80710054)
#define VH_ERROR_NO_HEADER ((int)0x80710016)
#define VH_ERROR_NO_CONTENT_LENGTH ((int)0x80710017)
#define VH_ERROR_TOO_MANY_REDIRECTS ((int)0x80710018)
#define VH_ERROR_TRANS_ABORTED ((int)0x80710024)
#define VH_ERROR_INVALID_VALUE ((int)0x80710027)
#define VH_ERROR_INVALID_DATA ((int)0x80710059)
#define VH_ERROR_BROKEN_CHUNK ((int)0x8071005a)
#define VH_NET_RESOLVER 0x80710100u
#define VH_NET_OPTION 0x80710300u
#define VH_NET_CONNECT 0x80710500u
#define VH_NET_SEND 0x80710600u
#define VH_NET_RECV 0x80710700u
#define VH_NET_SELECT 0x80710800u
#define VH_ERROR_TIMEOUT ((int)0x80710093)
/* https (tls.c): a handshake that failed, the certificate check's refusal included (Sony's), then
 * libssl's failures after it, SSL_get_error's kind in the low byte: 0xc00 sending, 0xd00 receiving */
#define VH_ERROR_SSL_REFUSED ((int)0x80710a06)
#define VH_ERROR_BAD_CA ((int)0x80710a01)
#define VH_NET_TLS_SEND 0x80710c00u
#define VH_NET_TLS_RECV 0x80710d00u
#define VH_NET_ERROR(kind, code) ((int)((kind) | ((unsigned)(code) & 0xffu)))

/* The debug log (VITALS_DEBUG, make http DEBUG=1 or 2), in /dev_hdd0/vitals/logs/vitals.log as "vitals-http:"
 * lines: 0 none; 1 the calls that do something (init, clients, their settings, transactions,
 * requests, responses) and their errors, each connection (made, reused, kept, closed), each
 * handshake and the certificate check's findings, the game's SSL callback's answer, redirects;
 * 2 also every getter, every read and write, and the request's and response's headers. Secrets
 * are logged as their length only: Cookie, Set-Cookie, Authorization and any header whose name
 * says token, session, ticket, key, secret, password, signature or auth; a URL's query too */
/* Its log (vitals/log.h), through vh_log, as vitals.log and the TTY take whole lines */
#define VITALS_LOG_PRINTF vh_log
#include "vitals/log.h"
/* What a log line may show of a header's value (into buffer, as "(N bytes)" for a secret) and of
 * a path (its query as "?(N bytes)") */
const char *vh_log_header(const char *name, const char *value, char *buffer, size_t size);
const char *vh_log_path(const char *path, char *buffer, size_t size);

/* A header, its name and value in the pool */
typedef struct VhHeader {
	char *name, *value;
} VhHeader;

typedef struct VhHeaders {
	VhHeader *items;
	unsigned count, capacity;
} VhHeaders;

/* A connection kept open after a response (keep-alive), for the next request to the same place */
typedef struct VhIdle {
	struct VhIdle *next;
	char *host;
	unsigned port;
	int fd;
	void *ssl; /* libssl's connection on fd, for https */
} VhIdle;

/* A proxy as libhttp or a client keeps it (proxy.c): its URI's parts, NULL ones as "" */
typedef struct VhProxy {
	int set;
	char *scheme, *host, *path, *username, *password;
	unsigned port;
} VhProxy;

#define VH_CLIENT_MAGIC 0x56484331u /* "VHC1" */
#define VH_TRANS_MAGIC 0x56485431u  /* "VHT1" */

typedef struct VhClient {
	uint32_t magic;
	struct VhClient *self, *next;
	uint32_t major, minor;
	uint8_t keep_alive, pipeline, auto_redirect, auto_authentication, authentication_cache, cookies,
	    connection_wait;
	int64_t conn_timeout, recv_timeout, send_timeout, connection_wait_timeout;
	uint32_t total_pool_size, per_host_pool_size, per_host_keep_alive_max, per_pipeline_max,
	    response_buffer_max;
	int recv_buffer_size, send_buffer_size;
	int32_t ssl_version, min_ssl_version;
	char *user_agent;
	VhHeaders headers;
	VhIdle *idle;
	/* Callbacks the game gives, in their slots (VH_CALLBACK_*) */
	void *callbacks[10], *callback_arguments[10];
	/* libssl's context for this client's https connections, made at the first (tls.c) */
	void *ssl_context;
	/* libhttp's proxy when the client was made, or its own (proxy.c) */
	VhProxy proxy;
	/* Its transactions, for cellHttpClientPollConnections */
	struct VhTransaction *transactions;
	/* cellHttpClientSetCacheStatus (cache.c) */
	uint8_t cache;
	/* The flags and values Sony's has no published name for (unnamed.c), in its tables' slots:
	 * flags 5, 6, 8 (the external cache's), 9 (the subsystem's), 10 gzip, the connection-wait
	 * table's 0; sizes 4 to 7 and 10; buffer values 1 to 3 */
	uint8_t flag5, flag6, flag8, flag9, gzip, wait0;
	uint32_t size4, size5, size6, size7, size10, buffer1, buffer2, buffer3;
} VhClient;

enum {
	VH_CALLBACK_AUTHENTICATION,
	VH_CALLBACK_STATE,
	VH_CALLBACK_REDIRECT,
	VH_CALLBACK_COOKIE_SEND,
	VH_CALLBACK_COOKIE_RECV,
	VH_CALLBACK_SSL,
	VH_CALLBACK_SSL_ID_DESTROY,
	VH_CALLBACK_CONNECTION_STATE,
	VH_CALLBACK_CACHE,
};

/* How a response's body ends */
typedef enum { VH_BODY_NONE, VH_BODY_LENGTH, VH_BODY_CHUNKED, VH_BODY_CLOSE } VhBody;

typedef struct VhTransaction {
	uint32_t magic;
	struct VhTransaction *self;
	VhClient *client;
	char *method, *scheme, *host, *path, *username, *password;
	unsigned port;
	VhHeaders request;
	int64_t content_length; /* -1 without one */
	int fd;
	int https;  /* the scheme is https */
	void *ssl;  /* libssl's connection on fd */
	/* The SSL getters' answers, from the connection's handshake (tls.c) */
	int has_ssl;
	char cipher_name[64], cipher_version[32], cipher_description[128];
	int bits_effective, bits_algorithm, cipher_id, ssl_version;
	const void *ssl_id;
	int head_sent, response_read, body_done, aborted;
	/* The request's body: chunked (cellHttpRequestSetChunkedTransferStatus), what was sent of it,
	 * and whether it's complete (then the response can be read) */
	int chunked, request_complete;
	uint64_t body_sent;
	/* cellHttpTransactionReleaseConnection gave its socket to the game */
	int released;
	/* Authentication (auth.c): the URI's credentials tried, the game's callback's answers so far,
	 * and the credentials tried last */
	int auth_tried_uri, auth_answers;
	char auth_username[256], auth_password[256];
	/* Through the client's proxy (proxy.c's settings): to it, or a CONNECT tunnel for https */
	int via_proxy;
	/* The cache (cache.c): asked If-Modified-Since; the body being kept as it's read; a 304's
	 * kept body, read from memory */
	int cache_revalidating, cache_capture;
	unsigned char *captured;
	size_t capture_length, capture_capacity;
	unsigned char *cached_body;
	size_t cached_length, cached_at;
	struct VhTransaction *next_in_client;
	/* The response */
	uint32_t major, minor;
	int32_t status;
	char *reason;
	VhHeaders response;
	VhBody body;
	uint64_t left; /* of the body (VH_BODY_LENGTH) or the current chunk (VH_BODY_CHUNKED) */
	int chunk_crlf, server_closes;
	/* What was read past what's been handed out */
	unsigned char buffer[2048];
	unsigned have, at;
} VhTransaction;

/* ---- core.c ---- */
int vh_initialized(void);
void *vh_alloc(size_t size);
void *vh_calloc(size_t size);
void vh_free(void *memory);
char *vh_strdup(const char *text);
void vh_lock(void);
void vh_unlock(void);
VhClient *vh_client(void *id);
VhTransaction *vh_transaction(void *id);
void vh_clients_add(VhClient *client);
void vh_clients_remove(VhClient *client);
int vh_equal_nocase(const char *a, const char *b);
/* text starts with word, case aside */
int vh_equal_nocase_prefix(const char *text, const char *word);

/* ---- headers.c ---- */
int vh_headers_add(VhHeaders *headers, const char *name, const char *value);
int vh_headers_insert(VhHeaders *headers, unsigned at, const char *name, const char *value);
int vh_headers_set(VhHeaders *headers, const char *name, const char *value);
int vh_headers_delete(VhHeaders *headers, const char *name);
int vh_headers_find(const VhHeaders *headers, const char *name);
void vh_headers_clear(VhHeaders *headers);
/* The getters' pool rules: a header (or all of them, an array then the strings) copied into pool;
 * *required is what that takes, given even without a pool. 0; the errors as Sony's */
int vh_headers_get(const VhHeaders *headers, void *out, const char *name, void *pool, size_t size, size_t *required);
int vh_headers_get_all(const VhHeaders *headers, void *out, size_t *items, void *pool, size_t size, size_t *required);

/* ---- client.c ---- */
void vh_client_free(VhClient *client);
/* A kept connection to host:port (with its TLS for https), -1 without one */
int vh_client_take_idle(VhClient *client, const char *host, unsigned port, int https, void **ssl);
void vh_client_keep_idle(VhClient *client, const char *host, unsigned port, int fd, void *ssl);
/* A connection closed: its TLS, then its socket */
/* The connection-state callback's call (state 0 opened, 1 closed), and a close with it */
void vh_connection_state(VhClient *client, int fd, const VhTransaction *t, uint32_t state);
void vh_connection_closed(VhClient *client, const VhTransaction *t, int fd, void *ssl);
void vh_connection_close(VhClient *client, int fd, void *ssl);

/* ---- proxy.c ---- */
#define VH_UTIL_ERROR_NO_MEMORY ((int)0x80711001)
#define VH_UTIL_ERROR_NO_BUFFER ((int)0x80711002)
void vh_proxy_clear(VhProxy *proxy);
/* libhttp's proxy into a new client's */
int vh_proxy_inherit(VhProxy *proxy);
/* At cellHttpEnd: libhttp's proxy goes with the heap it's in */
void vh_proxy_end(void);

/* ---- auth.c ---- */
/* Credentials for a 401's WWW-Authenticate, into the request's Authorization header: 0 to ask
 * again, or the request's error */
int vh_auth_answer(VhTransaction *t, const char *challenge);

/* ---- cache.c ---- */
int vh_cache_condition(VhTransaction *t, char date[40]);
int vh_cache_serve(VhTransaction *t);
void vh_cache_consider(VhTransaction *t);
void vh_cache_capture(VhTransaction *t, const void *data, size_t size);
void vh_cache_store(VhTransaction *t);
void vh_cache_end(void);
int vh_cache_initialized(void);
int vh_external_cache_initialized(void);

/* ---- inflate.c ---- */
/* A gzip body decoded into *out (vh_free it): 0, or -1 for one that isn't */
int vh_gunzip(const unsigned char *data, size_t size, unsigned char **out, size_t *out_size);

/* ---- unnamed.c ---- */
int vh_subsystem_initialized(void);

/* ---- transaction.c ---- */
/* The game's transaction-state callback, its answer ignored */
void vh_notify_state(VhTransaction *t, int32_t state);

/* ---- tls.c ---- */
int vh_tls_initialized(void);
void vh_tls_client_free(VhClient *client);
/* The handshake on t->fd, to t->host: 0 with t->ssl set, or the error */
int vh_tls_open(VhTransaction *t);
void vh_tls_resume(VhTransaction *t);
void vh_tls_close(void *ssl);
void vh_tls_close_quietly(void *ssl);
int vh_tls_send(void *ssl, const void *data, size_t size);
int vh_tls_recv(void *ssl, void *data, size_t size);

/* ---- platform ---- */
int vh_platform_lock_create(void);
void vh_platform_lock_destroy(void);
void vh_platform_lock(void);
void vh_platform_unlock(void);
int vh_platform_pool_create(void *block, size_t size);
void vh_platform_pool_delete(void);
void *vh_platform_alloc(size_t size);
void vh_platform_free(void *memory);
/* The heap's free size, and its mallinfo (10 words) */
uint32_t vh_platform_pool_free_size(void);
void vh_platform_pool_mallinfo(uint32_t info[10]);
/* Waits up to timeout microseconds for one of the sockets to be readable: its index, -1 when
 * none was, or a VH_NET_* error */
int vh_platform_wait_readable(const int *fds, unsigned count, int64_t timeout);
/* 1 when the memory at pointer can be read (Sony's libhttp checks each ID so, syscall 351) */
int vh_platform_readable(const void *pointer);
/* A connected socket to host:port within timeout microseconds (0 or less: the system's): the fd,
 * or a VH_NET_* error */
int vh_platform_connect(const char *host, unsigned port, int64_t timeout, int64_t send_timeout, int64_t recv_timeout);
/* What was sent or received (0 when the peer closed), or a VH_NET_* error */
int vh_platform_send(int fd, const void *data, size_t size);
int vh_platform_recv(int fd, void *data, size_t size);
void vh_platform_close(int fd);
/* The cookie store's heap (on cellHttpInitCookie's block) and lock */
int vh_platform_cookie_create(void *block, size_t size);
void vh_platform_cookie_delete(void);
void vh_platform_cookie_lock(void);
void vh_platform_cookie_unlock(void);
void *vh_platform_cookie_alloc(size_t size);
void vh_platform_cookie_free(void *memory);
/* Seconds since 1970 */
int64_t vh_platform_now(void);
/* Up to size bytes of the file at path from offset: how many were read (0 past its end), or a
 * negative error (cellFs's, as when there's no file) */
int vh_platform_file_read(const char *path, unsigned offset, void *buffer, unsigned size);
/* 0 when there's a file or directory at path, else cellFs's error */
int vh_platform_stat(const char *path);

/* ---- md5.c ---- */
void vh_md5(const void *data, size_t size, unsigned char digest[16]);

/* ---- cookie.c ---- */
/* A response's Set-Cookie (its client's cookies on): 0, or an error for the response */
int vh_cookie_receive(VhTransaction *t, const char *header);
/* The Cookie header's value for t's request into *value (vh_free it; NULL for none): 0, or the
 * game's send callback's negative answer, or 0x80710003 */
int vh_cookie_header(VhTransaction *t, char **value);

/* ---- redirect.c: vitals' additions, the host redirect list and the User-Agent ---- */

/* At least this receive timeout for a host the list sends others to (microseconds) */
#define VH_REDIRECT_RECV_TIMEOUT 30000000
/* host, or the list's new host for it */
const char *vh_redirect_host(const char *host);
/* Whether host is one the list sends others to */
int vh_redirect_is_target(const char *host);
/* The default User-Agent, with useragent.txt's line in place of the library's part */
const char *vh_default_user_agent(void);
void vh_redirect_end(void);

#endif
