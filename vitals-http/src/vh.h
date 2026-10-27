#ifndef HTTP_VH_H
#define HTTP_VH_H

/* http's internals: the objects behind the IDs the API hands out, the settings they
 * inherit, and the platform the engine runs on (memory, locking, the network) */

#include "http_extra.h"

/* DEBUG=2: each call the app makes, by name, to find the last one before a crash */
#define VH_TRACE() VITALS_VERBOSE("call %s", __func__)

#include <stddef.h>
#include <stdint.h>

/* Templates, connections and requests share one ID space: the settings functions accept any
 * of them, and a connection or request starts with its parent's settings */
#define VH_OBJECT_MAX 256u
#define VH_HOST_MAX 256u
#define VH_PATH_MAX 2048u
#define VH_USER_AGENT_MAX 256u
#define VH_HEADER_NAME_MAX 128u
#define VH_HEADER_VALUE_MAX 2048u
#define VH_HEADERS_MAX 32u
#define VH_METHOD_MAX 16u
/* The firmware version the User-Agent names: the latest, whatever the console runs */
#define VH_USER_AGENT_VERSION "3.74"

#define VH_ERROR_UNSUPPORTED ((int)SCE_HTTP_ERROR_UNKNOWN)
/* A non-blocking call that hasn't finished; the SDK header doesn't name it */
#define VH_ERROR_EAGAIN ((int)0x80431082)

typedef enum VhKind
{
    VH_FREE = 0,
    VH_TEMPLATE,
    VH_CONNECTION,
    VH_REQUEST,
} VhKind;

typedef struct VhHeader
{
    char *name;
    char *value;
} VhHeader;

/* Request headers added with sceHttpAddRequestHeader at any level, in the order added */
typedef struct VhHeaders
{
    VhHeader items[VH_HEADERS_MAX];
    unsigned int count;
} VhHeaders;

/* What a template, connection or request carries and passes on to the ones created from it */
typedef struct VhSettings
{
    unsigned int resolve_timeout_us, connect_timeout_us, send_timeout_us, recv_timeout_us;
    int resolve_retry;
    int auto_redirect, auth_enabled, cookie_enabled;
    unsigned int response_header_max;
    SceHttpRedirectCallback redirect_callback;
    void *redirect_argument;
    SceHttpAuthInfoCallback auth_callback;
    void *auth_argument;
    SceHttpsCallback ssl_callback;
    void *ssl_argument;
    SceHttpCookieRecvCallback cookie_recv_callback;
    void *cookie_recv_argument;
    SceHttpCookieSendCallback cookie_send_callback;
    void *cookie_send_argument;
    /* Ask for gzip bodies (Accept-Encoding), and decompress the ones that come */
    int accept_gzip, inflate_gzip;
    /* HTTPS options turned on and off for this object, over the global ones */
    unsigned int https_enabled, https_disabled;
    /* Requests return VH_ERROR_EAGAIN instead of blocking, and report to the epoll when done */
    int nonblock;
    SceHttpEpollHandle epoll;
    void *epoll_argument;
    int epoll_id;
    VhHeaders headers;
} VhSettings;

typedef struct VhTransport VhTransport;
typedef struct VhInflater VhInflater;

typedef enum VhRequestState
{
    VH_REQUEST_CREATED = 0,
    /* Response headers read; the body is read with sceHttpReadData */
    VH_REQUEST_RESPONDED,
    /* The whole body has been read */
    VH_REQUEST_DONE,
    VH_REQUEST_FAILED,
} VhRequestState;

/* What a non-blocking request's worker thread does */
typedef enum VhAsync
{
    VH_ASYNC_NONE = 0,
    VH_ASYNC_SEND,
    VH_ASYNC_READ,
} VhAsync;

typedef enum VhBodyMode
{
    VH_BODY_NONE = 0,
    VH_BODY_LENGTH,
    VH_BODY_CHUNKED,
    VH_BODY_UNTIL_CLOSE,
} VhBodyMode;

/* Its User-Agent is a request header in its settings */
typedef struct VhTemplate
{
    int http_version;
} VhTemplate;

typedef struct VhConnection
{
    int https;
    char host[VH_HOST_MAX];
    unsigned short port;
    int keep_alive;
    /* The open socket of the last request, kept for the next one when the server allows it */
    VhTransport *transport;
    /* Requests using the connection, which can't be deleted before them */
    unsigned int requests;
    int ssl_error;
    unsigned int ssl_detail;
} VhConnection;

typedef struct VhRequest
{
    char method[VH_METHOD_MAX];
    char path[VH_PATH_MAX];
    /* Where the request goes: its connection's server, until a redirect sends it elsewhere */
    char host[VH_HOST_MAX];
    unsigned short port;
    int https;
    /* Set by the app with the request or sceHttpSetRequestContentLength; -1 when not */
    long long content_length;
    VhRequestState state;
    int status_code;
    /* The response's status line and headers, as received, NUL-terminated */
    char *response_header;
    unsigned int response_header_size;
    VhBodyMode body_mode;
    /* What is left of the body (VH_BODY_LENGTH) or of the current chunk (VH_BODY_CHUNKED) */
    unsigned long long body_left;
    long long response_content_length;
    /* The chunked body's last chunk was read; the trailer is next */
    int chunk_trailer_pending;
    /* The CRLF after a chunk's data is still to be read */
    int chunk_crlf_pending;
    /* Decompresses a gzip body, when there is one */
    VhInflater *inflater;
    /* The status line and headers last sent, for sceHttpRequestGetAllHeaders */
    char *request_header;
    unsigned int request_header_size;
    int last_errno;
    /* The start of a refused response's body went to the debug log */
    int body_logged;
    unsigned long long started_us; /* when the last exchange began, for the debug log */
    /* Bytes received after the headers, not yet handed to the app */
    unsigned char *pending;
    unsigned int pending_size, pending_offset, pending_capacity;
    /* The socket, owned by the request while it is in use */
    VhTransport *transport;
    /* The socket can stay open for the connection's next request */
    int reusable;
    volatile int aborted;
    int busy;
    int ssl_error;
    unsigned int ssl_detail;
    /* A non-blocking send or read: its result, once done, is returned by the app's next call */
    VhAsync async;
    int async_done;
    int async_result;
    /* Its epoll event was handed out */
    int async_reported;
    /* The body a non-blocking send sends, copied; the data a non-blocking read received */
    unsigned char *async_data;
    unsigned int async_size, async_offset;
} VhRequest;

typedef struct VhObject
{
    int id;
    VhKind kind;
    int parent;
    /* Deleted by the app while one of its requests was busy: gone for the API, freed when idle */
    int doomed;
    VhSettings settings;
    union
    {
        VhTemplate template_;
        VhConnection connection;
        VhRequest request;
    } as;
} VhObject;

/* ---- core.c ---- */

/* 0 once sceHttpInit succeeded, SCE_HTTP_ERROR_BEFORE_INIT before */
int vh_initialized(void);
void vh_lock(void);
void vh_unlock(void);
/* The object with that ID and kind (VH_FREE: any kind), with the lock held; NULL when there is
 * none, or the app deleted it */
VhObject *vh_find(int id, VhKind kind);
/* The object in a slot of the table (VH_OBJECT_MAX of them), with the lock held; NULL when free */
VhObject *vh_object_at(unsigned int slot);
/* A fresh object of that kind, inheriting parent's settings (or the defaults), with the lock
 * held; NULL when the table is full or memory runs out */
VhObject *vh_create(VhKind kind, VhObject *parent);
/* Frees an object and everything it owns, with the lock held */
void vh_destroy(VhObject *object);
/* The object an object was created from, with the lock held */
VhObject *vh_parent(VhObject *object);
/* The objects created from the object with that ID, up to max of them, with the lock held;
 * returns how many there are */
unsigned int vh_children(int id, VhObject **children, unsigned int max);

void *vh_alloc(size_t size);
void vh_free(void *pointer);
char *vh_strdup(const char *text, size_t length);
void vh_settings_copy(VhSettings *destination, const VhSettings *source);
/* sceHttpAddRequestHeader on settings, with the lock held, without its checks */
int vh_add_header(VhSettings *settings, const char *name, const char *value, unsigned int mode);
void vh_settings_free(VhSettings *settings);
/* The global HTTPS options (sceHttpsEnableOption), SERVER_VERIFY and the date and name checks by
 * default */
unsigned int vh_https_options(void);

/* The HTTPS options in effect for these settings */
unsigned int vh_https_options_of(const VhSettings *settings);
/* Frees what a request owns besides its object, with the lock held */
void vh_request_free(VhRequest *request);
/* Frees the objects the app deleted that are no longer busy, with the lock held */
void vh_reap(void);

/* ---- request.c, for async.c ---- */

/* The blocking part of sceHttpSendRequest and sceHttpReadData, without the lock */
int vh_request_perform(VhObject *object, const unsigned char *body, size_t body_size);
int vh_request_read(VhRequest *request, unsigned char *data, size_t size);
/* What follows them, with the lock held; the object can be freed by it */
void vh_request_sent(VhObject *object, int result);
void vh_request_read_done(VhObject *object, int count);

/* ---- async.c: non-blocking requests and epoll ---- */

/* Runs the request's send or read (request->async) on a worker thread, with the lock held; 0 or
 * an error */
int vh_async_start(VhObject *object);
/* Forgets the epoll in every object's settings, with the lock held */
void vh_epoll_forget(SceHttpEpollHandle epoll);
/* Frees every epoll, for sceHttpTerm, with the lock held */
void vh_epoll_clear(void);

/* ---- redirect.c: the host redirect list ---- */

/* The host to connect to instead of host (the list's), or host itself; with the lock held */
const char *vh_redirect_host(const char *host);
/* url with its host redirected, freshly allocated, or NULL when no rule applies; with the lock held */
char *vh_redirect_url(const char *url);
/* Forgets the list, for sceHttpTerm, with the lock held */
void vh_redirect_clear(void);
int vh_redirect_is_target(const char *host);
/* The least receive timeout for a redirected host: community servers can take longer to answer
 * than the official ones a game's timeouts were made for */
#define VH_REDIRECT_RECV_TIMEOUT_US 30000000u

/* ---- cookie.c ---- */

/* The Cookie header's value for a request to that server and path, freshly allocated; NULL when
 * no cookie matches */
char *vh_cookie_header(const char *host, const char *path, int https);
/* Stores the cookie of one Set-Cookie header's value */
void vh_cookie_store(const char *host, const char *path, const char *value, size_t length);
void vh_cookie_clear(void);

/* ---- inflate.c ---- */

VhInflater *vh_inflater_create(void);
/* Where vh_inflate gets the compressed bytes: their number, 0 at the body's end, or an error */
typedef int (*VhInflateSource)(void *context, unsigned char *data, size_t size);
/* Decompresses into out: the bytes written, 0 at the stream's end, or a libhttp error */
int vh_inflate(VhInflater *inflater, unsigned char *out, size_t out_size, VhInflateSource source,
               void *context);
void vh_inflater_destroy(VhInflater *inflater);

/* ---- message.c ---- */

/* Case-insensitive comparison of length bytes */
int vh_equal_nocase(const char *a, const char *b, size_t length);
/* Builds the request's status line and headers into a freshly allocated buffer */
int vh_build_request(const VhObject *request, const VhObject *connection, const VhObject *template_,
                     unsigned long long body_size, int has_body, const char *cookie, char **text,
                     size_t *size);
/* Reads a chunk-size line ("1a;ext\r\n") at the start of data; 1 with *size and *used when a
 * whole line is there, 0 when more is needed, negative when it is malformed */
int vh_parse_chunk_size(const unsigned char *data, size_t length, unsigned long long *size, size_t *used);
/* The value of a header in a header block, as sceHttpParseResponseHeader finds it */
int vh_find_header(const char *header, size_t length, const char *name, const char **value,
                   unsigned int *value_length);

/* ---- uri.c ---- */

/* The parts of an absolute http or https URL, pointing into url; 0 when it is one */
typedef struct VhUrl
{
    const char *scheme, *host, *path;
    size_t scheme_length, host_length, path_length;
    unsigned short port;
    int https;
} VhUrl;
int vh_parse_url(const char *url, VhUrl *parts);

/* ---- platform_*.c: what the engine runs on ---- */

typedef struct VhOpen
{
    const char *host;
    unsigned short port;
    int https;
    unsigned int resolve_timeout_us, connect_timeout_us, send_timeout_us, recv_timeout_us;
    int resolve_retry;
    unsigned int https_options;
    SceHttpsCallback ssl_callback;
    void *ssl_argument;
} VhOpen;

/* Memory for the pool sceHttpInit asks for; the core keeps the accounting */
void *vh_platform_alloc(size_t size);
void vh_platform_free(void *pointer);
int vh_platform_init(unsigned int pool_size);
void vh_platform_term(void);
void vh_platform_lock(void);
void vh_platform_unlock(void);

/* A transport not yet connected, so it can be aborted while it resolves and connects; NULL when
 * memory runs out */
VhTransport *vh_transport_create(void);
/* Connects to the server, with TLS for https; 0 or a libhttp error */
int vh_transport_connect(VhTransport *transport, const VhOpen *open, int *ssl_error, unsigned int *ssl_detail);
/* Sends all of data; 0 or a libhttp error */
int vh_transport_send(VhTransport *transport, const void *data, size_t size);
/* Receives up to size bytes: their number, 0 when the server closed, or a libhttp error */
int vh_transport_recv(VhTransport *transport, void *data, size_t size);
/* Makes blocking sends and receives on the transport return SCE_HTTP_ERROR_ABORTED; any thread */
void vh_transport_abort(VhTransport *transport);
void vh_transport_close(VhTransport *transport);
/* The last network error number the transport saw, 0 when none */
int vh_transport_errno(VhTransport *transport);

/* The current time, in seconds since 1970 (UTC) */
long long vh_platform_time(void);
/* A clock in microseconds, for timeouts */
unsigned long long vh_platform_clock_us(void);
/* Runs function(argument) on a new thread; 0 or an error */
int vh_platform_thread(void (*function)(void *), void *argument);
/* A counter vh_platform_notify changes; vh_platform_wait waits, up to timeout_us (negative: no
 * limit), for it to differ from generation: 0, or SCE_HTTP_ERROR_TIMEOUT. Take the generation
 * before checking what is waited for, so a notify in between isn't missed */
unsigned int vh_platform_generation(void);
void vh_platform_notify(void);
int vh_platform_wait(unsigned int generation, long long timeout_us);
/* Up to size bytes of the host redirect list from offset: their number, 0 past the end, or an error */
int vh_platform_redirects_read(unsigned int offset, void *buffer, unsigned int size);
/* Sets up TLS's heap, on first use; 0 or negative */
int vh_platform_tls_init(void);
/* tls_platform.c: Mbed TLS's mutexes, entropy and time, before its first use; 0 or negative */
int vh_tls_platform_init(void);
/* Where the trusted CA bundle (PEM) is read from, as this process opens it: 0, or negative when
 * there is none */
int vh_platform_ca_path(char *path, size_t capacity);
/* The socket under the transport, for TLS: the bytes moved, or a libhttp error */
int vh_transport_raw_send(VhTransport *transport, const void *data, size_t size);
int vh_transport_raw_recv(VhTransport *transport, void *data, size_t size);
int vh_transport_aborted(VhTransport *transport);

/* ---- tls.c: TLS over a transport, with tls13-vita's Mbed TLS ---- */

typedef struct VhTls VhTls;
/* Handshakes with the server and checks its certificate as open asks; 0 or a libhttp error, with
 * *ssl_error and *ssl_detail saying what failed */
int vh_tls_start(VhTls **tls, VhTransport *transport, const VhOpen *open, int *ssl_error, unsigned int *ssl_detail);
int vh_tls_send(VhTls *tls, const void *data, size_t size);
/* What a server's TLS 1.2 handshake shows before it turns encrypted, read off the records as they
 * arrive: whether it asked for a client certificate. Data is fed in as received, in any pieces */
typedef struct VhRecordScan
{
    unsigned char header[5];
    unsigned int header_have, record_left;
    int record_type;
    unsigned char message[4];
    unsigned int message_have, message_left;
    /* A ChangeCipherSpec came: what follows is encrypted */
    int done;
    int certificate_request;
} VhRecordScan;
void vh_record_scan(VhRecordScan *scan, const unsigned char *data, size_t size);
int vh_tls_recv(VhTls *tls, void *data, size_t size);
void vh_tls_close(VhTls *tls);
/* sceHttpsLoadCert's certificates: CAs trusted besides the bundle, and the client's own; with
 * the lock held */
int vh_tls_load_certs(int count, const SceHttpsData **list, const SceHttpsData *cert, const SceHttpsData *key);
void vh_tls_unload_certs(void);

#endif
