#include "vh.h"

#include "diagnostics.h"
#include "md5.h"

#include <stdio.h>
#include <string.h>

#define VH_RECV_BLOCK SCE_HTTP_DEFAULT_RECV_BLOCK_SIZE
/* The longest chunk-size line or trailer line accepted */
#define VH_CHUNK_LINE_MAX 1024u
/* The longest URL a request can have: scheme, host, port and path */
#define VH_URL_MAX (VH_HOST_MAX + VH_PATH_MAX + 16u)
/* How much of a body is read and dropped after a gzip stream's end, so the socket can be reused */
#define VH_DRAIN_MAX 65536u
/* The most a non-blocking read receives at once */
#define VH_ASYNC_READ_MAX 16384u

static const char *const g_methods[] = {
    [SCE_HTTP_METHOD_GET] = "GET",         [SCE_HTTP_METHOD_POST] = "POST",
    [SCE_HTTP_METHOD_HEAD] = "HEAD",       [SCE_HTTP_METHOD_OPTIONS] = "OPTIONS",
    [SCE_HTTP_METHOD_PUT] = "PUT",         [SCE_HTTP_METHOD_DELETE] = "DELETE",
    [SCE_HTTP_METHOD_TRACE] = "TRACE",     [SCE_HTTP_METHOD_CONNECT] = "CONNECT",
};
#define VH_METHOD_COUNT (int)(sizeof(g_methods) / sizeof(g_methods[0]))

static int copy_text(char *destination, size_t capacity, const char *source, size_t length)
{
    if (length >= capacity)
        return 0;
    memcpy(destination, source, length);
    destination[length] = '\0';
    return 1;
}

/* ---- templates, connections and requests ---- */

int sceHttpCreateTemplate(const char *userAgent, int httpVer, int autoProxyConf)
{
    VH_TRACE();
    if (httpVer != SCE_HTTP_VERSION_1_0 && httpVer != SCE_HTTP_VERSION_1_1)
        return (int)SCE_HTTP_ERROR_INVALID_VERSION;
    if (userAgent != NULL && strlen(userAgent) >= VH_USER_AGENT_MAX)
        return (int)SCE_HTTP_ERROR_OUT_OF_SIZE;
    vh_lock();
    int result = vh_initialized();
    if (result == 0) {
        VhObject *object = vh_create(VH_TEMPLATE, NULL);
        if (object == NULL)
            result = (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
        else {
            /* As Sony's: the app's agent, then this library's and the console's, as a request
             * header of the template that the app can replace or remove. Sony's puts the
             * firmware's version in it; this one always gives the latest firmware's, unless
             * useragent.txt gives another */
            char agent[VH_USER_AGENT_MAX + VH_SUFFIX_MAX];
            object->as.template_.http_version = httpVer;
            object->as.template_.auto_proxy = autoProxyConf;
            snprintf(agent, sizeof(agent), "%s%s%s", userAgent != NULL ? userAgent : "",
                     userAgent != NULL && userAgent[0] != '\0' ? " " : "", vh_user_agent_suffix());
            result = sceHttpAddRequestHeader(object->id, "User-Agent", agent, SCE_HTTP_HEADER_OVERWRITE);
            if (result < 0)
                vh_destroy(object);
            else
                result = object->id;
        }
    }
    vh_unlock();
    return result;
}

/* Whether a request of the object, or the object itself, is in a blocking call */
static int tree_busy(VhObject *object)
{
    if (object->kind == VH_REQUEST)
        return object->as.request.busy;
    VhObject *children[VH_OBJECT_MAX];
    unsigned int count = vh_children(object->id, children, VH_OBJECT_MAX);
    for (unsigned int i = 0; i < count; ++i)
        if (tree_busy(children[i]))
            return 1;
    return 0;
}

/* Deletes an object and, first, everything created from it */
static void destroy_tree(VhObject *object)
{
    if (object->kind != VH_REQUEST) {
        VhObject *children[VH_OBJECT_MAX];
        unsigned int count = vh_children(object->id, children, VH_OBJECT_MAX);
        for (unsigned int i = 0; i < count; ++i)
            destroy_tree(children[i]);
    }
    vh_destroy(object);
}

/* Marks an object and what was created from it deleted, aborting the busy requests among them */
static void doom_tree(VhObject *object)
{
    object->doomed = 1;
    if (object->kind == VH_REQUEST) {
        if (object->as.request.busy) {
            object->as.request.aborted = 1;
            if (object->as.request.transport != NULL)
                vh_transport_abort(object->as.request.transport);
        }
        return;
    }
    VhObject *children[VH_OBJECT_MAX];
    unsigned int count = vh_children(object->id, children, VH_OBJECT_MAX);
    for (unsigned int i = 0; i < count; ++i)
        doom_tree(children[i]);
}

void vh_reap(void)
{
    for (unsigned int slot = 0; slot < VH_OBJECT_MAX; ++slot) {
        VhObject *object = vh_object_at(slot);
        VhObject *parent = object != NULL && object->doomed ? vh_parent(object) : NULL;
        /* From the topmost deleted object down, once nothing in it is busy */
        if (object != NULL && object->doomed && (parent == NULL || !parent->doomed) && !tree_busy(object))
            destroy_tree(object);
    }
}

/* An object in use, or with a request in use, is gone for the API at once and freed when its
 * requests are done, which are aborted */
static int delete_object(int id, VhKind kind)
{
    vh_lock();
    int result = vh_initialized();
    if (result == 0) {
        VhObject *object = vh_find(id, kind);
        if (object == NULL)
            result = (int)SCE_HTTP_ERROR_INVALID_ID;
        else if (tree_busy(object))
            doom_tree(object);
        else
            destroy_tree(object);
    }
    vh_unlock();
    return result;
}

int sceHttpDeleteTemplate(int tmplId)
{
    VH_TRACE();
    return delete_object(tmplId, VH_TEMPLATE);
}

static int create_connection(int tmplId, const char *host, size_t host_length, int https, unsigned short port,
                             int keep_alive)
{
    if (host_length == 0)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    if (host_length >= VH_HOST_MAX)
        return (int)SCE_HTTP_ERROR_OUT_OF_SIZE;
    vh_lock();
    int result = vh_initialized();
    if (result == 0) {
        VhObject *template_ = vh_find(tmplId, VH_TEMPLATE);
        VhObject *object = template_ != NULL ? vh_create(VH_CONNECTION, template_) : NULL;
        if (template_ == NULL)
            result = (int)SCE_HTTP_ERROR_INVALID_ID;
        else if (object == NULL)
            result = (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
        else {
            VhConnection *connection = &object->as.connection;
            connection->https = https;
            copy_text(connection->host, sizeof(connection->host), host, host_length);
            connection->port = port;
            connection->keep_alive = keep_alive != 0;
            result = object->id;
        }
    }
    vh_unlock();
    if (result < 0)
        VITALS_LOG("create connection on %d to %.*s:%u failed rc=%08X", tmplId, (int)host_length, host,
                   (unsigned int)port, (unsigned int)result);
    return result;
}

int sceHttpCreateConnection(int tmplId, const char *serverName, const char *scheme, unsigned short port,
                         int enableKeepalive)
{
    VH_TRACE();
    int https;
    if (serverName == NULL || scheme == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    if (strlen(scheme) == 4 && vh_equal_nocase(scheme, "http", 4))
        https = 0;
    else if (strlen(scheme) == 5 && vh_equal_nocase(scheme, "https", 5))
        https = 1;
    else
        return (int)SCE_HTTP_ERROR_UNKNOWN_SCHEME;
    if (port == 0)
        port = https ? 443 : 80;
    /* The host redirect list's host, when it has one for this one */
    char host[VH_HOST_MAX];
    vh_lock();
    const char *target = vh_redirect_host(serverName);
    int fits = copy_text(host, sizeof(host), target, strlen(target));
    vh_unlock();
    if (!fits)
        return (int)SCE_HTTP_ERROR_OUT_OF_SIZE;
    return create_connection(tmplId, host, strlen(host), https, port, enableKeepalive);
}

int sceHttpCreateConnectionWithURL(int tmplId, const char *url, int enableKeepalive)
{
    VH_TRACE();
    VhUrl parts;
    if (url == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    vh_lock();
    char *redirected = vh_redirect_url(url);
    vh_unlock();
    int result = vh_parse_url(redirected != NULL ? redirected : url, &parts);
    if (result < 0)
        VITALS_LOG("create connection with url failed rc=%08X length=%u start=%.8s", (unsigned int)result,
                   (unsigned int)strlen(url), url);
    if (result >= 0)
        result = create_connection(tmplId, parts.host, parts.host_length, parts.https, parts.port, enableKeepalive);
    vh_free(redirected);
    return result;
}

int sceHttpDeleteConnection(int connId)
{
    VH_TRACE();
    return delete_object(connId, VH_CONNECTION);
}

/* The methods whose requests have no body unless the app gives a length */
static int body_less(const char *method)
{
    static const char *const methods[] = {"GET", "HEAD", "OPTIONS", "DELETE", "TRACE", "CONNECT"};
    for (size_t i = 0; i < sizeof(methods) / sizeof(methods[0]); ++i)
        if (strcmp(method, methods[i]) == 0)
            return 1;
    return 0;
}

/* A method is a token (RFC 9110, 5.6.2) */
static int valid_method(const char *method)
{
    size_t length = strlen(method);
    if (length == 0 || length >= VH_METHOD_MAX)
        return 0;
    for (size_t i = 0; i < length; ++i) {
        char c = method[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              strchr("!#$%&'*+-.^_`|~", c) != NULL))
            return 0;
    }
    return 1;
}

/* The request target goes on the request line as it is: no spaces or control characters */
static int valid_target(const char *path, size_t length)
{
    for (size_t i = 0; i < length; ++i)
        if ((unsigned char)path[i] <= ' ' || path[i] == 0x7f)
            return 0;
    return 1;
}

static int is_url(const char *text)
{
    return (strlen(text) > 7 && vh_equal_nocase(text, "http://", 7)) ||
           (strlen(text) > 8 && vh_equal_nocase(text, "https://", 8));
}

/* As Sony's: a request gets its Host as a header of its own when it is made, in front of what it
 * inherited, and a new one when it is redirected; with the lock held */
static int set_host(VhObject *object)
{
    const VhRequest *request = &object->as.request;
    char host[VH_HOST_MAX + 8];
    if (request->port != (request->https ? 443 : 80))
        snprintf(host, sizeof(host), "%s:%u", request->host, (unsigned int)request->port);
    else
        snprintf(host, sizeof(host), "%s", request->host);
    return vh_add_header(&object->settings, "Host", host, SCE_HTTP_HEADER_OVERWRITE);
}

/* target is a path, or an absolute URL, which can name another server than the connection's */
static int create_request_at(int connId, const char *method, const char *target, int with_url,
                             unsigned long long content_length);

static int create_request(int connId, const char *method, const char *target, int with_url,
                          unsigned long long content_length)
{
    if (method == NULL || target == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    if (!valid_method(method))
        return (int)SCE_HTTP_ERROR_UNKNOWN_METHOD;
    if (content_length > 0x7fffffffffffffffull)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    /* As Sony's, a "URL" that is a path names the connection's server: the PS Store asks for
     * /nsx/sec/... that way, LiveArea and the update check too */
    with_url = (with_url && target[0] != '/') || is_url(target);
    /* A URL's host goes through the host redirect list */
    char *redirected = NULL;
    if (with_url) {
        vh_lock();
        redirected = vh_redirect_url(target);
        vh_unlock();
        if (redirected != NULL)
            target = redirected;
    }
    int result = create_request_at(connId, method, target, with_url, content_length);
#if VITALS_DEBUG >= 1
    /* Why one was refused: the server and the target's length, never the path, which can carry a
     * session or a token */
    if (result < 0) {
        VhUrl url;
        int parsed = with_url && vh_parse_url(target, &url) == 0;
        VITALS_LOG("create request %s on %d failed rc=%08X url=%d host=%.*s target length=%u start=%.8s", method,
                   connId, (unsigned int)result, with_url, parsed ? (int)url.host_length : 0, parsed ? url.host : "",
                   (unsigned int)strlen(target), target);
    }
#endif
    vh_free(redirected);
    return result;
}

static int create_request_at(int connId, const char *method, const char *target, int with_url,
                             unsigned long long content_length)
{
    VhUrl url;
    const char *path = target;
    size_t path_length = strlen(target);
    if (with_url) {
        int result = vh_parse_url(target, &url);
        if (result < 0)
            return result;
        path = url.path;
        path_length = url.path_length;
    }
    if (path_length >= VH_PATH_MAX)
        return (int)SCE_HTTP_ERROR_OUT_OF_SIZE;
    if (!valid_target(path, path_length))
        return (int)SCE_HTTP_ERROR_INVALID_URL;

    vh_lock();
    int result = vh_initialized();
    if (result == 0) {
        VhObject *connection = vh_find(connId, VH_CONNECTION);
        VhObject *object = connection != NULL ? vh_create(VH_REQUEST, connection) : NULL;
        if (connection == NULL)
            result = (int)SCE_HTTP_ERROR_INVALID_ID;
        else if (object == NULL)
            result = (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
        else {
            VhRequest *request = &object->as.request;
            const VhConnection *c = &connection->as.connection;
            copy_text(request->method, sizeof(request->method), method, strlen(method));
            copy_text(request->path, sizeof(request->path), path, path_length);
            if (with_url) {
                copy_text(request->host, sizeof(request->host), url.host, url.host_length);
                request->port = url.port;
                request->https = url.https;
            } else {
                copy_text(request->host, sizeof(request->host), c->host, strlen(c->host));
                request->port = c->port;
                request->https = c->https;
            }
            request->content_length =
                content_length == 0 && body_less(method) ? -1 : (long long)content_length;
            request->response_content_length = -1;
            ++connection->as.connection.requests;
            result = set_host(object);
            if (result < 0)
                vh_destroy(object);
            else
                result = object->id;
        }
    }
    vh_unlock();
    return result;
}

int sceHttpCreateRequest(int connId, int method, const char *path, unsigned long long int contentLength)
{
    VH_TRACE();
    if (method < 0 || method >= VH_METHOD_COUNT)
        return (int)SCE_HTTP_ERROR_UNKNOWN_METHOD;
    return create_request(connId, g_methods[method], path, 0, contentLength);
}

int sceHttpCreateRequestWithURL(int connId, int method, const char *url, unsigned long long int contentLength)
{
    VH_TRACE();
    if (method < 0 || method >= VH_METHOD_COUNT)
        return (int)SCE_HTTP_ERROR_UNKNOWN_METHOD;
    return create_request(connId, g_methods[method], url, 1, contentLength);
}

int sceHttpCreateRequest2(int connId, const char *method, const char *path, unsigned long long int contentLength)
{
    VH_TRACE();
    return create_request(connId, method, path, 0, contentLength);
}

int sceHttpCreateRequestWithURL2(int connId, const char *method, const char *url, unsigned long long int contentLength)
{
    VH_TRACE();
    return create_request(connId, method, url, 1, contentLength);
}

int sceHttpDeleteRequest(int reqId)
{
    VH_TRACE();
    int result = delete_object(reqId, VH_REQUEST);
    VITALS_VERBOSE("delete request %d rc=%08X", reqId, (unsigned int)result);
    return result;
}

int sceHttpSetRequestContentLength(int id, unsigned long long int contentLength)
{
    VH_TRACE();
    if (contentLength > 0x7fffffffffffffffull)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    vh_lock();
    int result = vh_initialized();
    if (result == 0) {
        VhObject *object = vh_find(id, VH_REQUEST);
        if (object == NULL)
            result = (int)SCE_HTTP_ERROR_INVALID_ID;
        else if (object->as.request.busy)
            result = (int)SCE_HTTP_ERROR_BUSY;
        else
            object->as.request.content_length = (long long)contentLength;
    }
    vh_unlock();
    return result;
}

/* ---- the request's socket and response ---- */

/* The request goes to the connection's server, so the connection may keep its socket */
static int same_server_kept(const VhConnection *connection, const VhRequest *request)
{
    size_t length = strlen(connection->host);
    return connection->https == request->https && connection->port == request->port &&
           strlen(request->host) == length && vh_equal_nocase(connection->host, request->host, length);
}

/* The connection's kept socket goes where the request goes: the same server, the same way */
static int same_server(const VhConnection *connection, const VhRequest *request)
{
    return same_server_kept(connection, request) && connection->transport_proxied == request->proxied;
}

/* Whether the whole body came off the socket, so the next response is what follows */
static int body_finished(const VhRequest *request)
{
    return request->body_mode == VH_BODY_NONE || (request->body_mode == VH_BODY_LENGTH && request->body_left == 0);
}

/* Takes the socket off the request: kept on the connection for its next request when keep is set
 * and the response allows it, closed otherwise; with the lock held */
static void release_transport(VhObject *connection, VhRequest *request, int keep)
{
    VhTransport *transport = request->transport;
    if (transport == NULL)
        return;
    request->transport = NULL;
    VhConnection *c = connection != NULL ? &connection->as.connection : NULL;
    if (keep && request->reusable && body_finished(request) && request->pending_offset == request->pending_size &&
        c != NULL && c->keep_alive && c->transport == NULL && same_server_kept(c, request)) {
        c->transport = transport;
        c->transport_proxied = request->proxied;
    }
    else
        vh_transport_close(transport);
}

/* Forgets the last response, with the lock held */
static void reset_response(VhObject *connection, VhRequest *request)
{
    release_transport(connection, request, 0);
    vh_free(request->response_header);
    request->response_header = NULL;
    request->response_header_size = 0;
    vh_free(request->pending);
    request->pending = NULL;
    request->pending_size = request->pending_offset = request->pending_capacity = 0;
    if (request->inflater != NULL) {
        vh_inflater_destroy(request->inflater);
        request->inflater = NULL;
    }
    request->state = VH_REQUEST_CREATED;
    request->status_code = 0;
    request->body_mode = VH_BODY_NONE;
    request->body_left = 0;
    request->response_content_length = -1;
    request->chunk_trailer_pending = request->chunk_crlf_pending = 0;
    request->reusable = 0;
    request->body_logged = 0;
}

void vh_request_free(VhRequest *request)
{
    if (request->transport != NULL)
        vh_transport_close(request->transport);
    request->transport = NULL;
    reset_response(NULL, request);
    vh_free(request->request_header);
    request->request_header = NULL;
    vh_free(request->sent_cookie);
    request->sent_cookie = NULL;
    vh_free(request->async_data);
    request->async_data = NULL;
    vh_free(request->upload);
    request->upload = NULL;
    request->upload_size = 0;
}

/* An error of the request's network calls, as the app sees it */
static int failed(VhRequest *request, int error)
{
    if (request->aborted)
        error = (int)SCE_HTTP_ERROR_ABORTED;
    if (request->transport != NULL && vh_transport_errno(request->transport) != 0)
        request->last_errno = vh_transport_errno(request->transport);
    return error;
}

static void current_url(const VhRequest *request, char *url, size_t capacity)
{
    char port[8] = "";
    if (request->port != (request->https ? 443 : 80))
        snprintf(port, sizeof(port), ":%u", (unsigned int)request->port);
    snprintf(url, capacity, "%s://%s%s%s", request->https ? "https" : "http", request->host, port,
             request->path[0] != '\0' ? request->path : "/");
}

/* Receives more of the response into the pending buffer, which has all been used: the bytes, 0
 * when the server closed, or an error */
static int refill(VhRequest *request)
{
    if (request->pending_capacity < VH_RECV_BLOCK) {
        unsigned char *buffer = vh_alloc(VH_RECV_BLOCK);
        if (buffer == NULL)
            return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
        vh_free(request->pending);
        request->pending = buffer;
        request->pending_capacity = VH_RECV_BLOCK;
    }
    request->pending_size = request->pending_offset = 0;
    int received = vh_transport_recv(request->transport, request->pending, request->pending_capacity);
    if (received > 0)
        request->pending_size = (unsigned int)received;
    return received;
}

/* Up to size bytes of the response: the pending ones first, then from the socket */
static int receive(VhRequest *request, unsigned char *data, size_t size)
{
    if (request->pending_offset == request->pending_size) {
        if (size >= VH_RECV_BLOCK)
            return vh_transport_recv(request->transport, data, size);
        int received = refill(request);
        if (received <= 0)
            return received;
    }
    size_t count = request->pending_size - request->pending_offset;
    if (count > size)
        count = size;
    memcpy(data, request->pending + request->pending_offset, count);
    request->pending_offset += (unsigned int)count;
    return (int)count;
}

/* A line ending in LF, without its CR LF, into line: its length, or an error */
static int receive_line(VhRequest *request, char *line, size_t capacity)
{
    size_t length = 0;
    for (;;) {
        if (request->pending_offset == request->pending_size) {
            int received = refill(request);
            if (received <= 0)
                return received == 0 ? (int)SCE_HTTP_ERROR_BAD_RESPONSE : received;
        }
        char c = (char)request->pending[request->pending_offset++];
        if (c == '\n') {
            if (length > 0 && line[length - 1] == '\r')
                --length;
            line[length] = '\0';
            return (int)length;
        }
        if (length + 2 >= capacity)
            return (int)SCE_HTTP_ERROR_CHUNK_ENC;
        line[length++] = c;
    }
}

/* The body as sent, without its chunked encoding: the bytes, 0 at its end, or an error */
static int read_raw(void *context, unsigned char *data, size_t size)
{
    VhRequest *request = context;
    char line[VH_CHUNK_LINE_MAX];
    int count;

    switch (request->body_mode) {
    case VH_BODY_NONE:
        return 0;
    case VH_BODY_UNTIL_CLOSE:
        return receive(request, data, size);
    case VH_BODY_LENGTH:
        if (request->body_left == 0)
            return 0;
        count = receive(request, data, size < request->body_left ? size : (size_t)request->body_left);
        if (count == 0)
            return (int)SCE_HTTP_ERROR_BAD_RESPONSE;
        if (count > 0)
            request->body_left -= (unsigned long long)count;
        return count;
    case VH_BODY_CHUNKED:
        for (;;) {
            if (request->chunk_crlf_pending) {
                count = receive_line(request, line, sizeof(line));
                if (count < 0)
                    return count;
                if (count != 0)
                    return (int)SCE_HTTP_ERROR_CHUNK_ENC;
                request->chunk_crlf_pending = 0;
            }
            if (request->chunk_trailer_pending) {
                /* Trailer fields, up to an empty line */
                do
                    count = receive_line(request, line, sizeof(line));
                while (count > 0);
                if (count < 0)
                    return count;
                request->chunk_trailer_pending = 0;
                request->body_mode = VH_BODY_NONE;
                return 0;
            }
            if (request->body_left == 0) {
                unsigned long long chunk;
                size_t used;
                count = receive_line(request, line, sizeof(line));
                if (count < 0)
                    return count;
                line[count] = '\n';
                if (vh_parse_chunk_size((const unsigned char *)line, (size_t)count + 1, &chunk, &used) != 1)
                    return (int)SCE_HTTP_ERROR_CHUNK_ENC;
                if (chunk == 0)
                    request->chunk_trailer_pending = 1;
                request->body_left = chunk;
                continue;
            }
            count = receive(request, data, size < request->body_left ? size : (size_t)request->body_left);
            if (count <= 0)
                return count == 0 ? (int)SCE_HTTP_ERROR_BAD_RESPONSE : count;
            request->body_left -= (unsigned long long)count;
            if (request->body_left == 0)
                request->chunk_crlf_pending = 1;
            return count;
        }
    }
    return (int)SCE_HTTP_ERROR_UNKNOWN;
}

/* The body as the app reads it, decompressed when it is gzip */
static int read_body(VhRequest *request, unsigned char *data, size_t size)
{
    if (request->inflater == NULL)
        return read_raw(request, data, size);
    int count = vh_inflate(request->inflater, data, size, read_raw, request);
    if (count == 0) {
        /* What follows the stream (a chunked body's end) is read, so the socket can be reused */
        unsigned char rest[256];
        size_t drained = 0;
        int got;
        while (drained < VH_DRAIN_MAX && (got = read_raw(request, rest, sizeof(rest))) > 0)
            drained += (size_t)got;
    }
    return count;
}

/* Reads the response's status line and headers, skipping 1xx responses; 0 or an error, with
 * *nothing left set when the server closed before sending a byte */
static int receive_header(VhRequest *request, unsigned int max, int *nothing)
{
    char *buffer = vh_alloc((size_t)max + 1);
    size_t filled = 0, scanned = 0;
    if (buffer == NULL)
        return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
    *nothing = 1;
    for (;;) {
        /* The headers end with an empty line */
        size_t end = 0;
        for (; scanned < filled && end == 0; ++scanned)
            if (buffer[scanned] == '\n' &&
                ((scanned >= 1 && buffer[scanned - 1] == '\n') ||
                 (scanned >= 2 && buffer[scanned - 1] == '\r' && buffer[scanned - 2] == '\n')))
                end = scanned + 1;
        if (end == 0) {
            int received = filled == max ? (int)SCE_HTTP_ERROR_TOO_LARGE_RESPONSE_HEADER
                                         : vh_transport_recv(request->transport, buffer + filled, max - filled);
            if (received <= 0) {
                vh_free(buffer);
                return received == 0 ? (int)SCE_HTTP_ERROR_BAD_RESPONSE : received;
            }
            *nothing = 0;
            filled += (size_t)received;
            continue;
        }
        int major, minor, code;
        const char *reason;
        unsigned int reason_length;
        if (sceHttpParseStatusLine(buffer, (unsigned int)end, &major, &minor, &code, &reason, &reason_length) < 0) {
            vh_free(buffer);
            return (int)SCE_HTTP_ERROR_BAD_RESPONSE;
        }
        if (code >= 100 && code < 200 && code != 101) {
            memmove(buffer, buffer + end, filled - end);
            filled -= end;
            scanned = 0;
            continue;
        }
        /* What came after the headers is the body's start */
        char *header = vh_strdup(buffer, end);
        if (header == NULL) {
            vh_free(buffer);
            return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
        }
        if (filled > end) {
            size_t rest = filled - end;
            size_t capacity = rest > VH_RECV_BLOCK ? rest : VH_RECV_BLOCK;
            request->pending = vh_alloc(capacity);
            if (request->pending == NULL) {
                vh_free(header);
                vh_free(buffer);
                return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
            }
            memcpy(request->pending, buffer + end, rest);
            request->pending_size = (unsigned int)rest;
            request->pending_offset = 0;
            request->pending_capacity = (unsigned int)capacity;
        }
        vh_free(buffer);
        vh_lock();
        request->response_header = header;
        request->response_header_size = (unsigned int)end;
        request->status_code = code;
        vh_unlock();
        return 0;
    }
}

static int header_value(const VhRequest *request, const char *name, const char **value, unsigned int *length)
{
    return vh_find_header(request->response_header, request->response_header_size, name, value, length);
}

/* Whether a comma-separated header value has the token, in any case */
static int has_token(const char *value, unsigned int length, const char *token)
{
    size_t token_length = strlen(token);
    unsigned int at = 0;
    while (at < length) {
        while (at < length && (value[at] == ' ' || value[at] == '\t' || value[at] == ','))
            ++at;
        unsigned int start = at;
        while (at < length && value[at] != ',' && value[at] != ';')
            ++at;
        unsigned int end = at;
        while (end > start && (value[end - 1] == ' ' || value[end - 1] == '\t'))
            --end;
        if (end - start == token_length && vh_equal_nocase(value + start, token, token_length))
            return 1;
        while (at < length && value[at] != ',')
            ++at;
    }
    return 0;
}

/* How the body comes, from the response's headers (RFC 9112, 6.3) */
static int prepare_body(VhObject *object)
{
    VhRequest *request = &object->as.request;
    const char *value;
    unsigned int length;
    int major, minor, code;
    const char *reason;
    unsigned int reason_length;

    sceHttpParseStatusLine(request->response_header, request->response_header_size, &major, &minor, &code, &reason,
                        &reason_length);
    int keep = major > 1 || (major == 1 && minor >= 1);
    if (header_value(request, "Connection", &value, &length) == 0) {
        if (has_token(value, length, "close"))
            keep = 0;
        else if (has_token(value, length, "keep-alive"))
            keep = 1;
    }
    if (header_value(request, "Content-Length", &value, &length) == 0) {
        unsigned long long number = 0;
        if (length == 0 || length > 18)
            return (int)SCE_HTTP_ERROR_BAD_RESPONSE;
        for (unsigned int i = 0; i < length; ++i) {
            if (value[i] < '0' || value[i] > '9')
                return (int)SCE_HTTP_ERROR_BAD_RESPONSE;
            number = number * 10u + (unsigned long long)(value[i] - '0');
        }
        request->response_content_length = (long long)number;
    }

    if (strcmp(request->method, "HEAD") == 0 || (code >= 100 && code < 200) || code == 204 || code == 304)
        request->body_mode = VH_BODY_NONE;
    else if (header_value(request, "Transfer-Encoding", &value, &length) == 0) {
        request->body_mode = has_token(value, length, "chunked") ? VH_BODY_CHUNKED : VH_BODY_UNTIL_CLOSE;
        request->response_content_length = -1;
    } else if (request->response_content_length >= 0) {
        request->body_mode = VH_BODY_LENGTH;
        request->body_left = (unsigned long long)request->response_content_length;
    } else
        request->body_mode = VH_BODY_UNTIL_CLOSE;
    if (request->body_mode == VH_BODY_UNTIL_CLOSE)
        keep = 0;
    request->reusable = keep;

    /* Decompressed only when this library asked for gzip; a body the app asked for stays as it came */
    if (request->body_mode != VH_BODY_NONE && object->settings.accept_gzip == SCE_HTTP_ENABLE &&
        object->settings.inflate_gzip == SCE_HTTP_ENABLE && header_value(request, "Content-Encoding", &value, &length) == 0 &&
        has_token(value, length, "gzip")) {
        request->inflater = vh_inflater_create();
        if (request->inflater == NULL)
            return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
    }
    return 0;
}

/* Keeps the response's cookies, each offered to the app's callback first */
static void store_cookies(VhObject *object)
{
    VhRequest *request = &object->as.request;
    const char *header = request->response_header;
    size_t length = request->response_header_size, at = 0;
    char url[VH_URL_MAX];

    if (object->settings.cookie_enabled != SCE_HTTP_ENABLE)
        return;
    current_url(request, url, sizeof(url));
    while (at < length) {
        size_t end = at;
        while (end < length && header[end] != '\n')
            ++end;
        size_t line_end = end > at && header[end - 1] == '\r' ? end - 1 : end;
        if (line_end - at > 11 && vh_equal_nocase(header + at, "Set-Cookie:", 11)) {
            size_t start = at + 11;
            while (start < line_end && (header[start] == ' ' || header[start] == '\t'))
                ++start;
            SceHttpCookieRecvCallback callback = object->settings.cookie_recv_callback;
            if (callback == NULL || callback(object->id, url, header + start, (unsigned int)(line_end - start),
                                             object->settings.cookie_recv_argument) >= 0) {
                vh_lock();
                vh_cookie_store(request->host, request->path, header + start, line_end - start);
                vh_unlock();
            }
        }
        at = end + 1;
    }
}

/* The proxy the request goes through: the system's (from the network settings) when its template
 * was made with autoProxyConf 1, as Sony's reads it again for every send; otherwise the one
 * sceHttpPrivateSetProxy gave the object, when it turned one on. 1 with its host and port, or 0 */
static int choose_proxy(VhObject *object, const VhObject *template_, char *host, size_t capacity, unsigned short *port)
{
    if (template_ != NULL && template_->as.template_.auto_proxy == 1)
        return vh_platform_system_proxy(host, capacity, port);
    int proxied = 0;
    vh_lock();
    const VhSettings *settings = &object->settings;
    if (settings->proxy_mode == 1 && settings->proxy_host != NULL && settings->proxy_host[0] != '\0' &&
        settings->proxy_port != 0 && strlen(settings->proxy_host) < capacity) {
        memcpy(host, settings->proxy_host, strlen(settings->proxy_host) + 1);
        *port = settings->proxy_port;
        proxied = 1;
    }
    vh_unlock();
    return proxied;
}

/* Sends the request and reads the response's headers, on the connection's open socket when it
 * has one for this server; 0 or an error */
static int exchange(VhObject *object, VhObject *connection, const VhObject *template_, const unsigned char *body,
                    size_t body_size, int has_body)
{
    VhRequest *request = &object->as.request;
    VhConnection *c = &connection->as.connection;
    char url[VH_URL_MAX];
    char *cookie = NULL;
    char *text;
    size_t text_size;

    current_url(request, url, sizeof(url));
    request->started_us = vh_platform_clock_us();
    VITALS_VERBOSE("exchange request %d %s %s body=%u", object->id, request->method, url, (unsigned int)body_size);
    vh_lock();
    if (object->settings.cookie_enabled == SCE_HTTP_ENABLE)
        cookie = vh_cookie_header(request->host, request->path, request->https);
    SceHttpCookieSendCallback cookie_callback = object->settings.cookie_send_callback;
    void *cookie_argument = object->settings.cookie_send_argument;
    vh_unlock();
    if (cookie != NULL && cookie_callback != NULL)
        VITALS_VERBOSE("cookie send callback request %d", object->id);
    if (cookie != NULL && cookie_callback != NULL && cookie_callback(object->id, url, cookie, cookie_argument) < 0) {
        vh_free(cookie);
        cookie = NULL;
    }

    /* Through a proxy, decided before the request text, which depends on it */
    char proxy_host[VH_HOST_MAX];
    unsigned short proxy_port = 0;
    int proxied = choose_proxy(object, template_, proxy_host, sizeof(proxy_host), &proxy_port);
    if (proxied)
        VITALS_LOG("request %d through proxy %s:%u", object->id, proxy_host, (unsigned int)proxy_port);

    vh_lock();
    request->proxied = proxied;
    int result = vh_build_request(object, connection, template_, body_size, has_body, cookie, &text, &text_size);
    if (result == 0) {
        vh_free(request->request_header);
        request->request_header = text;
        request->request_header_size = (unsigned int)text_size;
        vh_free(request->sent_cookie);
        request->sent_cookie = cookie;
        cookie = NULL;
    }
    const VhSettings *settings = &object->settings;
    VhOpen open = {
        .host = request->host,
        .port = request->port,
        .https = request->https,
        .resolve_timeout_us = settings->resolve_timeout_us,
        .connect_timeout_us = settings->connect_timeout_us,
        .send_timeout_us = settings->send_timeout_us,
        .recv_timeout_us = settings->recv_timeout_us,
        .resolve_retry = settings->resolve_retry,
        .https_options = vh_https_options_of(settings),
        .ssl_callback = settings->ssl_callback,
        .ssl_argument = settings->ssl_argument,
        .option14 = settings->option14,
        .option14_set = settings->option14_set,
        .proxy_host = proxied ? proxy_host : NULL,
        .proxy_port = proxy_port,
    };
    unsigned int header_max = settings->response_header_max;
    if (open.recv_timeout_us != 0 && open.recv_timeout_us < VH_REDIRECT_RECV_TIMEOUT_US &&
        vh_redirect_is_target(request->host)) {
        VITALS_VERBOSE("request %d recv timeout %u -> %u us (redirected host)", object->id, open.recv_timeout_us,
                       VH_REDIRECT_RECV_TIMEOUT_US);
        open.recv_timeout_us = VH_REDIRECT_RECV_TIMEOUT_US;
    }
    vh_unlock();
    vh_free(cookie);
    if (result < 0)
        return result;

    for (int attempt = 0;; ++attempt) {
        int reused = 0, nothing = 1;
        vh_lock();
        if (request->aborted) {
            vh_unlock();
            return (int)SCE_HTTP_ERROR_ABORTED;
        }
        if (attempt == 0 && c->transport != NULL && same_server(c, request)) {
            request->transport = c->transport;
            c->transport = NULL;
            reused = 1;
        } else
            request->transport = vh_transport_create();
        vh_unlock();
        if (request->transport == NULL)
            return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
        if (!reused) {
            int ssl_error = 0;
            unsigned int ssl_detail = 0;
            result = vh_transport_connect(request->transport, &open, &ssl_error, &ssl_detail);
            vh_lock();
            request->ssl_error = c->ssl_error = ssl_error;
            request->ssl_detail = c->ssl_detail = ssl_detail;
            vh_unlock();
            if (result < 0)
                return failed(request, result);
        }
        VITALS_VERBOSE("send request %d reused=%d header=%u", object->id, reused, request->request_header_size);
        result = vh_transport_send(request->transport, request->request_header, request->request_header_size);
        if (result == 0 && body_size != 0)
            result = vh_transport_send(request->transport, body, body_size);
        if (result == 0)
            result = receive_header(request, header_max, &nothing);
        VITALS_VERBOSE("response header request %d rc=%08X status=%d", object->id, (unsigned int)result,
                       request->status_code);
        if (result < 0 && reused && nothing && !request->aborted) {
            /* The server closed the idle socket meanwhile: once more, on a new one */
            vh_lock();
            release_transport(connection, request, 0);
            vh_unlock();
            continue;
        }
        return result < 0 ? failed(request, result) : 0;
    }
}

static int is_redirect(int code)
{
    return code == 301 || code == 302 || code == 303 || code == 307 || code == 308;
}

static int method_index(const char *method)
{
    for (int i = 0; i < VH_METHOD_COUNT; ++i)
        if (strcmp(method, g_methods[i]) == 0)
            return i;
    return -1;
}

/* Points the request at the response's Location: 1 when it did, 0 when the response stays the
 * request's, negative on an error; *drop_body when the next request has no body */
static int follow_redirect(VhObject *object, VhObject *connection, int *drop_body)
{
    VhRequest *request = &object->as.request;
    const char *location;
    unsigned int length, need = 0;
    char base[VH_URL_MAX];
    VhUrl url;
    int result = 0;

    *drop_body = 0;
    if (object->settings.auto_redirect != SCE_HTTP_ENABLE ||
        header_value(request, "Location", &location, &length) < 0 || length == 0)
        return 0;
    current_url(request, base, sizeof(base));
    char *target = vh_strdup(location, length);
    if (target == NULL)
        return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
    char *merged = NULL;
    if (sceHttpUriMerge(NULL, base, target, &need, 0, 0) == 0 && (merged = vh_alloc(need)) != NULL &&
        sceHttpUriMerge(merged, base, target, NULL, need, 0) == 0 && vh_parse_url(merged, &url) == 0 &&
        url.path_length < VH_PATH_MAX && valid_target(url.path, url.path_length)) {
        /* 303 turns the request into a GET, as 301 and 302 do a POST (RFC 9110, 15.4) */
        int method = method_index(request->method), next = method;
        int code = request->status_code;
        if ((code == 303 && method != SCE_HTTP_METHOD_HEAD) ||
            ((code == 301 || code == 302) && method == SCE_HTTP_METHOD_POST))
            next = SCE_HTTP_METHOD_GET;
        SceHttpRedirectCallback callback = object->settings.redirect_callback;
        int proceed = 1;
        if (callback != NULL) {
            int chosen = next;
            proceed = callback(object->id, code, &chosen, merged, object->settings.redirect_argument) >= 0;
            if (chosen >= 0 && chosen < VH_METHOD_COUNT)
                next = chosen;
        }
        if (proceed) {
            vh_lock();
            reset_response(connection, request);
            copy_text(request->host, sizeof(request->host), url.host, url.host_length);
            request->port = url.port;
            request->https = url.https;
            copy_text(request->path, sizeof(request->path), url.path, url.path_length);
            result = set_host(object);
            if (next != method && next >= 0) {
                copy_text(request->method, sizeof(request->method), g_methods[next], strlen(g_methods[next]));
                if (body_less(request->method)) {
                    request->content_length = -1;
                    *drop_body = 1;
                }
            }
            vh_unlock();
            result = result < 0 ? result : 1;
        }
    }
    vh_free(merged);
    vh_free(target);
    return result;
}

static size_t base64(const unsigned char *in, size_t length, char *out)
{
    static const char digits[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t at = 0;
    for (size_t i = 0; i < length; i += 3) {
        unsigned int group = (unsigned int)in[i] << 16;
        if (i + 1 < length)
            group |= (unsigned int)in[i + 1] << 8;
        if (i + 2 < length)
            group |= in[i + 2];
        out[at++] = digits[(group >> 18) & 63u];
        out[at++] = digits[(group >> 12) & 63u];
        out[at++] = i + 1 < length ? digits[(group >> 6) & 63u] : '=';
        out[at++] = i + 2 < length ? digits[group & 63u] : '=';
    }
    out[at] = '\0';
    return at;
}

/* A parameter of an auth challenge (name=value or name="value", comma-separated), into out */
static int challenge_parameter(const char *value, unsigned int length, const char *name, char *out, size_t capacity)
{
    size_t name_length = strlen(name);
    for (unsigned int at = 0; at < length;) {
        while (at < length && (value[at] == ' ' || value[at] == ',' || value[at] == '\t'))
            ++at;
        unsigned int key = at;
        while (at < length && value[at] != '=' && value[at] != ',' && value[at] != ' ')
            ++at;
        unsigned int key_end = at;
        while (at < length && value[at] == ' ')
            ++at;
        if (at >= length || value[at] != '=')
            continue;
        ++at;
        while (at < length && value[at] == ' ')
            ++at;
        unsigned int start = at, end;
        if (at < length && value[at] == '"') {
            start = ++at;
            while (at < length && value[at] != '"')
                at += value[at] == '\\' && at + 1 < length ? 2u : 1u;
            end = at < length ? at++ : at;
        } else {
            while (at < length && value[at] != ',')
                ++at;
            end = at;
            while (end > start && value[end - 1] == ' ')
                --end;
        }
        if (key_end - key == name_length && vh_equal_nocase(value + key, name, name_length)) {
            size_t size = end - start < capacity - 1 ? end - start : capacity - 1;
            memcpy(out, value + start, size);
            out[size] = '\0';
            return 1;
        }
    }
    out[0] = '\0';
    return 0;
}

/* MD5 of the parts, as lowercase hex */
static void md5_hex(const char *const parts[], size_t count, char out[33])
{
    unsigned char digest[16];
    VhMd5 context;
    vh_md5_init(&context);
    for (size_t i = 0; i < count; ++i)
        vh_md5_update(&context, parts[i], strlen(parts[i]));
    vh_md5_finish(&context, digest);
    vh_md5_hex(digest, out);
}

/* The Digest answer (RFC 2617): qop auth, or auth-int over the body, or none; MD5 or MD5-sess */
static int digest_header(VhObject *object, const char *challenge, unsigned int length, const char *username,
                         const char *password, const unsigned char *body, size_t body_size, char *out, size_t capacity)
{
    VhRequest *request = &object->as.request;
    char realm[256], nonce[256], opaque[256], algorithm[32], qops[64];
    char ha1[33], ha2[33], response[33], cnonce[33], body_hash[33] = "";
    static unsigned int counter;

    challenge_parameter(challenge, length, "realm", realm, sizeof(realm));
    if (!challenge_parameter(challenge, length, "nonce", nonce, sizeof(nonce)))
        return -1;
    int has_opaque = challenge_parameter(challenge, length, "opaque", opaque, sizeof(opaque));
    int has_algorithm = challenge_parameter(challenge, length, "algorithm", algorithm, sizeof(algorithm));
    if (has_algorithm && !vh_equal_nocase(algorithm, "MD5", 4) && !vh_equal_nocase(algorithm, "MD5-sess", 9))
        return -1;
    const char *qop = NULL;
    if (challenge_parameter(challenge, length, "qop", qops, sizeof(qops))) {
        if (has_token(qops, (unsigned int)strlen(qops), "auth"))
            qop = "auth";
        else if (has_token(qops, (unsigned int)strlen(qops), "auth-int"))
            qop = "auth-int";
        else
            return -1;
    }
    /* The client nonce: not a secret, only different each time */
    char seed[64];
    snprintf(seed, sizeof(seed), "%llu:%d:%u", vh_platform_clock_us(), object->id, ++counter);
    const char *seed_parts[] = {seed};
    md5_hex(seed_parts, 1, cnonce);
    cnonce[16] = '\0';

    const char *ha1_parts[] = {username, ":", realm, ":", password};
    md5_hex(ha1_parts, 5, ha1);
    if (has_algorithm && vh_equal_nocase(algorithm, "MD5-sess", 9)) {
        const char *session_parts[] = {ha1, ":", nonce, ":", cnonce};
        md5_hex(session_parts, 5, ha1);
    }
    const char *uri = request->path[0] != '\0' ? request->path : "/";
    if (qop != NULL && strcmp(qop, "auth-int") == 0) {
        unsigned char digest[16];
        VhMd5 context;
        vh_md5_init(&context);
        if (body != NULL)
            vh_md5_update(&context, body, body_size);
        vh_md5_finish(&context, digest);
        vh_md5_hex(digest, body_hash);
        const char *ha2_parts[] = {request->method, ":", uri, ":", body_hash};
        md5_hex(ha2_parts, 5, ha2);
    } else {
        const char *ha2_parts[] = {request->method, ":", uri};
        md5_hex(ha2_parts, 3, ha2);
    }
    if (qop != NULL) {
        const char *parts[] = {ha1, ":", nonce, ":", "00000001", ":", cnonce, ":", qop, ":", ha2};
        md5_hex(parts, 11, response);
    } else {
        const char *parts[] = {ha1, ":", nonce, ":", ha2};
        md5_hex(parts, 5, response);
    }
    int written = snprintf(out, capacity, "Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\"",
                           username, realm, nonce, uri, response);
    if (written > 0 && (size_t)written < capacity && has_algorithm)
        written += snprintf(out + written, capacity - (size_t)written, ", algorithm=%s", algorithm);
    if (written > 0 && (size_t)written < capacity && qop != NULL)
        written += snprintf(out + written, capacity - (size_t)written, ", qop=%s, nc=00000001, cnonce=\"%s\"", qop, cnonce);
    if (written > 0 && (size_t)written < capacity && has_opaque)
        written += snprintf(out + written, capacity - (size_t)written, ", opaque=\"%s\"", opaque);
    return written > 0 && (size_t)written < capacity ? 0 : -1;
}

/* Answers a 401 with credentials from the app's callback, Basic or Digest as the server asks: 1
 * when the request goes again */
static int try_auth(VhObject *object, VhObject *connection, const unsigned char *body, size_t body_size)
{
    VhRequest *request = &object->as.request;
    const char *value;
    unsigned int length;
    char realm[256] = "";

    SceHttpAuthInfoCallback callback = object->settings.auth_callback;
    if (request->status_code != 401 || object->settings.auth_enabled != SCE_HTTP_ENABLE ||
        header_value(request, "WWW-Authenticate", &value, &length) < 0)
        return 0;
    int digest = length >= 6 && vh_equal_nocase(value, "Digest", 6) && (length == 6 || value[6] == ' ');
    int basic = length >= 5 && vh_equal_nocase(value, "Basic", 5) && (length == 5 || value[5] == ' ');
    unsigned int skip = digest ? 6u : 5u;
    if (basic || digest)
        challenge_parameter(value + skip, length - skip, "realm", realm, sizeof(realm));
    VITALS_LOG("auth %s realm=%s callback=%d", digest ? "digest" : basic ? "basic" : "unknown", realm, callback != NULL);
    if (callback == NULL || (!basic && !digest))
        return 0;

    char username[SCE_HTTP_USERNAME_MAX_SIZE] = "", password[SCE_HTTP_PASSWORD_MAX_SIZE] = "";
    unsigned char *entity = NULL;
    unsigned int entity_size = 0;
    int save = 0;
    int answer = callback(object->id, digest ? SCE_HTTP_AUTH_DIGEST : SCE_HTTP_AUTH_BASIC, realm, username, password,
                          0, &entity, &entity_size, &save, object->settings.auth_argument);
    VITALS_LOG("auth callback rc=%08X", (unsigned int)answer);
    if (answer < 0)
        return 0;
    username[sizeof(username) - 1] = password[sizeof(password) - 1] = '\0';

    char header[VH_HEADER_VALUE_MAX + 1];
    if (digest) {
        if (digest_header(object, value + skip, length - skip, username, password, body, body_size, header,
                          sizeof(header)) < 0) {
            VITALS_LOG("auth digest challenge unsupported");
            return 0;
        }
    } else {
        unsigned char credentials[SCE_HTTP_USERNAME_MAX_SIZE + SCE_HTTP_PASSWORD_MAX_SIZE + 1];
        size_t user_length = strlen(username), password_length = strlen(password);
        memcpy(credentials, username, user_length);
        credentials[user_length] = ':';
        memcpy(credentials + user_length + 1, password, password_length);
        memcpy(header, "Basic ", 6);
        base64(credentials, user_length + 1 + password_length, header + 6);
    }
    vh_lock();
    int result = vh_add_header(&object->settings, "Authorization", header, SCE_HTTP_HEADER_OVERWRITE);
    if (result == 0)
        reset_response(connection, request);
    vh_unlock();
    return result == 0;
}

/* The request, its redirects and its retries with credentials, up to the final response's headers */
static int perform(VhObject *object, VhObject *connection, const VhObject *template_, const unsigned char *body,
                   size_t body_size)
{
    VhRequest *request = &object->as.request;
    int has_body = body != NULL;

    for (unsigned int redirects = 0, auths = 0;;) {
        int result = exchange(object, connection, template_, body, body_size, has_body);
        if (result < 0)
            return result;
        store_cookies(object);
        result = prepare_body(object);
        if (result < 0)
            return failed(request, result);
        vh_lock();
        request->state = VH_REQUEST_RESPONDED;
        if (request->body_mode == VH_BODY_NONE) {
            request->state = VH_REQUEST_DONE;
            release_transport(connection, request, 1);
        }
        vh_unlock();

        if (is_redirect(request->status_code) && redirects < SCE_HTTP_DEFAULT_REDIRECT_MAX) {
            int drop_body;
            result = follow_redirect(object, connection, &drop_body);
            if (result < 0)
                return result;
            if (result == 1) {
                ++redirects;
                if (drop_body) {
                    body = NULL;
                    body_size = 0;
                    has_body = 0;
                }
                continue;
            }
        }
        if (auths < SCE_HTTP_DEFAULT_TRY_AUTH_MAX && try_auth(object, connection, body, body_size)) {
            ++auths;
            continue;
        }
        return 0;
    }
}

int vh_request_perform(VhObject *object, const unsigned char *body, size_t body_size)
{
    VhObject *connection = vh_parent(object);
    return perform(object, connection, vh_parent(connection), body, body_size);
}

#if VITALS_DEBUG >= 1
/* Whether a header's name has "token" in it (X-NP-CONSOLE-TOKEN, X-NP-TITLE-TOKEN...) */
static int names_token(const char *name, size_t length)
{
    for (size_t i = 0; i + 5 <= length; ++i)
        if (vh_equal_nocase(name + i, "token", 5))
            return 1;
    return 0;
}

/* A header block, a line at a time; with redact, Cookie, Set-Cookie, Authorization and any
 * header named with "token" show only their size */
static void log_lines(const char *label, const char *text, size_t length, int redact)
{
    char line[224];
    for (size_t at = 0; at < length;) {
        size_t end = at;
        while (end < length && text[end] != '\n')
            ++end;
        size_t size = (end > at && text[end - 1] == '\r' ? end - 1 : end) - at;
        const char *colon = memchr(text + at, ':', size);
        int secret = redact && colon != NULL &&
                     (((size_t)(colon - (text + at)) == 6 && vh_equal_nocase(text + at, "Cookie", 6)) ||
                      ((size_t)(colon - (text + at)) == 10 && vh_equal_nocase(text + at, "Set-Cookie", 10)) ||
                      ((size_t)(colon - (text + at)) == 13 && vh_equal_nocase(text + at, "Authorization", 13)) ||
                      names_token(text + at, (size_t)(colon - (text + at))));
        if (secret)
            size = (size_t)(colon - (text + at)) + 1;
        if (size != 0) {
            size_t shown = size < sizeof(line) - 1 ? size : sizeof(line) - 1;
            memcpy(line, text + at, shown);
            line[shown] = '\0';
            if (secret)
                VITALS_LOG("%s %s (%u bytes)", label, line, (unsigned int)((end > at && text[end - 1] == '\r' ? end - 1 : end) - at - size));
            else
                VITALS_LOG("%s %s", label, line);
        }
        at = end + 1;
    }
}
#endif

void vh_request_sent(VhObject *object, int result)
{
    VhRequest *request = &object->as.request;
#if VITALS_DEBUG >= 1
    char url[VH_URL_MAX];
    current_url(request, url, sizeof(url));
    VITALS_LOG("request %d %s %s rc=%08X status=%d", object->id, request->method, url, (unsigned int)result,
               result == 0 ? request->status_code : 0);
    /* A failed one, with how long it took and the timeouts it had */
    if (result < 0)
        VITALS_LOG("  after %ums; timeouts resolve=%u connect=%u send=%u recv=%u us",
                   (unsigned int)((vh_platform_clock_us() - request->started_us) / 1000u),
                   object->settings.resolve_timeout_us, object->settings.connect_timeout_us,
                   object->settings.send_timeout_us, object->settings.recv_timeout_us);
    /* A refused or failed request, with what it sent and what came back; with DEBUG=2, every one */
    if (result < 0 || request->status_code >= 400 || VITALS_DEBUG >= 2) {
        if (request->request_header != NULL)
            log_lines("  sent", request->request_header, request->request_header_size, 1);
        if (request->response_header != NULL)
            log_lines("  got", request->response_header, request->response_header_size, 1);
    }
#endif
    request->busy = 0;
    if (result < 0) {
        request->state = VH_REQUEST_FAILED;
        release_transport(vh_parent(object), request, 0);
    }
    vh_reap();
}

int vh_request_read(VhRequest *request, unsigned char *data, size_t size)
{
    int count = read_body(request, data, size);
    /* A body of known length fills the buffer up to its end, as apps (Sound Shapes) read one
     * Content-Length in one call; one that streams (chunked, or until close) returns what came */
    while (count > 0 && (size_t)count < size && request->body_mode == VH_BODY_LENGTH && !request->aborted) {
        int more = read_body(request, data + count, size - (size_t)count);
        if (more < 0)
            return failed(request, more);
        if (more == 0)
            break;
        count += more;
    }
#if VITALS_DEBUG >= 1
    /* An error's body; with DEBUG=2, also a short one's bytes (a longer one may hold a token) */
    if (count > 0 && (request->status_code >= 400 || (VITALS_DEBUG >= 2 && count <= 32)) && !request->body_logged) {
        char text[161];
        size_t shown = (size_t)count < sizeof(text) - 1 ? (size_t)count : sizeof(text) - 1;
        for (size_t i = 0; i < shown; ++i)
            text[i] = data[i] >= 0x20 && data[i] < 0x7f ? (char)data[i] : '.';
        text[shown] = '\0';
        VITALS_LOG("  body %s", text);
#if VITALS_DEBUG >= 2
        /* A short body's bytes, as a binary one shows only dots */
        if (count <= 32) {
            char hex[65];
            for (int i = 0; i < count; ++i)
                snprintf(hex + 2 * i, 3, "%02X", data[i]);
            VITALS_VERBOSE("  body hex %s", hex);
        }
#endif
        request->body_logged = 1;
    }
#endif
    return count < 0 ? failed(request, count) : count;
}

void vh_request_read_done(VhObject *object, int count)
{
    VhRequest *request = &object->as.request;
    request->busy = 0;
    if (count < 0) {
        request->state = VH_REQUEST_FAILED;
        release_transport(vh_parent(object), request, 0);
    } else if (count == 0) {
        request->state = VH_REQUEST_DONE;
        release_transport(vh_parent(object), request, 1);
    }
    vh_reap();
}

/* Forgets a non-blocking call's result, with the lock held */
static void async_clear(VhRequest *request)
{
    vh_free(request->async_data);
    request->async_data = NULL;
    request->async_size = request->async_offset = 0;
    request->async = VH_ASYNC_NONE;
    request->async_done = request->async_reported = 0;
    request->async_result = 0;
}

/* A non-blocking send or read: started on a worker thread, with the lock held */
static int async_begin(VhObject *object, VhAsync kind, const void *data, size_t size)
{
    VhRequest *request = &object->as.request;
    request->async_data = size != 0 ? vh_alloc(size) : NULL;
    if (size != 0 && request->async_data == NULL)
        return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
    if (kind == VH_ASYNC_SEND && size != 0)
        memcpy(request->async_data, data, size);
    /* The body to send, or the room to read into */
    request->async_size = (unsigned int)size;
    request->async_offset = 0;
    request->async = kind;
    request->async_done = request->async_reported = 0;
    request->busy = 1;
    int result = vh_async_start(object);
    if (result < 0) {
        request->busy = 0;
        async_clear(request);
        return result;
    }
    return VH_ERROR_EAGAIN;
}

int sceHttpSendRequest(int reqId, const void *postData, unsigned int size)
{
    VH_TRACE();
    if (postData == NULL && size != 0)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    vh_lock();
    int result = vh_initialized();
    VhObject *object = result == 0 ? vh_find(reqId, VH_REQUEST) : NULL;
    VhRequest *request = object != NULL ? &object->as.request : NULL;
    if (result == 0 && object == NULL)
        result = (int)SCE_HTTP_ERROR_INVALID_ID;
    else if (request != NULL && request->async == VH_ASYNC_SEND) {
        /* Called again for a non-blocking send: its result once it is done */
        result = request->async_done ? request->async_result : VH_ERROR_EAGAIN;
        if (request->async_done)
            async_clear(request);
        vh_unlock();
        return result;
    } else if (request != NULL && request->busy)
        result = (int)SCE_HTTP_ERROR_BUSY;
    if (result < 0) {
        vh_unlock();
        return result;
    }
    /* A body of declared length can come in pieces, one call each (the shell's Commerce2 sends
     * crSess.action's like that): as Sony's, each piece but the last returns 0, and the last one
     * sends the request and gets the response */
    unsigned char *upload = NULL;
    if (request->content_length > 0 && (request->upload_size != 0 || (long long)size < request->content_length)) {
        unsigned long long total = (unsigned long long)request->upload_size + size;
        if (total > (unsigned long long)request->content_length) {
            vh_unlock();
            return (int)SCE_HTTP_ERROR_INVALID_VALUE;
        }
        if (request->upload == NULL) {
            request->upload = vh_alloc((size_t)request->content_length);
            if (request->upload == NULL) {
                vh_unlock();
                return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
            }
        }
        if (size != 0)
            memcpy(request->upload + request->upload_size, postData, size);
        request->upload_size = (unsigned int)total;
        VITALS_VERBOSE("send request %d piece size=%u body=%u of %u", reqId, size, request->upload_size,
                       (unsigned int)request->content_length);
        if (total < (unsigned long long)request->content_length) {
            vh_unlock();
            return 0;
        }
        upload = request->upload;
        request->upload = NULL;
        request->upload_size = 0;
        postData = upload;
        size = (unsigned int)total;
    }
    async_clear(request);
    reset_response(vh_parent(object), request);
    request->aborted = 0;
    request->last_errno = 0;
    if (object->settings.nonblock == SCE_HTTP_ENABLE) {
        result = async_begin(object, VH_ASYNC_SEND, postData, size);
        vh_free(upload);
        vh_unlock();
        return result;
    }
    request->busy = 1;
    vh_unlock();

    result = vh_request_perform(object, postData, size);

    vh_lock();
    vh_free(upload);
    vh_request_sent(object, result);
    vh_unlock();
    return result;
}

/* A non-blocking read's data, as much as fits, with the lock held */
static int async_deliver(VhRequest *request, unsigned char *data, size_t size)
{
    if (!request->async_done)
        return VH_ERROR_EAGAIN;
    int result = request->async_result;
    if (result > 0) {
        size_t left = request->async_size - request->async_offset;
        result = (int)(left < size ? left : size);
        memcpy(data, request->async_data + request->async_offset, (size_t)result);
        request->async_offset += (unsigned int)result;
        if (request->async_offset < request->async_size)
            return result;
    }
    async_clear(request);
    return result;
}

int sceHttpReadData(int reqId, void *data, unsigned int size)
{
    VH_TRACE();
    if (data == NULL && size != 0)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    if (size > 0x7fffffffu)
        size = 0x7fffffffu;
    vh_lock();
    int result = vh_initialized();
    VhObject *object = result == 0 ? vh_find(reqId, VH_REQUEST) : NULL;
    VhRequest *request = object != NULL ? &object->as.request : NULL;
    if (request != NULL && request->async == VH_ASYNC_READ && size != 0) {
        result = async_deliver(request, data, size);
        vh_unlock();
        return result;
    }
    /* A finished non-blocking send whose result the app didn't collect */
    if (request != NULL && request->async == VH_ASYNC_SEND && request->async_done)
        async_clear(request);
    if (result == 0 && object == NULL)
        result = (int)SCE_HTTP_ERROR_INVALID_ID;
    else if (request != NULL && request->busy)
        result = request->async != VH_ASYNC_NONE ? VH_ERROR_EAGAIN : (int)SCE_HTTP_ERROR_BUSY;
    else if (request != NULL && request->state == VH_REQUEST_CREATED)
        result = (int)SCE_HTTP_ERROR_BEFORE_SEND;
    else if (request != NULL && request->state == VH_REQUEST_FAILED)
        result = (int)SCE_HTTP_ERROR_NOT_IN_COM;
    else if (request != NULL && strcmp(request->method, "HEAD") == 0)
        result = (int)SCE_HTTP_ERROR_READ_BY_HEAD_METHOD;
    if (result < 0 || request->state == VH_REQUEST_DONE || size == 0) {
        vh_unlock();
        return result;
    }
    if (object->settings.nonblock == SCE_HTTP_ENABLE) {
        result = async_begin(object, VH_ASYNC_READ, NULL, size < VH_ASYNC_READ_MAX ? size : VH_ASYNC_READ_MAX);
        vh_unlock();
        return result;
    }
    request->busy = 1;
    vh_unlock();

    int count = vh_request_read(request, data, size);
    VITALS_VERBOSE("read request %d size=%u rc=%d", reqId, size, count);

    vh_lock();
    vh_request_read_done(object, count);
    vh_unlock();
    return count;
}

static int abort_request(int reqId)
{
    vh_lock();
    int result = vh_initialized();
    if (result == 0) {
        VhObject *object = vh_find(reqId, VH_REQUEST);
        if (object == NULL)
            result = (int)SCE_HTTP_ERROR_INVALID_ID;
        else {
            object->as.request.aborted = 1;
            if (object->as.request.transport != NULL)
                vh_transport_abort(object->as.request.transport);
        }
    }
    vh_unlock();
    return result;
}

int sceHttpAbortRequest(int reqId)
{
    VH_TRACE();
    int result = abort_request(reqId);
    VITALS_VERBOSE("abort request %d rc=%08X", reqId, (unsigned int)result);
    return result;
}

int sceHttpAbortRequestForce(int reqId)
{
    VH_TRACE();
    return abort_request(reqId);
}

/* ---- what the response said ---- */

/* The request, with the lock held, once its response's headers are in; NULL and *result set otherwise */
static VhRequest *responded(int reqId, int *result)
{
    *result = vh_initialized();
    if (*result != 0)
        return NULL;
    VhObject *object = vh_find(reqId, VH_REQUEST);
    if (object == NULL) {
        *result = (int)SCE_HTTP_ERROR_INVALID_ID;
        return NULL;
    }
    if (object->as.request.busy) {
        *result = (int)SCE_HTTP_ERROR_BUSY;
        return NULL;
    }
    if (object->as.request.response_header == NULL) {
        *result = (int)SCE_HTTP_ERROR_BEFORE_SEND;
        return NULL;
    }
    return &object->as.request;
}

int sceHttpGetStatusCode(int reqId, int *statusCode)
{
    VH_TRACE();
    int result;
    if (statusCode == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    vh_lock();
    VhRequest *request = responded(reqId, &result);
    if (request != NULL)
        *statusCode = request->status_code;
    vh_unlock();
    return result;
}

int sceHttpGetAllResponseHeaders(int reqId, char **header, unsigned int *headerSize)
{
    VH_TRACE();
    int result;
    if (header == NULL || headerSize == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    vh_lock();
    VhRequest *request = responded(reqId, &result);
    if (request != NULL) {
        /* As Sony's: the size counts the NUL that ends the text */
        *header = request->response_header;
        *headerSize = request->response_header_size + 1;
    }
    vh_unlock();
    return result;
}

int sceHttpGetResponseContentLength(int reqId, unsigned long long int *contentLength)
{
    VH_TRACE();
    int result;
    if (contentLength == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    vh_lock();
    VhRequest *request = responded(reqId, &result);
    if (request != NULL) {
        if (request->response_content_length < 0)
            result = (int)SCE_HTTP_ERROR_NO_CONTENT_LENGTH;
        else
            *contentLength = (unsigned long long)request->response_content_length;
    }
    vh_unlock();
    VITALS_VERBOSE("content length request %d rc=%08X", reqId, (unsigned int)result);
    return result;
}

/* As Sony's: the headers the request has now, sent or not; count is always set, pairs only when
 * given, so a first call with pairs NULL tells how many to make room for */
int sceHttpRequestGetAllHeaders(int reqId, SceHttpHeaderPair *pairs, unsigned int *count, char *lengthBuffer,
                                unsigned int *lengthBufferSize)
{
    VH_TRACE();
    vh_lock();
    int result = vh_initialized();
    /* Sony's refuses only both missing, then writes the count regardless */
    if (result == 0 && count == NULL)
        result = (int)SCE_HTTP_ERROR_INVALID_VALUE;
    if (result == 0) {
        VhObject *object = vh_find(reqId, VH_REQUEST);
        if (object == NULL)
            result = (int)SCE_HTTP_ERROR_INVALID_ID;
        else
            *count = vh_list_request_headers(object, vh_parent(object), pairs, lengthBuffer, lengthBufferSize);
    }
    vh_unlock();
    return result;
}

int sceHttpGetLastErrno(int reqId, int *errNum)
{
    VH_TRACE();
    if (errNum == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    vh_lock();
    int result = vh_initialized();
    if (result == 0) {
        VhObject *object = vh_find(reqId, VH_REQUEST);
        if (object == NULL)
            result = (int)SCE_HTTP_ERROR_INVALID_ID;
        else
            *errNum = object->as.request.last_errno;
    }
    vh_unlock();
    return result;
}

/* Of the last connect of a request, or of any of a connection's requests */
int sceHttpsGetSslError(int id, int *errNum, unsigned int *detail)
{
    VH_TRACE();
    if (errNum == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    vh_lock();
    int result = vh_initialized();
    if (result == 0) {
        VhObject *object = vh_find(id, VH_FREE);
        if (object == NULL || object->kind == VH_TEMPLATE)
            result = (int)SCE_HTTP_ERROR_INVALID_ID;
        else if (object->kind == VH_REQUEST) {
            *errNum = object->as.request.ssl_error;
            if (detail != NULL)
                *detail = object->as.request.ssl_detail;
        } else {
            *errNum = object->as.connection.ssl_error;
            if (detail != NULL)
                *detail = object->as.connection.ssl_detail;
        }
    }
    vh_unlock();
    return result;
}
