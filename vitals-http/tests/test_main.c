/* Host tests of the engine, through the exported API, against tests/server.py */
#include "http_extra.h"
#include "vh.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_failures, g_checks;
static int g_port;
static char g_base[64], g_secure_base[64];
static const char *g_cert_path;
static const char *g_client_cert_path, *g_client_key_path, *g_hello_path;
/* platform_posix.c's CA bundle and host redirect list */
extern const char *vh_test_ca_path, *vh_test_redirects_path, *vh_test_useragent_path;

#define CHECK(condition)                                                  \
    do                                                                    \
    {                                                                     \
        ++g_checks;                                                       \
        if (!(condition))                                                 \
        {                                                                 \
            ++g_failures;                                                 \
            printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        }                                                                 \
    } while (0)

#define CHECK_EQ(actual, expected)                                                           \
    do                                                                                       \
    {                                                                                        \
        int a_ = (int)(actual), e_ = (int)(expected);                                        \
        ++g_checks;                                                                          \
        if (a_ != e_)                                                                        \
        {                                                                                    \
            ++g_failures;                                                                    \
            printf("  FAIL %s:%d: %s == 0x%x, expected 0x%x\n", __FILE__, __LINE__, #actual, \
                   (unsigned int)a_, (unsigned int)e_);                                      \
        }                                                                                    \
    } while (0)

static char *url(const char *base, const char *path)
{
    static char buffers[4][256];
    static int next;
    char *buffer = buffers[next++ % 4];
    snprintf(buffer, 256, "%s%s", base, path);
    return buffer;
}

/* Reads the whole body in pieces of piece bytes: its length, or the error */
/* The status line and headers the request last sent, as they went out */
static int sent_header(int request, char **header, unsigned int *size)
{
    VhObject *object = vh_find(request, VH_REQUEST);
    if (object == NULL || object->as.request.request_header == NULL)
        return -1;
    *header = object->as.request.request_header;
    *size = object->as.request.request_header_size;
    return 0;
}

static int read_all(int request, char *out, int capacity, int piece)
{
    int total = 0;
    for (;;)
    {
        int room = capacity - total < piece ? capacity - total : piece;
        if (room <= 0)
            return total;
        int got = sceHttpReadData(request, out + total, (unsigned int)room);
        if (got < 0)
            return got;
        if (got == 0)
            return total;
        total += got;
    }
}

/* One request on a fresh request object of the connection: the body's length, or the error */
static int fetch(int connection, int method, const char *target, const char *body, int *status, char *out,
                 int capacity, int *request_out)
{
    int request = sceHttpCreateRequestWithURL(connection, method, target, body != NULL ? strlen(body) : 0);
    if (request < 0)
        return request;
    int result = sceHttpSendRequest(request, body, body != NULL ? (unsigned int)strlen(body) : 0);
    if (result == 0)
        result = sceHttpGetStatusCode(request, status);
    if (result == 0)
        result = read_all(request, out, capacity - 1, 1000);
    if (result >= 0)
        out[result] = '\0';
    if (request_out != NULL)
        *request_out = request;
    else
        sceHttpDeleteRequest(request);
    return result;
}

static void test_basic(int template_)
{
    char body[256];
    int status = 0, request;
    printf("basic GET, HEAD, 204, 100-continue\n");
    int connection = sceHttpCreateConnectionWithURL(template_, g_base, 1);
    CHECK(connection > 0);
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/hello"), NULL, &status, body, sizeof(body), &request), 11);
    CHECK_EQ(status, 200);
    CHECK(strcmp(body, "hello world") == 0);
    unsigned long long length = 0;
    CHECK_EQ(sceHttpGetResponseContentLength(request, &length), 0);
    CHECK_EQ(length, 11);
    /* As Sony's: the top digit of an ID is its kind */
    CHECK_EQ((unsigned int)template_ >> 28, 1u);
    CHECK_EQ((unsigned int)request >> 28, 3u);
    char *header;
    unsigned int header_size;
    CHECK_EQ(sceHttpGetAllResponseHeaders(request, &header, &header_size), 0);
    /* As Sony's: the status line first, and a size that counts the ending NUL */
    CHECK(strncmp(header, "HTTP/1.", 7) == 0 && header_size > 1 && header[header_size - 1] == '\0');
    CHECK(strlen(header) == header_size - 1);
    const char *value;
    unsigned int value_length;
    int end = sceHttpParseResponseHeader(header, header_size, "content-type", &value, &value_length);
    CHECK(value_length == 10 && memcmp(value, "text/plain", 10) == 0);
    /* As Sony's: the offset of the value's end */
    CHECK_EQ(end, value + value_length - header);
    CHECK_EQ(sent_header(request, &header, &header_size), 0);
    CHECK(strstr(header, "GET /hello HTTP/1.1\r\n") == header);
    CHECK(strstr(header, "User-Agent: vh-test libhttp/3.74 (PS Vita)\r\n") != NULL);
    CHECK(strstr(header, "Content-Length") == NULL);
    /* Read again after the end */
    CHECK_EQ(sceHttpReadData(request, body, sizeof(body)), 0);
    sceHttpDeleteRequest(request);

    request = sceHttpCreateRequestWithURL(connection, SCE_HTTP_METHOD_HEAD, url(g_base, "/hello"), 0);
    CHECK_EQ(sceHttpSendRequest(request, NULL, 0), 0);
    CHECK_EQ(sceHttpGetResponseContentLength(request, &length), 0);
    CHECK_EQ(length, 11);
    CHECK_EQ(sceHttpReadData(request, body, sizeof(body)), SCE_HTTP_ERROR_READ_BY_HEAD_METHOD);
    sceHttpDeleteRequest(request);

    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/nocontent"), NULL, &status, body, sizeof(body), NULL), 0);
    CHECK_EQ(status, 204);
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/continue"), NULL, &status, body, sizeof(body), NULL), 14);
    CHECK(strcmp(body, "after continue") == 0);
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/missing"), NULL, &status, body, sizeof(body), NULL), 9);
    CHECK_EQ(status, 404);
    /* A refused request with secrets: the debug log shows only their size */
    request = sceHttpCreateRequestWithURL(connection, SCE_HTTP_METHOD_GET, url(g_base, "/missing"), 0);
    sceHttpAddRequestHeader(request, "Cookie", "secret=hunter2", SCE_HTTP_HEADER_OVERWRITE);
    sceHttpAddRequestHeader(request, "Authorization", "Bearer hunter2", SCE_HTTP_HEADER_OVERWRITE);
    CHECK_EQ(sceHttpSendRequest(request, NULL, 0), 0);
    sceHttpDeleteRequest(request);
    sceHttpDeleteConnection(connection);
}

static void test_keep_alive(int template_)
{
    char first[32], second[32], third[32], body[64];
    int status;
    printf("keep-alive\n");
    int connection = sceHttpCreateConnectionWithURL(template_, g_base, 1);
    CHECK(fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/conn"), NULL, &status, first, sizeof(first), NULL) > 0);
    CHECK(fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/conn"), NULL, &status, second, sizeof(second), NULL) > 0);
    CHECK(strcmp(first, second) == 0);
    /* A chunked gzip body read to its end leaves the socket usable */
    int request = sceHttpCreateRequestWithURL(connection, SCE_HTTP_METHOD_GET, url(g_base, "/gzip-chunked"), 0);
    sceHttpSetAcceptEncodingGZIPEnabled(request, SCE_HTTP_ENABLE);
    CHECK_EQ(sceHttpSendRequest(request, NULL, 0), 0);
    char *big = malloc(100000);
    CHECK_EQ(read_all(request, big, 100000, 4096), 7 * 3000);
    free(big);
    sceHttpDeleteRequest(request);
    CHECK(fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/conn"), NULL, &status, third, sizeof(third), NULL) > 0);
    CHECK(strcmp(first, third) == 0);
    /* Connection: close isn't reused, and the next request still works */
    CHECK(fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/close"), NULL, &status, body, sizeof(body), NULL) > 0);
    CHECK(fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/conn"), NULL, &status, third, sizeof(third), NULL) > 0);
    CHECK(strcmp(first, third) != 0);
    sceHttpDeleteConnection(connection);

    connection = sceHttpCreateConnectionWithURL(template_, g_base, 0);
    fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/conn"), NULL, &status, first, sizeof(first), NULL);
    fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/conn"), NULL, &status, second, sizeof(second), NULL);
    CHECK(strcmp(first, second) != 0);
    sceHttpDeleteConnection(connection);
}

static void test_bodies(int template_)
{
    static char body[2 * 1024 * 1024];
    int status;
    printf("chunked, gzip, until-close, large\n");
    int connection = sceHttpCreateConnectionWithURL(template_, g_base, 1);
    int length = fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/chunked"), NULL, &status, body, sizeof(body), NULL);
    CHECK_EQ(length, 6 + 7 + 5000 + 4);
    CHECK(memcmp(body, "first second xxx", 16) == 0 && memcmp(body + length - 4, " end", 4) == 0);

    int request = sceHttpCreateRequestWithURL(connection, SCE_HTTP_METHOD_GET, url(g_base, "/chunked"), 0);
    unsigned long long content_length;
    sceHttpSendRequest(request, NULL, 0);
    CHECK_EQ(sceHttpGetResponseContentLength(request, &content_length), SCE_HTTP_ERROR_NO_CONTENT_LENGTH);
    CHECK_EQ(read_all(request, body, sizeof(body), 1), length);
    sceHttpDeleteRequest(request);

    /* A Content-Length body arriving in pieces comes whole from one read, as Sound Shapes needs */
    request = sceHttpCreateRequestWithURL(connection, SCE_HTTP_METHOD_GET, url(g_base, "/split"), 0);
    CHECK_EQ(sceHttpSendRequest(request, NULL, 0), 0);
    CHECK_EQ(sceHttpReadData(request, body, 4096), 3000);
    CHECK(body[0] == 'a' && body[1500] == 'b' && body[2999] == 'c');
    CHECK_EQ(sceHttpReadData(request, body, 4096), 0);
    sceHttpDeleteRequest(request);

    /* gzip: decompressed only when asked for through the API */
    length = fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/gzip"), NULL, &status, body, sizeof(body), NULL);
    CHECK_EQ(length, 11 * 2000);
    request = sceHttpCreateRequestWithURL(connection, SCE_HTTP_METHOD_GET, url(g_base, "/gzip"), 0);
    CHECK_EQ(sceHttpSetAcceptEncodingGZIPEnabled(request, SCE_HTTP_ENABLE), 0);
    CHECK_EQ(sceHttpSendRequest(request, NULL, 0), 0);
    CHECK_EQ(read_all(request, body, sizeof(body), 333), 11 * 2000);
    CHECK(memcmp(body, "compressed compressed", 21) == 0);
    sceHttpDeleteRequest(request);
    request = sceHttpCreateRequestWithURL(connection, SCE_HTTP_METHOD_GET, url(g_base, "/gzip"), 0);
    sceHttpSetAcceptEncodingGZIPEnabled(request, SCE_HTTP_ENABLE);
    sceHttpSetInflateGZIPEnabled(request, SCE_HTTP_DISABLE);
    sceHttpSendRequest(request, NULL, 0);
    length = read_all(request, body, sizeof(body), 4096);
    CHECK(length > 0 && length < 1000 && (unsigned char)body[0] == 0x1f && (unsigned char)body[1] == 0x8b);
    sceHttpDeleteRequest(request);

    length = fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/close"), NULL, &status, body, sizeof(body), NULL);
    CHECK_EQ(length, 12 * 100);

    request = sceHttpCreateRequestWithURL(connection, SCE_HTTP_METHOD_GET, url(g_base, "/big"), 0);
    CHECK_EQ(sceHttpSendRequest(request, NULL, 0), 0);
    CHECK_EQ(read_all(request, body, sizeof(body), 7777), 256 * 4096);
    int intact = 1;
    for (int i = 0; i < 256 * 4096; ++i)
        intact &= (unsigned char)body[i] == (unsigned char)i;
    CHECK(intact);
    sceHttpDeleteRequest(request);
    sceHttpDeleteConnection(connection);
}

static int refuse_redirect(int request, int statusCode, int *method, const char *location, void *userArg)
{
    (void)request, (void)statusCode, (void)method;
    strcpy(userArg, location);
    return -1;
}

static void test_redirects_and_post(int template_)
{
    char body[256], seen[256] = "";
    int status, request;
    printf("redirects, POST\n");
    int connection = sceHttpCreateConnectionWithURL(template_, g_base, 1);
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/redirect"), NULL, &status, body, sizeof(body), NULL), 11);
    CHECK_EQ(status, 200);
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/redirect-chain"), NULL, &status, body, sizeof(body), NULL), 11);
    CHECK_EQ(status, 200);
    CHECK(fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/redirect-loop"), NULL, &status, body, sizeof(body), NULL) >= 0);
    CHECK_EQ(status, 302);

    request = sceHttpCreateRequestWithURL(connection, SCE_HTTP_METHOD_GET, url(g_base, "/redirect"), 0);
    sceHttpSetRedirectCallback(request, refuse_redirect, seen);
    sceHttpSendRequest(request, NULL, 0);
    sceHttpGetStatusCode(request, &status);
    CHECK_EQ(status, 302);
    CHECK(strcmp(seen, url(g_base, "/hello")) == 0);
    sceHttpDeleteRequest(request);

    request = sceHttpCreateRequestWithURL(connection, SCE_HTTP_METHOD_GET, url(g_base, "/redirect"), 0);
    sceHttpSetAutoRedirect(request, SCE_HTTP_DISABLE);
    sceHttpSendRequest(request, NULL, 0);
    sceHttpGetStatusCode(request, &status);
    CHECK_EQ(status, 302);
    sceHttpDeleteRequest(request);

    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_POST, url(g_base, "/echo"), "some data", &status, body, sizeof(body), NULL), 14);
    CHECK(strcmp(body, "POST:some data") == 0);
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_POST, url(g_base, "/echo"), "", &status, body, sizeof(body), NULL), 5);
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_POST, url(g_base, "/post-redirect"), "x=1", &status, body, sizeof(body), &request), 11);
    char *header;
    unsigned int header_size;
    sent_header(request, &header, &header_size);
    CHECK(strncmp(header, "GET /hello", 10) == 0);
    sceHttpDeleteRequest(request);

    /* A custom method, and a path request on the connection */
    request = sceHttpCreateRequest2(connection, "PUT", "/echo", 3);
    CHECK(request > 0);
    CHECK_EQ(sceHttpSendRequest(request, "abc", 3), 0);
    CHECK_EQ(read_all(request, body, sizeof(body), 100), 8);
    sceHttpDeleteRequest(request);
    /* A resolve timeout under a second is a second, as Sony's; 0 stays 0 */
    CHECK_EQ(sceHttpSetResolveTimeOut(connection, 645161), 0);
    CHECK_EQ(vh_find(connection, VH_CONNECTION)->settings.resolve_timeout_us, 1000000);
    CHECK_EQ(sceHttpSetResolveTimeOut(connection, 0), 0);
    CHECK_EQ(vh_find(connection, VH_CONNECTION)->settings.resolve_timeout_us, 0);
    CHECK_EQ(sceHttpSetResolveTimeOut(connection, 3000000), 0);
    CHECK_EQ(vh_find(connection, VH_CONNECTION)->settings.resolve_timeout_us, 3000000);

    /* A path where a URL goes: on the connection's server, as Sony's takes it */
    request = sceHttpCreateRequestWithURL2(connection, "GET", "/hello", 0);
    CHECK(request > 0);
    CHECK_EQ(sceHttpSendRequest(request, NULL, 0), 0);
    CHECK_EQ(read_all(request, body, sizeof(body) - 1, 100), 11);
    sceHttpDeleteRequest(request);
    request = sceHttpCreateRequestWithURL(connection, SCE_HTTP_METHOD_GET, "/hello", 0);
    CHECK(request > 0);
    sceHttpDeleteRequest(request);
    CHECK_EQ(sceHttpCreateRequestWithURL(connection, SCE_HTTP_METHOD_GET, "hello", 0), SCE_HTTP_ERROR_INVALID_URL);

    /* An SSL context, asked of a template or a connection by its ID (the Store does so after
     * crSess.action) */
    int created = -1;
    CHECK_EQ(sceHttpSslIsCtxCreated(template_, &created), 0);
    CHECK_EQ(created, 1);
    CHECK_EQ(sceHttpSslIsCtxCreated(connection, &created), 0);
    CHECK_EQ(created, 0);
    CHECK_EQ(sceHttpSslIsCtxCreated(connection, NULL), SCE_HTTP_ERROR_INVALID_VALUE);
    CHECK_EQ(sceHttpSslIsCtxCreated(0x30000999, &created), SCE_HTTP_ERROR_INVALID_ID);
    int secure = sceHttpCreateConnectionWithURL(template_, g_secure_base, 1);
    CHECK_EQ(sceHttpSslIsCtxCreated(secure, &created), 0);
    CHECK_EQ(created, 1);
    sceHttpDeleteConnection(secure);

    /* A body of declared length in pieces, as the shell's Commerce2 sends crSess.action's: each
     * piece but the last returns at once, the last one sends it all; one past the length is refused */
    request = sceHttpCreateRequest2(connection, "POST", "/echo", 17);
    CHECK(request > 0);
    CHECK_EQ(sceHttpSendRequest(request, "first ", 6), 0);
    CHECK_EQ(sceHttpGetStatusCode(request, &status), SCE_HTTP_ERROR_BEFORE_SEND);
    CHECK_EQ(sceHttpSendRequest(request, "second ", 7), 0);
    CHECK_EQ(sceHttpSendRequest(request, "end!!", 5), SCE_HTTP_ERROR_INVALID_VALUE);
    CHECK_EQ(sceHttpSendRequest(request, "end!", 4), 0);
    CHECK_EQ(sceHttpGetStatusCode(request, &status), 0);
    CHECK_EQ(status, 200);
    CHECK_EQ(read_all(request, body, sizeof(body) - 1, 100), 22);
    body[22] = '\0';
    CHECK(strcmp(body, "POST:first second end!") == 0);
    sceHttpDeleteRequest(request);
    /* Deleted halfway: its pieces go with it */
    request = sceHttpCreateRequest2(connection, "POST", "/echo", 10);
    CHECK_EQ(sceHttpSendRequest(request, "half", 4), 0);
    CHECK_EQ(sceHttpDeleteRequest(request), 0);
    CHECK_EQ(sceHttpCreateRequest2(connection, "BAD METHOD", "/", 0), SCE_HTTP_ERROR_UNKNOWN_METHOD);
    sceHttpDeleteConnection(connection);
}

static void test_cookies(int template_)
{
    char body[256], jar[256];
    int status;
    unsigned int length;
    printf("cookies\n");
    int connection = sceHttpCreateConnectionWithURL(template_, g_base, 1);
    fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/cookie/set"), NULL, &status, body, sizeof(body), NULL);
    fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/cookie/echo"), NULL, &status, body, sizeof(body), NULL);
    CHECK(strcmp(body, "session=abc123; other=xyz") == 0);
    fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/echo-cookie"), NULL, &status, body, sizeof(body), NULL);
    CHECK(strcmp(body, "session=abc123") == 0);
    CHECK_EQ(sceHttpGetCookie(url(g_base, "/cookie/x"), jar, &length, sizeof(jar), 0), 0);
    CHECK(strcmp(jar, "session=abc123; other=xyz") == 0);
    CHECK_EQ(length, strlen(jar));

    unsigned int size = 0;
    CHECK_EQ(sceHttpCookieExport(NULL, 0, &size), 0);
    char *exported = malloc(size);
    CHECK_EQ(sceHttpCookieExport(exported, size, &size), 0);
    CHECK_EQ(sceHttpCookieFlush(), 0);
    CHECK_EQ(sceHttpGetCookie(url(g_base, "/"), jar, &length, sizeof(jar), 0), 0);
    CHECK_EQ(length, 0);
    CHECK_EQ(sceHttpCookieImport(exported, size), 0);
    free(exported);
    sceHttpGetCookie(url(g_base, "/cookie/"), jar, &length, sizeof(jar), 0);
    CHECK(strcmp(jar, "session=abc123; other=xyz") == 0);

    /* Domain cookies, Secure, deletion */
    CHECK_EQ(sceHttpAddCookie("http://www.example.com/a/b", "d=1; Domain=.example.com", 0), 0);
    CHECK_EQ(sceHttpAddCookie("http://www.example.com/a/b", "p=2", 0), 0);
    CHECK_EQ(sceHttpAddCookie("http://www.example.com/", "s=3; Secure; Expires=Wed, 21 Oct 2099 07:28:00 GMT", 0), 0);
    CHECK_EQ(sceHttpAddCookie("http://www.example.com/", "old=4; Expires=Wed, 21 Oct 2015 07:28:00 GMT", 0), 0);
    CHECK_EQ(sceHttpAddCookie("http://www.example.com/", "x=5; Domain=other.com", 0), 0);
    /* Set from /a/b, so their path is /a */
    sceHttpGetCookie("http://example.com/", jar, &length, sizeof(jar), 0);
    CHECK_EQ(length, 0);
    sceHttpGetCookie("http://example.com/a/x", jar, &length, sizeof(jar), 0);
    CHECK(strcmp(jar, "d=1") == 0);
    sceHttpGetCookie("http://www.example.com/a/c", jar, &length, sizeof(jar), 1);
    CHECK(strcmp(jar, "d=1; p=2; s=3") == 0);
    sceHttpAddCookie("http://www.example.com/a/b", "p=2; Max-Age=0", 0);
    sceHttpGetCookie("http://www.example.com/a/c", jar, &length, sizeof(jar), 0);
    CHECK(strcmp(jar, "d=1") == 0);
    CHECK_EQ(sceHttpGetCookie("http://www.example.com/a/c", jar, &length, 2, 0), SCE_HTTP_ERROR_OUT_OF_SIZE);

    /* Turned off for a request */
    int request = sceHttpCreateRequestWithURL(connection, SCE_HTTP_METHOD_GET, url(g_base, "/echo-cookie"), 0);
    sceHttpSetCookieEnabled(request, SCE_HTTP_DISABLE);
    sceHttpSendRequest(request, NULL, 0);
    CHECK_EQ(read_all(request, body, sizeof(body), 100), 0);
    sceHttpDeleteRequest(request);
    sceHttpCookieFlush();
    sceHttpDeleteConnection(connection);
}

static int auth_callback(int request, SceHttpAuthType authType, const char *realm, char *username, char *password,
                         int needEntity, unsigned char **entityBody, unsigned int *entitySize, int *save, void *userArg)
{
    (void)request, (void)needEntity, (void)entityBody, (void)entitySize, (void)save;
    ++*(int *)userArg;
    if (!(authType == SCE_HTTP_AUTH_BASIC && strcmp(realm, "test realm") == 0) &&
        !(authType == SCE_HTTP_AUTH_DIGEST && strcmp(realm, "digest realm") == 0))
        return -1;
    strcpy(username, "user");
    strcpy(password, "pass");
    return 0;
}

static void test_auth(int template_)
{
    char body[64];
    int status, calls = 0;
    printf("basic auth\n");
    int connection = sceHttpCreateConnectionWithURL(template_, g_base, 1);
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/auth"), NULL, &status, body, sizeof(body), NULL), 2);
    CHECK_EQ(status, 401);
    sceHttpSetAuthInfoCallback(connection, auth_callback, &calls);
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/auth"), NULL, &status, body, sizeof(body), NULL), 7);
    CHECK_EQ(status, 200);
    CHECK_EQ(calls, 1);
    /* Digest, MD5 and MD5-sess, qop=auth */
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/digest"), NULL, &status, body, sizeof(body), NULL), 14);
    CHECK_EQ(status, 200);
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/digest-sess"), NULL, &status, body, sizeof(body), NULL), 14);
    CHECK_EQ(status, 200);
    CHECK_EQ(calls, 3);
    sceHttpDeleteConnection(connection);
}

typedef struct Slow
{
    int request, result;
} Slow;

static void *send_slow(void *argument)
{
    Slow *slow = argument;
    slow->result = sceHttpSendRequest(slow->request, NULL, 0);
    return NULL;
}

/* Waits until the request is inside its send, so what follows meets it busy whatever the load */
static void wait_busy(int request)
{
    for (int waited = 0; waited < 5000; ++waited) {
        vh_lock();
        VhObject *object = vh_find(request, VH_REQUEST);
        int busy = object != NULL && object->as.request.busy;
        vh_unlock();
        if (busy)
            break;
        usleep(1000);
    }
    /* A moment more, so it is waiting on the server rather than about to */
    usleep(50000);
}

static void test_abort_and_errors(int template_)
{
    char body[64];
    printf("abort, errors, deletion\n");
    int connection = sceHttpCreateConnectionWithURL(template_, g_base, 1);
    Slow slow = {sceHttpCreateRequestWithURL(connection, SCE_HTTP_METHOD_GET, url(g_base, "/slow"), 0), 1};
    pthread_t thread;
    pthread_create(&thread, NULL, send_slow, &slow);
    wait_busy(slow.request);
    CHECK_EQ(sceHttpReadData(slow.request, body, sizeof(body)), SCE_HTTP_ERROR_BUSY);
    CHECK_EQ(sceHttpAbortRequest(slow.request), 0);
    pthread_join(thread, NULL);
    CHECK_EQ(slow.result, SCE_HTTP_ERROR_ABORTED);
    CHECK_EQ(sceHttpReadData(slow.request, body, sizeof(body)), SCE_HTTP_ERROR_NOT_IN_COM);
    CHECK_EQ(sceHttpDeleteRequest(slow.request), 0);

    /* Deleting a connection whose request is busy aborts it; both are gone at once */
    int doomed = sceHttpCreateConnectionWithURL(template_, g_base, 1);
    slow.request = sceHttpCreateRequestWithURL(doomed, SCE_HTTP_METHOD_GET, url(g_base, "/slow"), 0);
    pthread_create(&thread, NULL, send_slow, &slow);
    wait_busy(slow.request);
    CHECK_EQ(sceHttpDeleteConnection(doomed), 0);
    CHECK_EQ(sceHttpDeleteRequest(slow.request), SCE_HTTP_ERROR_INVALID_ID);
    pthread_join(thread, NULL);
    CHECK_EQ(slow.result, SCE_HTTP_ERROR_ABORTED);
    CHECK_EQ(sceHttpSendRequest(slow.request, NULL, 0), SCE_HTTP_ERROR_INVALID_ID);

    int request = sceHttpCreateRequestWithURL(connection, SCE_HTTP_METHOD_GET, url(g_base, "/hello"), 0);
    CHECK_EQ(sceHttpReadData(request, body, sizeof(body)), SCE_HTTP_ERROR_BEFORE_SEND);
    int status;
    CHECK_EQ(sceHttpGetStatusCode(request, &status), SCE_HTTP_ERROR_BEFORE_SEND);
    CHECK_EQ(sceHttpSetRecvTimeOut(request, 200000), 0);
    sceHttpDeleteRequest(request);
    request = sceHttpCreateRequestWithURL(connection, SCE_HTTP_METHOD_GET, url(g_base, "/slow"), 0);
    sceHttpSetRecvTimeOut(request, 200000);
    CHECK_EQ(sceHttpSendRequest(request, NULL, 0), SCE_HTTP_ERROR_TIMEOUT);
    sceHttpDeleteRequest(request);

    CHECK_EQ(sceHttpCreateConnectionWithURL(template_, "ftp://example.com/", 1), SCE_HTTP_ERROR_UNKNOWN_SCHEME);
    CHECK_EQ(sceHttpCreateConnectionWithURL(template_, "not a url", 1), SCE_HTTP_ERROR_INVALID_URL);
    CHECK_EQ(sceHttpCreateConnection(template_, "localhost", "gopher", 70, 1), SCE_HTTP_ERROR_UNKNOWN_SCHEME);
    CHECK_EQ(sceHttpCreateConnectionWithURL(12345, g_base, 1), SCE_HTTP_ERROR_INVALID_ID);
    CHECK_EQ(sceHttpSendRequest(12345, NULL, 0), SCE_HTTP_ERROR_INVALID_ID);
    CHECK_EQ(sceHttpAddRequestHeader(connection, "Bad\nName", "x", SCE_HTTP_HEADER_ADD), SCE_HTTP_ERROR_INVALID_VALUE);

    /* Nothing listens on port 1 */
    int closed = sceHttpCreateConnection(template_, "127.0.0.1", "http", 1, 1);
    request = sceHttpCreateRequest(closed, SCE_HTTP_METHOD_GET, "/", 0);
    CHECK_EQ(sceHttpSendRequest(request, NULL, 0), SCE_HTTP_ERROR_NETWORK);
    int errno_value = 0;
    CHECK_EQ(sceHttpGetLastErrno(request, &errno_value), 0);
    CHECK(errno_value != 0);

    /* Deleting a connection deletes its requests */
    CHECK_EQ(sceHttpDeleteConnection(closed), 0);
    CHECK_EQ(sceHttpDeleteRequest(request), SCE_HTTP_ERROR_INVALID_ID);

    /* Headers added on the connection reach its requests */
    CHECK_EQ(sceHttpAddRequestHeader(connection, "X-Test", "one", SCE_HTTP_HEADER_OVERWRITE), 0);
    CHECK_EQ(sceHttpAddRequestHeader(connection, "x-test", "two", SCE_HTTP_HEADER_OVERWRITE), 0);
    static char headers[4096];
    fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/headers"), NULL, &status, headers, sizeof(headers), NULL);
    /* Overwriting replaces the header, under the name it was given the second time */
    CHECK(strstr(headers, "x-test: two") != NULL && strstr(headers, "one") == NULL);
    CHECK_EQ(sceHttpRemoveRequestHeader(connection, "X-TEST"), 0);
    CHECK_EQ(sceHttpRemoveRequestHeader(connection, "X-TEST"), SCE_HTTP_ERROR_NOT_FOUND);
    sceHttpDeleteConnection(connection);
}

#define VH_TEST_EAGAIN ((int)0x80431082)

/* The whole body of a non-blocking request, waiting on the epoll whenever it would block */
static int read_nonblocking(int request, SceHttpEpollHandle epoll, char *out, int capacity)
{
    SceHttpNBEvent events[4];
    int total = 0;
    for (;;)
    {
        int got = sceHttpReadData(request, out + total, (unsigned int)(capacity - total < 700 ? capacity - total : 700));
        if (got == VH_TEST_EAGAIN)
        {
            if (sceHttpWaitRequest(epoll, events, 4, 5000000) != 1 || events[0].id != request ||
                !(events[0].events & SCE_HTTP_NB_EVENT_IN))
                return -1;
            continue;
        }
        if (got <= 0)
            return got < 0 ? got : total;
        total += got;
    }
}

static void test_nonblocking(int template_)
{
    static char body[16384];
    SceHttpNBEvent events[4];
    SceHttpEpollHandle epoll;
    int marker, status, enabled = 0;
    printf("non-blocking, epoll\n");
    CHECK_EQ(sceHttpCreateEpoll(&epoll), 0);
    int connection = sceHttpCreateConnectionWithURL(template_, g_base, 1);
    CHECK_EQ(sceHttpSetNonblock(connection, SCE_HTTP_ENABLE), 0);
    CHECK_EQ(sceHttpSetEpoll(connection, epoll, &marker), 0);

    /* Settings come from the connection */
    int request = sceHttpCreateRequestWithURL(connection, SCE_HTTP_METHOD_GET, url(g_base, "/chunked"), 0);
    CHECK_EQ(sceHttpGetNonblock(request, &enabled), 0);
    CHECK_EQ(enabled, SCE_HTTP_ENABLE);
    SceHttpEpollHandle seen = NULL;
    void *argument = NULL;
    CHECK_EQ(sceHttpGetEpoll(request, &seen, &argument), 0);
    CHECK(seen == epoll && argument == &marker);

    CHECK_EQ(sceHttpSendRequest(request, NULL, 0), VH_TEST_EAGAIN);
    CHECK_EQ(sceHttpSendRequest(request, NULL, 0) == 0 || sceHttpSendRequest(request, NULL, 0) == VH_TEST_EAGAIN, 1);
    int count = sceHttpWaitRequest(epoll, events, 4, 5000000);
    CHECK_EQ(count, 1);
    CHECK(events[0].id == request && events[0].userArg == &marker && (events[0].events & SCE_HTTP_NB_EVENT_OUT));
    /* Reported once */
    CHECK_EQ(sceHttpWaitRequest(epoll, events, 4, 0), 0);
    CHECK_EQ(sceHttpSendRequest(request, NULL, 0), 0);
    CHECK_EQ(sceHttpGetStatusCode(request, &status), 0);
    CHECK_EQ(status, 200);
    CHECK_EQ(read_nonblocking(request, epoll, body, sizeof(body)), 6 + 7 + 5000 + 4);
    CHECK(memcmp(body, "first second ", 13) == 0);
    sceHttpDeleteRequest(request);

    /* A POST, its body sent from the library's copy */
    request = sceHttpCreateRequestWithURL(connection, SCE_HTTP_METHOD_POST, url(g_base, "/echo"), 5);
    char data[] = "12345";
    CHECK_EQ(sceHttpSendRequest(request, data, 5), VH_TEST_EAGAIN);
    memset(data, 'x', 5);
    CHECK_EQ(sceHttpWaitRequest(epoll, events, 4, 5000000), 1);
    CHECK_EQ(sceHttpSendRequest(request, data, 5), 0);
    CHECK_EQ(read_nonblocking(request, epoll, body, sizeof(body)), 10);
    CHECK(memcmp(body, "POST:12345", 10) == 0);
    sceHttpDeleteRequest(request);

    /* Without an epoll, the app calls again until it is done */
    request = sceHttpCreateRequestWithURL(connection, SCE_HTTP_METHOD_GET, url(g_base, "/hello"), 0);
    CHECK_EQ(sceHttpUnsetEpoll(request), 0);
    int result, tries = 0;
    while ((result = sceHttpSendRequest(request, NULL, 0)) == VH_TEST_EAGAIN && ++tries < 500)
        usleep(10000);
    CHECK_EQ(result, 0);
    int total = 0;
    for (tries = 0; tries < 500; ++tries)
    {
        result = sceHttpReadData(request, body + total, 4);
        if (result == VH_TEST_EAGAIN)
        {
            usleep(10000);
            continue;
        }
        if (result <= 0)
            break;
        total += result;
    }
    CHECK_EQ(result, 0);
    CHECK_EQ(total, 11);
    CHECK(memcmp(body, "hello world", 11) == 0);
    sceHttpDeleteRequest(request);

    /* https, the handshake on the worker */
    int secure = sceHttpCreateConnectionWithURL(template_, g_secure_base, 1);
    sceHttpSetNonblock(secure, SCE_HTTP_ENABLE);
    sceHttpSetEpoll(secure, epoll, NULL);
    sceHttpsDisableOption2(secure, SCE_HTTPS_FLAG_SERVER_VERIFY);
    request = sceHttpCreateRequestWithURL(secure, SCE_HTTP_METHOD_GET, url(g_secure_base, "/hello"), 0);
    CHECK_EQ(sceHttpSendRequest(request, NULL, 0), VH_TEST_EAGAIN);
    CHECK_EQ(sceHttpWaitRequest(epoll, events, 4, 5000000), 1);
    CHECK_EQ(sceHttpSendRequest(request, NULL, 0), 0);
    CHECK_EQ(read_nonblocking(request, epoll, body, sizeof(body)), 11);
    sceHttpDeleteRequest(request);
    sceHttpDeleteConnection(secure);

    /* A failed request is reported as a socket error */
    int closed = sceHttpCreateConnection(template_, "127.0.0.1", "http", 1, 1);
    sceHttpSetNonblock(closed, SCE_HTTP_ENABLE);
    sceHttpSetEpoll(closed, epoll, NULL);
    request = sceHttpCreateRequest(closed, SCE_HTTP_METHOD_GET, "/", 0);
    CHECK_EQ(sceHttpSendRequest(request, NULL, 0), VH_TEST_EAGAIN);
    CHECK_EQ(sceHttpWaitRequest(epoll, events, 4, 5000000), 1);
    CHECK(events[0].events & SCE_HTTP_NB_EVENT_SOCK_ERR);
    CHECK_EQ(sceHttpSendRequest(request, NULL, 0), SCE_HTTP_ERROR_NETWORK);
    sceHttpDeleteConnection(closed);

    /* Waits: a timeout, an abort, and a request deleted while it runs */
    CHECK_EQ(sceHttpWaitRequest(epoll, events, 4, 100000), 0);
    CHECK_EQ(sceHttpAbortWaitRequest(epoll), 0);
    CHECK_EQ(sceHttpWaitRequest(epoll, events, 4, -1), SCE_HTTP_ERROR_ABORTED);
    request = sceHttpCreateRequestWithURL(connection, SCE_HTTP_METHOD_GET, url(g_base, "/slow"), 0);
    CHECK_EQ(sceHttpSendRequest(request, NULL, 0), VH_TEST_EAGAIN);
    usleep(100000);
    CHECK_EQ(sceHttpDeleteRequest(request), 0);
    CHECK_EQ(sceHttpSendRequest(request, NULL, 0), SCE_HTTP_ERROR_INVALID_ID);
    CHECK_EQ(sceHttpWaitRequest(epoll, events, 4, 300000), 0);

    CHECK_EQ(sceHttpWaitRequest(epoll, NULL, 4, 0), SCE_HTTP_ERROR_INVALID_VALUE);
    CHECK_EQ(sceHttpDestroyEpoll(epoll), 0);
    CHECK_EQ(sceHttpGetEpoll(connection, &seen, &argument), 0);
    CHECK(seen == NULL);
    CHECK_EQ(sceHttpWaitRequest(epoll, events, 4, 0), SCE_HTTP_ERROR_INVALID_ID);
    sceHttpDeleteConnection(connection);
}

static int accept_anything(unsigned int verifyErr, void *const sslCert[], int certNum, void *userArg)
{
    (void)sslCert, (void)certNum;
    *(unsigned int *)userArg = verifyErr;
    return 0;
}

static void test_https(int template_)
{
    char body[64];
    int status, ssl_error;
    unsigned int detail, seen = 0;
    printf("https\n");
    int connection = sceHttpCreateConnectionWithURL(template_, g_secure_base, 1);
    int request;
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(g_secure_base, "/hello"), NULL, &status, body, sizeof(body), &request),
             SCE_HTTP_ERROR_SSL);
    CHECK_EQ(sceHttpsGetSslError(request, &ssl_error, &detail), 0);
    CHECK_EQ(ssl_error, SCE_HTTPS_ERROR_CERT);
    CHECK(detail & SCE_HTTPS_ERROR_SSL_UNKNOWN_CA);
    sceHttpDeleteRequest(request);

    request = sceHttpCreateRequestWithURL(connection, SCE_HTTP_METHOD_GET, url(g_secure_base, "/hello"), 0);
    sceHttpsSetSslCallback(request, accept_anything, &seen);
    CHECK_EQ(sceHttpSendRequest(request, NULL, 0), 0);
    CHECK(seen & SCE_HTTPS_ERROR_SSL_UNKNOWN_CA);
    CHECK_EQ(read_all(request, body, sizeof(body), 100), 11);
    sceHttpDeleteRequest(request);

    request = sceHttpCreateRequestWithURL(connection, SCE_HTTP_METHOD_GET, url(g_secure_base, "/hello"), 0);
    sceHttpsDisableOption2(request, SCE_HTTPS_FLAG_SERVER_VERIFY);
    CHECK_EQ(sceHttpSendRequest(request, NULL, 0), 0);
    sceHttpDeleteRequest(request);

    /* Trusting the server's certificate */
    FILE *file = fopen(g_cert_path, "rb");
    static char pem[8192];
    size_t size = fread(pem, 1, sizeof(pem), file);
    fclose(file);
    SceHttpsData data = {pem, (unsigned int)size};
    const SceHttpsData *list[] = {&data};
    /* A key that isn't one is refused */
    CHECK_EQ(sceHttpsLoadCert(1, list, &data, &data), SCE_HTTP_ERROR_INVALID_VALUE);
    SceHttpsData garbage = {"not a certificate", 17};
    const SceHttpsData *bad[] = {&garbage};
    CHECK_EQ(sceHttpsLoadCert(1, bad, NULL, NULL), SCE_HTTP_ERROR_INVALID_VALUE);
    /* Self-signed and loaded by the app: trusted as itself */
    CHECK_EQ(sceHttpsLoadCert(1, list, NULL, NULL), 0);
    char first[32], second[32];
    CHECK(fetch(connection, SCE_HTTP_METHOD_GET, url(g_secure_base, "/conn"), NULL, &status, first, sizeof(first), NULL) > 0);
    CHECK(fetch(connection, SCE_HTTP_METHOD_GET, url(g_secure_base, "/conn"), NULL, &status, second, sizeof(second), NULL) > 0);
    CHECK(strcmp(first, second) == 0);
    static char big[2 * 1024 * 1024];
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(g_secure_base, "/big"), NULL, &status, big, sizeof(big), NULL), 256 * 4096);
    sceHttpDeleteConnection(connection);

    /* The certificate is for 127.0.0.1, not localhost */
    char other[64];
    snprintf(other, sizeof(other), "https://localhost:%d", g_port + 1);
    connection = sceHttpCreateConnectionWithURL(template_, other, 1);
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(other, "/hello"), NULL, &status, body, sizeof(body), &request), SCE_HTTP_ERROR_SSL);
    sceHttpsGetSslError(request, &ssl_error, &detail);
    CHECK_EQ(detail, SCE_HTTPS_ERROR_SSL_CN_CHECK);
    sceHttpDeleteRequest(request);
    request = sceHttpCreateRequestWithURL(connection, SCE_HTTP_METHOD_GET, url(other, "/hello"), 0);
    sceHttpsDisableOption2(request, SCE_HTTPS_FLAG_CN_CHECK);
    CHECK_EQ(sceHttpSendRequest(request, NULL, 0), 0);
    sceHttpDeleteRequest(request);
    sceHttpDeleteConnection(connection);

    /* Unloaded, the certificate is unknown again */
    CHECK_EQ(sceHttpsUnloadCert(), 0);
    connection = sceHttpCreateConnectionWithURL(template_, g_secure_base, 1);
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(g_secure_base, "/hello"), NULL, &status, body, sizeof(body), &request),
             SCE_HTTP_ERROR_SSL);
    sceHttpsGetSslError(request, &ssl_error, &detail);
    CHECK_EQ(detail, SCE_HTTPS_ERROR_SSL_UNKNOWN_CA);
    sceHttpDeleteRequest(request);
    sceHttpDeleteConnection(connection);
}

/* Writes a TLS record of the given type holding data */
static size_t record(unsigned char *out, int type, const unsigned char *data, size_t size)
{
    out[0] = (unsigned char)type, out[1] = 3, out[2] = 3;
    out[3] = (unsigned char)(size >> 8), out[4] = (unsigned char)size;
    memcpy(out + 5, data, size);
    return size + 5;
}

static void test_record_scan(void)
{
    /* ServerHello, a Certificate split over two records, CertificateRequest, ServerHelloDone */
    static const unsigned char hello[] = {2, 0, 0, 3, 1, 2, 3};
    static const unsigned char certificate_first[] = {11, 0, 0, 6, 9, 9};
    static const unsigned char certificate_rest[] = {9, 9, 9, 9, 13, 0, 0, 1, 7, 14, 0, 0, 0};
    static const unsigned char cipher_spec[] = {1};
    /* After ChangeCipherSpec, a byte 13 at a message's start means nothing */
    static const unsigned char encrypted[] = {13, 0, 0, 0};
    unsigned char flight[128];
    printf("TLS 1.2 handshake scan\n");
    for (int with_request = 0; with_request < 2; ++with_request) {
        size_t size = record(flight, 22, hello, sizeof(hello));
        size += record(flight + size, 22, certificate_first, sizeof(certificate_first));
        unsigned char rest[sizeof(certificate_rest)];
        memcpy(rest, certificate_rest, sizeof(rest));
        if (!with_request)
            rest[4] = 15;
        size += record(flight + size, 22, rest, sizeof(rest));
        size += record(flight + size, 20, cipher_spec, sizeof(cipher_spec));
        size += record(flight + size, 22, encrypted, sizeof(encrypted));
        /* Fed whole, a byte at a time, and in pieces of 7 */
        for (size_t piece = 0; piece < 3; ++piece) {
            VhRecordScan scan;
            memset(&scan, 0, sizeof(scan));
            size_t step = piece == 0 ? size : piece == 1 ? 1 : 7;
            for (size_t at = 0; at < size; at += step)
                vh_record_scan(&scan, flight + at, at + step < size ? step : size - at);
            CHECK_EQ(scan.certificate_request, with_request);
            CHECK_EQ(scan.done, 1);
        }
    }
}

static void test_parse_header(void)
{
    static const char block[] = "HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nX-Folded: one\r\n two\r\n"
                                "set-cookie: b=2  \r\nEmpty:\r\n\r\n";
    const char *value;
    unsigned int length, at = 0;
    char seen[64] = "";
    printf("response header parsing\n");
    /* Repeated fields, walked with the returned offset as Sony's own code does */
    for (int result; (result = sceHttpParseResponseHeader(block + at, sizeof(block) - 1 - at, "Set-Cookie", &value,
                                                          &length)) > 0;
         at += (unsigned int)result)
        strncat(seen, value, length), strcat(seen, "|");
    CHECK(strcmp(seen, "a=1|b=2  |") == 0);
    CHECK(sceHttpParseResponseHeader(block, sizeof(block) - 1, "X-Folded", &value, &length) > 0);
    CHECK(length == 9 && memcmp(value, "one\r\n two", 9) == 0);
    CHECK(sceHttpParseResponseHeader(block, sizeof(block) - 1, "Empty", &value, &length) > 0);
    CHECK_EQ(length, 0);
    CHECK_EQ(sceHttpParseResponseHeader(block, sizeof(block) - 1, "Cookie", &value, &length),
             SCE_HTTP_ERROR_PARSE_HTTP_NOT_FOUND);
    CHECK_EQ(sceHttpParseResponseHeader(NULL, 0, "A", &value, &length), SCE_HTTP_ERROR_PARSE_HTTP_INVALID_RESPONSE);
}

/* Sony's order: the request's list from the front (cookies, then the newest headers, then the
 * Host it got when made, then what it inherited), then Connection and Content-Length */
static void test_header_order(void)
{
    char body[64], *header;
    unsigned int size;
    int status;
    printf("header order\n");
    int template_ = sceHttpCreateTemplate("Agent", SCE_HTTP_VERSION_1_1, 0);
    int connection = sceHttpCreateConnectionWithURL(template_, g_base, 1);
    sceHttpAddRequestHeader(connection, "X-Connection", "c", SCE_HTTP_HEADER_ADD);
    int request = sceHttpCreateRequestWithURL(connection, SCE_HTTP_METHOD_POST, url(g_base, "/echo"), 2);
    sceHttpAddRequestHeader(request, "X-First", "1", SCE_HTTP_HEADER_ADD);
    sceHttpAddRequestHeader(request, "X-Second", "2", SCE_HTTP_HEADER_ADD);
    sceHttpAddCookie(url(g_base, "/"), "order=1", 0);
    CHECK_EQ(sceHttpSendRequest(request, "hi", 2), 0);
    read_all(request, body, sizeof(body), 64);
    sent_header(request, &header, &size);
    char expected[512];
    snprintf(expected, sizeof(expected),
             "POST /echo HTTP/1.1\r\nCookie: order=1\r\nX-Second: 2\r\nX-First: 1\r\nHost: 127.0.0.1:%d\r\n"
             "X-Connection: c\r\nUser-Agent: Agent libhttp/3.74 (PS Vita)\r\nConnection: Keep-Alive\r\n"
             "Content-Length: 2\r\n\r\n",
             g_port);
    CHECK(size == strlen(expected) && memcmp(header, expected, size) == 0);
    if (size != strlen(expected) || memcmp(header, expected, size) != 0)
        printf("  sent:\n%.*s", (int)size, header);
    sceHttpDeleteRequest(request);
    /* A GET has no Content-Length */
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/hello"), NULL, &status, body, sizeof(body), &request), 11);
    sent_header(request, &header, &size);
    CHECK(memmem(header, size, "Content-Length", 14) == NULL);
    sceHttpDeleteRequest(request);
    sceHttpCookieFlush();
    sceHttpDeleteTemplate(template_);
}

static int has_pair(const SceHttpHeaderPair *pairs, unsigned int count, const char *name, const char *value)
{
    for (unsigned int i = 0; i < count; ++i)
        if (strcmp(pairs[i].name, name) == 0 && pairs[i].value != NULL && strcmp(pairs[i].value, value) == 0)
            return 1;
    return 0;
}

static void test_raw_and_all_headers(void)
{
    SceHttpHeaderPair pairs[16];
    unsigned int count = 99, size;
    char length[32], body[64], *header;
    printf("raw headers and all headers\n");
    int template_ = sceHttpCreateTemplate("Agent", SCE_HTTP_VERSION_1_1, 0);
    int connection = sceHttpCreateConnectionWithURL(template_, g_base, 1);
    int request = sceHttpCreateRequestWithURL(connection, SCE_HTTP_METHOD_POST, url(g_base, "/echo"), 2);

    /* Raw: one line, split at the colon, spaces before the name and the value skipped; ADD only */
    CHECK_EQ(sceHttpAddRequestHeaderRaw(request, "  X-Raw:   one: two", SCE_HTTP_HEADER_ADD), 0);
    CHECK_EQ(sceHttpAddRequestHeaderRaw(request, "X-Raw: again", SCE_HTTP_HEADER_ADD), 0);
    CHECK_EQ(sceHttpAddRequestHeaderRaw(request, "X-Empty:", SCE_HTTP_HEADER_ADD), 0);
    CHECK_EQ(sceHttpAddRequestHeaderRaw(request, "X-Over: 1", SCE_HTTP_HEADER_OVERWRITE), (int)SCE_HTTP_ERROR_INVALID_VALUE);
    CHECK_EQ(sceHttpAddRequestHeaderRaw(request, "no colon", SCE_HTTP_HEADER_ADD), (int)SCE_HTTP_ERROR_INVALID_VALUE);
    CHECK_EQ(sceHttpAddRequestHeaderRaw(request, NULL, SCE_HTTP_HEADER_ADD), (int)SCE_HTTP_ERROR_INVALID_VALUE);
    CHECK_EQ(sceHttpAddRequestHeaderRaw(0x7fff, "X-A: b", SCE_HTTP_HEADER_ADD), (int)SCE_HTTP_ERROR_INVALID_ID);
    /* On templates and connections too */
    CHECK_EQ(sceHttpAddRequestHeaderRaw(connection, "X-Conn: c", SCE_HTTP_HEADER_ADD), 0);
    CHECK_EQ(sceHttpRemoveRequestHeader(connection, "X-Conn"), 0);

    /* All headers: count first, then the pairs; the request's own, then the library's */
    CHECK_EQ(sceHttpRequestGetAllHeaders(request, NULL, &count, NULL, NULL), 0);
    CHECK(count > 5 && count <= 16);
    unsigned int counted = count;
    size = 0;
    CHECK_EQ(sceHttpRequestGetAllHeaders(request, pairs, &count, NULL, &size), 0);
    CHECK_EQ(count, counted);
    CHECK_EQ(size, 21);
    size = sizeof(length);
    CHECK_EQ(sceHttpRequestGetAllHeaders(request, pairs, &count, length, &size), 0);
    CHECK_EQ(count, counted);
    CHECK(strcmp(pairs[0].name, "X-Empty") == 0 && strcmp(pairs[0].value, "") == 0);
    CHECK(strcmp(pairs[1].name, "X-Raw") == 0 && strcmp(pairs[1].value, "again") == 0);
    CHECK(strcmp(pairs[2].name, "X-Raw") == 0 && strcmp(pairs[2].value, "one: two") == 0);
    CHECK(has_pair(pairs, count, "User-Agent", "Agent libhttp/3.74 (PS Vita)"));
    CHECK(strcmp(pairs[count - 2].name, "Connection") == 0 && strcmp(pairs[count - 2].value, "Keep-Alive") == 0);
    CHECK(strcmp(pairs[count - 1].name, "Content-Length") == 0 && pairs[count - 1].value == length);
    CHECK(strcmp(length, "2") == 0);
    /* What is listed is what is sent; the Cookie it went with is listed after, first */
    sceHttpAddCookie(url(g_base, "/"), "pair=1", 0);
    CHECK_EQ(sceHttpSendRequest(request, "hi", 2), 0);
    read_all(request, body, sizeof(body), 64);
    CHECK_EQ(sceHttpRequestGetAllHeaders(request, pairs, &count, length, &size), 0);
    CHECK_EQ(count, counted + 1);
    CHECK(strcmp(pairs[0].name, "Cookie") == 0 && strcmp(pairs[0].value, "pair=1") == 0);
    CHECK(strcmp(pairs[1].name, "X-Empty") == 0);
    sceHttpCookieFlush();
    CHECK_EQ(sent_header(request, &header, &size), 0);
    CHECK(memmem(header, size, "X-Empty: \r\nX-Raw: again\r\nX-Raw: one: two\r\n", 42) != NULL);
    CHECK(memmem(header, size, "Content-Length: 2\r\n", 19) != NULL);
    /* Errors: both missing, the count missing, a connection's ID */
    CHECK_EQ(sceHttpRequestGetAllHeaders(request, NULL, NULL, NULL, NULL), (int)SCE_HTTP_ERROR_INVALID_VALUE);
    CHECK_EQ(sceHttpRequestGetAllHeaders(request, pairs, NULL, NULL, NULL), (int)SCE_HTTP_ERROR_INVALID_VALUE);
    CHECK_EQ(sceHttpRequestGetAllHeaders(connection, NULL, &count, NULL, NULL), (int)SCE_HTTP_ERROR_INVALID_ID);
    sceHttpDeleteRequest(request);

    /* A GET has no Content-Length; gzip adds Accept-Encoding; without keep-alive, close */
    request = sceHttpCreateRequestWithURL(connection, SCE_HTTP_METHOD_GET, url(g_base, "/hello"), 0);
    CHECK_EQ(sceHttpSetAcceptEncodingGZIPEnabled(request, SCE_HTTP_ENABLE), 0);
    CHECK_EQ(sceHttpRequestGetAllHeaders(request, pairs, &count, NULL, NULL), 0);
    CHECK(!has_pair(pairs, count, "Content-Length", "0"));
    for (unsigned int i = 0; i < count; ++i)
        CHECK(strcmp(pairs[i].name, "Content-Length") != 0);
    /* Sony's name for it ends in ": " */
    CHECK(strcmp(pairs[count - 1].name, "Accept-Encoding: ") == 0 && strcmp(pairs[count - 1].value, "gzip") == 0);
    sceHttpDeleteRequest(request);
    int closing = sceHttpCreateConnectionWithURL(template_, g_base, 0);
    request = sceHttpCreateRequestWithURL(closing, SCE_HTTP_METHOD_GET, url(g_base, "/hello"), 0);
    CHECK_EQ(sceHttpRequestGetAllHeaders(request, pairs, &count, NULL, NULL), 0);
    CHECK(has_pair(pairs, count, "Connection", "close"));
    sceHttpDeleteRequest(request);
    sceHttpDeleteTemplate(template_);
}

static void test_user_agent(void)
{
    static char headers[4096];
    char *header;
    unsigned int size;
    int status;
    printf("user agent\n");
    int template_ = sceHttpCreateTemplate(NULL, SCE_HTTP_VERSION_1_1, 0);
    int connection = sceHttpCreateConnectionWithURL(template_, g_base, 1);
    int request = 0;
    fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/headers"), NULL, &status, headers, sizeof(headers), &request);
    sent_header(request, &header, &size);
    CHECK(strstr(header, "User-Agent: libhttp/3.74 (PS Vita)\r\n") != NULL);
    sceHttpDeleteRequest(request);
    /* The app's own replaces it */
    CHECK_EQ(sceHttpAddRequestHeader(connection, "user-agent", "Game/1.0", SCE_HTTP_HEADER_OVERWRITE), 0);
    fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/headers"), NULL, &status, headers, sizeof(headers), NULL);
    CHECK(strstr(headers, "Game/1.0") != NULL && strstr(headers, "libhttp/") == NULL);
    sceHttpDeleteTemplate(template_);
}

/* The request header a template made with this agent sends */
static const char *user_agent_of(const char *agent)
{
    static char headers[4096];
    char *header;
    unsigned int size;
    int status, request = 0;
    int template_ = sceHttpCreateTemplate(agent, SCE_HTTP_VERSION_1_1, 0);
    int connection = sceHttpCreateConnectionWithURL(template_, g_base, 1);
    fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/headers"), NULL, &status, headers, sizeof(headers), &request);
    sent_header(request, &header, &size);
    snprintf(headers, sizeof(headers), "%.*s", (int)size, header);
    sceHttpDeleteTemplate(template_);
    return headers;
}

static size_t read_file(const char *path, char *out, size_t capacity)
{
    FILE *file = fopen(path, "rb");
    size_t size = file != NULL ? fread(out, 1, capacity, file) : 0;
    if (file != NULL)
        fclose(file);
    return size;
}

extern char vh_test_printed[16384];

/* The exports no header names, as Sony's code does them */
static void test_private(int template_)
{
    static char server_pem[8192], client_pem[8192], client_der[8192];
    char body[64], mutual[64];
    int status, value = 99;
    SceHttpMemoryPoolStats before, after;
    printf("private exports\n");
    CHECK_EQ(sceHttpPrivateDebugNothing(), 0);
    CHECK_EQ(sceHttpPrivateCertCheckNothing(), 0);
    CHECK_EQ(sceHttpPrivateLoadedCertInit(NULL, NULL), 0);
    CHECK_EQ(sceHttpGetMemoryPoolStats(&before), 0);

    /* Settings: kept on the object, passed on to what is made from it, checked as Sony's */
    int parent = sceHttpCreateTemplate("Private", SCE_HTTP_VERSION_1_1, 0);
    CHECK_EQ(sceHttpPrivateSetOption19(parent, 7), 0);
    CHECK_EQ(sceHttpPrivateSetOption21(parent, 2), 0);
    CHECK_EQ(vh_find(parent, VH_TEMPLATE)->settings.option21, 0);
    CHECK_EQ(sceHttpPrivateSetOption21(parent, 1), 0);
    CHECK_EQ(sceHttpPrivateSetSocketOption(parent, 1), 0);
    CHECK_EQ(sceHttpPrivateSetMode(parent, 1), SCE_HTTP_ERROR_INVALID_VALUE);
    CHECK_EQ(sceHttpPrivateSetMode(parent, 3), 0);
    CHECK_EQ(sceHttpPrivateSetProxy(parent, 1, 0, NULL, 8080), SCE_HTTP_ERROR_INVALID_VALUE);
    /* Kept but off (mode 0): the requests below go to the server directly */
    CHECK_EQ(sceHttpPrivateSetProxy(parent, 0, 0, "proxy.example", 8080), 0);
    CHECK_EQ(sceHttpPrivateSetSslContextOption(1), 0);
    int connection = sceHttpCreateConnectionWithURL(parent, g_base, 1);
    const VhSettings *inherited = &vh_find(connection, VH_CONNECTION)->settings;
    CHECK_EQ(inherited->option19, 7);
    CHECK_EQ(inherited->option21, 1);
    CHECK_EQ(inherited->option14, 1);
    CHECK_EQ(inherited->option14_set, 1);
    /* Without it, connections leave the socket option alone */
    CHECK_EQ(vh_find(template_, VH_TEMPLATE)->settings.option14_set, 0);
    CHECK_EQ(inherited->mode, 3);
    CHECK(inherited->proxy_host != NULL && strcmp(inherited->proxy_host, "proxy.example") == 0);
    CHECK_EQ(inherited->proxy_port, 8080);
    /* Sony's reads option 14 back with the wrong size: it never succeeds */
    CHECK_EQ(sceHttpPrivateGetSocketOption(connection, &value), SCE_HTTP_ERROR_INVALID_VALUE);
    CHECK_EQ(value, 99);
    CHECK_EQ(sceHttpPrivateGetSocketOption(0x7fff, &value), SCE_HTTP_ERROR_INVALID_ID);
    CHECK_EQ(sceHttpPrivateSetOption19(0x7fff, 1), SCE_HTTP_ERROR_INVALID_ID);

    /* Statistics: no socket before a request, the open one after it (keep-alive) */
    SceHttpPrivateConnectionStats connection_stats;
    SceHttpPrivateRequestStats request_stats;
    CHECK_EQ(sceHttpPrivateGetConnectionStats(connection, NULL), SCE_HTTP_ERROR_INVALID_VALUE);
    CHECK_EQ(sceHttpPrivateGetConnectionStats(parent, &connection_stats), SCE_HTTP_ERROR_INVALID_ID);
    CHECK_EQ(sceHttpPrivateGetConnectionStats(connection, &connection_stats), 0);
    CHECK(connection_stats.alive == 0 && connection_stats.socket == -1);
    int request;
    /* The proxy is off: the request goes to the server directly */
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/hello"), NULL, &status, body, sizeof(body), &request), 11);
    /* A request can't be given the mode */
    CHECK_EQ(sceHttpPrivateSetMode(request, 2), SCE_HTTP_ERROR_INVALID_ID);
    CHECK_EQ(sceHttpPrivateGetConnectionStats(connection, &connection_stats), 0);
    CHECK(connection_stats.alive == 1 && connection_stats.socket >= 0 && connection_stats.shut_down == 0);
    CHECK_EQ(connection_stats.first_socket, connection_stats.socket);
    CHECK_EQ(sceHttpPrivateGetRequestStats(request, NULL), SCE_HTTP_ERROR_INVALID_VALUE);
    CHECK_EQ(sceHttpPrivateGetRequestStats(connection, &request_stats), SCE_HTTP_ERROR_INVALID_ID);
    CHECK_EQ(sceHttpPrivateGetRequestStats(request, &request_stats), 0);
    CHECK(request_stats.socket == connection_stats.socket && request_stats.own_socket == -1);

    /* The dumps: debug output, a line at a time in Sony's formats */
    vh_test_printed[0] = '\0';
    sceHttpPrivateDumpDebugInfo();
    CHECK(strstr(vh_test_printed, "vitals-http: **** libhttp debug information ****\nvitals-http: MEMORY POOL\n"
                                  "vitals-http:  current      max\n") != NULL);
    CHECK(strstr(vh_test_printed, "vitals-http: CONNECTION\nvitals-http: num. of active connection = ") != NULL);
    CHECK(strstr(vh_test_printed, "127.0.0.1(-)\n") != NULL);
    CHECK(strstr(vh_test_printed, "vitals-http: REQUEST\nvitals-http: num. of current request = ") != NULL);
    CHECK(strstr(vh_test_printed, "http  127.0.0.1 /hello\n") != NULL);
    vh_test_printed[0] = '\0';
    sceHttpPrivateDumpMemoryPool();
    CHECK(strncmp(vh_test_printed, "vitals-http:  current      max\nvitals-http: ", 44) == 0);
    vh_test_printed[0] = '\0';
    sceHttpPrivateDumpRequests();
    sceHttpPrivateDumpConnections();
    CHECK(strstr(vh_test_printed, "vitals-http: id       status connId   \n") != NULL);
    CHECK(strstr(vh_test_printed, "vitals-http: id        sock  port leased4  stat \n") != NULL);
    CHECK(strstr(vh_test_printed, "vitals-http: ---------------------\n") != NULL);
    sceHttpDeleteRequest(request);
    sceHttpDeleteTemplate(parent);
    /* Nothing is left behind in the pool, the proxy's copies included */
    CHECK_EQ(sceHttpGetMemoryPoolStats(&after), 0);
    CHECK_EQ(after.currentInuseSize, before.currentInuseSize);

    /* The loaded certificates, one at a time: the server's certificate as a CA */
    size_t server_size = read_file(g_cert_path, server_pem, sizeof(server_pem));
    size_t client_size = read_file(g_client_cert_path, client_pem, sizeof(client_pem));
    size_t key_size = read_file(g_client_key_path, client_der, sizeof(client_der));
    CHECK_EQ(sceHttpsUnloadCert(), 0);
    connection = sceHttpCreateConnectionWithURL(template_, g_secure_base, 1);
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(g_secure_base, "/hello"), NULL, &status, body, sizeof(body), NULL),
             SCE_HTTP_ERROR_SSL);
    CHECK_EQ(sceHttpPrivateLoadedCertAddCa("not a certificate", 17), 0);
    CHECK_EQ(sceHttpPrivateLoadedCertAddCa(server_pem, (unsigned int)server_size), 0);
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(g_secure_base, "/hello"), NULL, &status, body, sizeof(body), NULL), 11);
    sceHttpDeleteConnection(connection);
    CHECK_EQ(sceHttpPrivateLoadedCertClearCa(), 0);
    connection = sceHttpCreateConnectionWithURL(template_, g_secure_base, 1);
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(g_secure_base, "/hello"), NULL, &status, body, sizeof(body), NULL),
             SCE_HTTP_ERROR_SSL);
    sceHttpDeleteConnection(connection);

    /* The client certificate and its key, for a server that wants one */
    snprintf(mutual, sizeof(mutual), "https://127.0.0.1:%d", g_port + 2);
    CHECK_EQ(sceHttpPrivateLoadedCertAddCa(server_pem, (unsigned int)server_size), 0);
    CHECK_EQ(sceHttpPrivateLoadedCertSetClientCert(client_pem, (unsigned int)client_size), 0);
    CHECK_EQ(sceHttpPrivateLoadedCertSetClientKey(client_der, (unsigned int)key_size), 0);
    connection = sceHttpCreateConnectionWithURL(template_, mutual, 1);
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(mutual, "/hello"), NULL, &status, body, sizeof(body), NULL), 11);
    sceHttpDeleteConnection(connection);
    CHECK_EQ(sceHttpPrivateLoadedCertClearClient(), 0);
    connection = sceHttpCreateConnectionWithURL(template_, mutual, 1);
    int refused = fetch(connection, SCE_HTTP_METHOD_GET, url(mutual, "/hello"), NULL, &status, body, sizeof(body), NULL);
    CHECK(refused == (int)SCE_HTTP_ERROR_SSL || refused == (int)SCE_HTTP_ERROR_NETWORK);
    sceHttpDeleteConnection(connection);
    /* Ending the store forgets the CA certificate too */
    CHECK_EQ(sceHttpPrivateLoadedCertTerm(), 0);
    connection = sceHttpCreateConnectionWithURL(template_, g_secure_base, 1);
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(g_secure_base, "/hello"), NULL, &status, body, sizeof(body), NULL),
             SCE_HTTP_ERROR_SSL);
    sceHttpDeleteConnection(connection);
}

extern char vh_test_system_proxy_host[256];
extern unsigned short vh_test_system_proxy_port;

/* What the test proxy has done, asked of it directly */
static void proxy_stats(char *out, int capacity)
{
    char base[64];
    int status;
    snprintf(base, sizeof(base), "http://127.0.0.1:%d", g_port + 5);
    int template_ = sceHttpCreateTemplate("Stats", SCE_HTTP_VERSION_1_1, 0);
    int connection = sceHttpCreateConnectionWithURL(template_, base, 0);
    int got = fetch(connection, SCE_HTTP_METHOD_GET, url(base, "/stats"), NULL, &status, out, capacity - 1, NULL);
    out[got > 0 ? got : 0] = '\0';
    sceHttpDeleteTemplate(template_);
}

static void test_proxy(void)
{
    static char headers[4096], stats[512], pem[8192];
    char body[64], expected[160], length[32], *header;
    unsigned int size, count;
    int status, request, ssl_error;
    unsigned int detail;
    SceHttpHeaderPair pairs[16];
    printf("proxy\n");
    size_t pem_size = read_file(g_cert_path, pem, sizeof(pem));
    SceHttpsData server = {pem, (unsigned int)pem_size};
    const SceHttpsData *list[] = {&server};
    CHECK_EQ(sceHttpsLoadCert(1, list, NULL, NULL), 0);

    /* Set on the template: plain http names the whole URL, and Proxy-Connection replaces Connection */
    int template_ = sceHttpCreateTemplate("Proxied", SCE_HTTP_VERSION_1_1, 0);
    CHECK_EQ(sceHttpPrivateSetProxy(template_, 1, 0, "127.0.0.1", (unsigned short)(g_port + 5)), 0);
    int connection = sceHttpCreateConnectionWithURL(template_, g_base, 1);
    request = sceHttpCreateRequestWithURL(connection, SCE_HTTP_METHOD_GET, url(g_base, "/headers"), 0);
    CHECK_EQ(sceHttpRequestGetAllHeaders(request, pairs, &count, length, &size), 0);
    CHECK(strcmp(pairs[count - 1].name, "Proxy-Connection") == 0);
    CHECK_EQ(sceHttpSendRequest(request, NULL, 0), 0);
    int got = read_all(request, headers, sizeof(headers) - 1, 1000);
    headers[got > 0 ? got : 0] = '\0';
    CHECK(strstr(headers, "Proxy-Connection: Keep-Alive") != NULL);
    CHECK_EQ(sent_header(request, &header, &size), 0);
    snprintf(expected, sizeof(expected), "GET http://127.0.0.1:%d/headers HTTP/1.1\r\n", g_port);
    CHECK(size > strlen(expected) && memcmp(header, expected, strlen(expected)) == 0);
    sceHttpDeleteRequest(request);
    proxy_stats(stats, sizeof(stats));
    snprintf(expected, sizeof(expected), "last=GET http://127.0.0.1:%d/headers HTTP/1.1", g_port);
    CHECK(strstr(stats, expected) != NULL);
    sceHttpDeleteConnection(connection);

    /* https goes through a tunnel, and the server's certificate is still checked */
    connection = sceHttpCreateConnectionWithURL(template_, g_secure_base, 1);
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(g_secure_base, "/hello"), NULL, &status, body, sizeof(body), NULL), 11);
    proxy_stats(stats, sizeof(stats));
    snprintf(expected, sizeof(expected), "last=CONNECT 127.0.0.1:%d HTTP/1.1", g_port + 1);
    CHECK(strstr(stats, expected) != NULL);
    char before[512];
    snprintf(before, sizeof(before), "%s", stats);
    /* The tunnel is kept for the next request, as a direct socket is */
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(g_secure_base, "/hello"), NULL, &status, body, sizeof(body), NULL), 11);
    proxy_stats(stats, sizeof(stats));
    CHECK(strncmp(stats, before, strcspn(before, " ")) == 0);
    sceHttpDeleteConnection(connection);
    CHECK_EQ(sceHttpsUnloadCert(), 0);
    connection = sceHttpCreateConnectionWithURL(template_, g_secure_base, 1);
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(g_secure_base, "/hello"), NULL, &status, body, sizeof(body), &request),
             SCE_HTTP_ERROR_SSL);
    CHECK_EQ(sceHttpsGetSslError(request, &ssl_error, &detail), 0);
    CHECK_EQ(ssl_error, SCE_HTTPS_ERROR_CERT);
    sceHttpDeleteRequest(request);
    sceHttpDeleteConnection(connection);

    /* A tunnel the proxy refuses */
    connection = sceHttpCreateConnectionWithURL(template_, "https://127.0.0.1:1", 1);
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, "https://127.0.0.1:1/", NULL, &status, body, sizeof(body), &request),
             SCE_HTTP_ERROR_SSL);
    CHECK_EQ(sceHttpsGetSslError(request, &ssl_error, &detail), 0);
    CHECK_EQ(ssl_error, SCE_HTTPS_ERROR_PROXY);
    sceHttpDeleteRequest(request);
    sceHttpDeleteConnection(connection);

    /* Turned off again: direct */
    CHECK_EQ(sceHttpPrivateSetProxy(template_, 0, 0, "127.0.0.1", (unsigned short)(g_port + 5)), 0);
    connection = sceHttpCreateConnectionWithURL(template_, g_base, 1);
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/hello"), NULL, &status, body, sizeof(body), &request), 11);
    CHECK_EQ(sent_header(request, &header, &size), 0);
    CHECK(strncmp(header, "GET /hello HTTP/1.1\r\n", 21) == 0);
    sceHttpDeleteRequest(request);
    sceHttpDeleteTemplate(template_);

    /* The system's proxy, for templates made with autoProxyConf 1 only, and over what the object set */
    snprintf(vh_test_system_proxy_host, sizeof(vh_test_system_proxy_host), "127.0.0.1");
    vh_test_system_proxy_port = (unsigned short)(g_port + 5);
    template_ = sceHttpCreateTemplate("System", SCE_HTTP_VERSION_1_1, 1);
    CHECK_EQ(sceHttpPrivateSetProxy(template_, 1, 0, "proxy.invalid", 9), 0);
    connection = sceHttpCreateConnectionWithURL(template_, g_base, 1);
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/hello"), NULL, &status, body, sizeof(body), &request), 11);
    CHECK_EQ(sent_header(request, &header, &size), 0);
    snprintf(expected, sizeof(expected), "GET http://127.0.0.1:%d/hello HTTP/1.1\r\n", g_port);
    CHECK(memcmp(header, expected, strlen(expected)) == 0);
    sceHttpDeleteRequest(request);
    sceHttpDeleteTemplate(template_);
    int direct = sceHttpCreateTemplate("Direct", SCE_HTTP_VERSION_1_1, 0);
    connection = sceHttpCreateConnectionWithURL(direct, g_base, 1);
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/hello"), NULL, &status, body, sizeof(body), &request), 11);
    CHECK_EQ(sent_header(request, &header, &size), 0);
    CHECK(strncmp(header, "GET /hello HTTP/1.1\r\n", 21) == 0);
    sceHttpDeleteRequest(request);
    sceHttpDeleteTemplate(direct);
    /* With none set in the system, none is used */
    vh_test_system_proxy_host[0] = '\0';
    template_ = sceHttpCreateTemplate("System", SCE_HTTP_VERSION_1_1, 1);
    connection = sceHttpCreateConnectionWithURL(template_, g_base, 1);
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(g_base, "/hello"), NULL, &status, body, sizeof(body), &request), 11);
    CHECK_EQ(sent_header(request, &header, &size), 0);
    CHECK(strncmp(header, "GET /hello HTTP/1.1\r\n", 21) == 0);
    sceHttpDeleteRequest(request);
    sceHttpDeleteTemplate(template_);
}

static void test_client_certificate(int template_)
{
    static char server_pem[8192], client_pem[8192], client_der[8192];
    char body[64], base[64];
    int status, request, ssl_error;
    unsigned int detail;
    printf("client certificate\n");
    snprintf(base, sizeof(base), "https://127.0.0.1:%d", g_port + 2);
    SceHttpsData server = {server_pem, (unsigned int)read_file(g_cert_path, server_pem, sizeof(server_pem))};
    SceHttpsData certificate = {client_pem, (unsigned int)read_file(g_client_cert_path, client_pem, sizeof(client_pem))};
    SceHttpsData key = {client_der, (unsigned int)read_file(g_client_key_path, client_der, sizeof(client_der))};
    const SceHttpsData *list[] = {&server};
    int connection = sceHttpCreateConnectionWithURL(template_, base, 1);

    /* Without one, the server ends the handshake: with its alert, or, when its close overtakes the
     * alert, with a reset, which is a network error */
    CHECK_EQ(sceHttpsLoadCert(1, list, NULL, NULL), 0);
    int refused = fetch(connection, SCE_HTTP_METHOD_GET, url(base, "/hello"), NULL, &status, body, sizeof(body), &request);
    CHECK(refused == (int)SCE_HTTP_ERROR_SSL || refused == (int)SCE_HTTP_ERROR_NETWORK);
    /* With TLS 1.3 the server checks the certificate after the client's side of the handshake, so
     * its refusal comes on the first read */
    CHECK_EQ(sceHttpsGetSslError(request, &ssl_error, &detail), 0);
    sceHttpDeleteRequest(request);

    /* With one, PEM certificate and DER key, it serves the request, over a reused socket too */
    CHECK_EQ(sceHttpsLoadCert(1, list, &certificate, &key), 0);
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(base, "/hello"), NULL, &status, body, sizeof(body), NULL), 11);
    CHECK_EQ(status, 200);
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(base, "/hello"), NULL, &status, body, sizeof(body), NULL), 11);
    sceHttpDeleteConnection(connection);

    /* Unloading forgets it */
    CHECK_EQ(sceHttpsUnloadCert(), 0);
    CHECK_EQ(sceHttpsLoadCert(1, list, NULL, NULL), 0);
    connection = sceHttpCreateConnectionWithURL(template_, base, 1);
    refused = fetch(connection, SCE_HTTP_METHOD_GET, url(base, "/hello"), NULL, &status, body, sizeof(body), NULL);
    CHECK(refused == (int)SCE_HTTP_ERROR_SSL || refused == (int)SCE_HTTP_ERROR_NETWORK);
    sceHttpDeleteConnection(connection);
    CHECK_EQ(sceHttpsUnloadCert(), 0);
}

/* Sony's own connections (private HTTPS option 0x40) get the console's handshake: TLS 1.2 and its
 * suites only */
static void test_console_profile(int template_)
{
    char body[64], legacy[64];
    int status, request;
    printf("console TLS profile\n");
    snprintf(legacy, sizeof(legacy), "https://127.0.0.1:%d", g_port + 3);
    int connection = sceHttpCreateConnectionWithURL(template_, legacy, 1);
    sceHttpsDisableOption2(connection, SCE_HTTPS_FLAG_SERVER_VERIFY);
    CHECK_EQ(sceHttpsEnableOptionPrivate(connection, 0x40), 0);
    CHECK(fetch(connection, SCE_HTTP_METHOD_GET, url(legacy, "/cipher"), NULL, &status, body, sizeof(body), NULL) > 0);
    CHECK(strstr(body, "TLSv1.2") != NULL &&
          (strstr(body, "AES256-SHA256") != NULL || strstr(body, "AES128-SHA256") != NULL ||
           strstr(body, "AES256-SHA") != NULL || strstr(body, "AES128-SHA") != NULL));
    if (strstr(body, "TLSv1.2") == NULL)
        printf("  negotiated: %s\n", body);
    sceHttpDeleteConnection(connection);

    /* The ClientHello, byte for byte as the console's in a capture of a working PSN sign-in, but
     * for its random bytes and the host name */
    char hello_base[64];
    snprintf(hello_base, sizeof(hello_base), "https://localhost:%d", g_port + 4);
    connection = sceHttpCreateConnectionWithURL(template_, hello_base, 1);
    sceHttpsEnableOptionPrivate(connection, 0x40);
    remove(g_hello_path);
    fetch(connection, SCE_HTTP_METHOD_GET, url(hello_base, "/"), NULL, &status, body, sizeof(body), &request);
    sceHttpDeleteRequest(request);
    sceHttpDeleteConnection(connection);
    static const char console[] =
        "160303005d" "01000059" "0303" "0000000000000000000000000000000000000000000000000000000000000000"
        "00" "0010" "003d003c0035002f000a0005000400ff" "0100"
        "0020" "0000000e000c0000096c6f63616c686f7374" "000d000a00080401060105010201";
    char sent[512] = "";
    read_file(g_hello_path, sent, sizeof(sent) - 1);
    /* The random bytes, after the record and handshake headers and the version */
    if (strlen(sent) == strlen(console))
        memset(sent + 22, '0', 64);
    CHECK(strcmp(sent, console) == 0);
    if (strcmp(sent, console) != 0)
        printf("  sent     %s\n  expected %s\n", sent, console);

    /* A modern server offers none of those suites: the console's handshake can't reach it */
    connection = sceHttpCreateConnectionWithURL(template_, g_secure_base, 1);
    sceHttpsDisableOption2(connection, SCE_HTTPS_FLAG_SERVER_VERIFY);
    sceHttpsEnableOptionPrivate(connection, 0x40);
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(g_secure_base, "/cipher"), NULL, &status, body, sizeof(body), &request),
             SCE_HTTP_ERROR_SSL);
    sceHttpDeleteRequest(request);
    sceHttpDeleteConnection(connection);

    /* Without the option the same server is reached over TLS 1.3 */
    connection = sceHttpCreateConnectionWithURL(template_, g_secure_base, 1);
    sceHttpsDisableOption2(connection, SCE_HTTPS_FLAG_SERVER_VERIFY);
    CHECK(fetch(connection, SCE_HTTP_METHOD_GET, url(g_secure_base, "/cipher"), NULL, &status, body, sizeof(body), NULL) > 0);
    CHECK(strstr(body, "TLSv1.3") != NULL);
    sceHttpDeleteConnection(connection);
}

/* ux0:data/vitals/redirects.txt: a host that doesn't exist, sent to another */
static void test_host_redirects(int template_)
{
    char body[64], old[64];
    int status;
    printf("host redirects\n");
    snprintf(old, sizeof(old), "http://old.vitals.test:%d", g_port);
    int connection = sceHttpCreateConnectionWithURL(template_, old, 1);
    CHECK(connection > 0);
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(old, "/hello"), NULL, &status, body, sizeof(body), NULL), 11);
    CHECK(strcmp(body, "hello world") == 0);
    sceHttpDeleteConnection(connection);
    connection = sceHttpCreateConnection(template_, "OLD.vitals.test", "http", (unsigned short)g_port, 1);
    int request = sceHttpCreateRequest(connection, SCE_HTTP_METHOD_GET, "/hello", 0);
    CHECK_EQ(sceHttpSendRequest(request, NULL, 0), 0);
    CHECK_EQ(read_all(request, body, sizeof(body), 64), 11);
    sceHttpDeleteConnection(connection);
    /* A request with a URL on a connection to the real server */
    connection = sceHttpCreateConnectionWithURL(template_, g_base, 1);
    CHECK_EQ(fetch(connection, SCE_HTTP_METHOD_GET, url(old, "/hello"), NULL, &status, body, sizeof(body), NULL), 11);
    sceHttpDeleteConnection(connection);
    /* A redirected host gets at least VH_REDIRECT_RECV_TIMEOUT_US to answer: /slow takes 5 s */
    connection = sceHttpCreateConnectionWithURL(template_, old, 1);
    CHECK_EQ(sceHttpSetRecvTimeOut(connection, 2000000), 0);
    request = sceHttpCreateRequestWithURL(connection, SCE_HTTP_METHOD_GET, url(old, "/slow"), 0);
    CHECK_EQ(sceHttpSendRequest(request, NULL, 0), 0);
    CHECK_EQ(read_all(request, body, sizeof(body), 64), 4);
    sceHttpDeleteConnection(connection);
}

static void test_uri(void)
{
    char out[256];
    unsigned int need;
    printf("URI functions\n");
    CHECK_EQ(sceHttpUriEscape(out, &need, sizeof(out), "a b/c"), 0);
    CHECK(strcmp(out, "a%20b%2Fc") == 0);
    CHECK_EQ(sceHttpUriUnescape(out, &need, sizeof(out), "a%20b%2fc%zz"), 0);
    CHECK(strcmp(out, "a b/c%zz") == 0);
    CHECK_EQ(sceHttpUriMerge(out, "http://h/a/b/c?q", "../d", &need, sizeof(out), 0), 0);
    CHECK(strcmp(out, "http://h/a/d") == 0);
    CHECK_EQ(sceHttpUriSweepPath(out, "/a/./b/../c", 12), 0);
    CHECK(strcmp(out, "/a/c") == 0);
}

int main(int argc, char **argv)
{
    if (argc < 9)
        return 2;
    g_port = atoi(argv[1]);
    g_cert_path = argv[2];
    vh_test_ca_path = argv[3];
    g_client_cert_path = argv[4];
    g_client_key_path = argv[5];
    g_hello_path = argv[6];
    vh_test_redirects_path = argv[7];
    snprintf(g_base, sizeof(g_base), "http://127.0.0.1:%d", g_port);
    snprintf(g_secure_base, sizeof(g_secure_base), "https://127.0.0.1:%d", g_port + 1);

    CHECK_EQ(sceHttpCreateTemplate("x", SCE_HTTP_VERSION_1_1, 0), SCE_HTTP_ERROR_BEFORE_INIT);
    CHECK_EQ(sceHttpInit(1024 * 1024), 0);
    CHECK_EQ(sceHttpInit(1024 * 1024), SCE_HTTP_ERROR_ALREADY_INITED);
    int template_ = sceHttpCreateTemplate("vh-test", SCE_HTTP_VERSION_1_1, 0);
    CHECK(template_ > 0);

    test_uri();
    test_parse_header();
    test_record_scan();
    test_user_agent();
    test_header_order();
    test_raw_and_all_headers();
    test_basic(template_);
    test_keep_alive(template_);
    test_bodies(template_);
    test_redirects_and_post(template_);
    test_cookies(template_);
    test_auth(template_);
    test_abort_and_errors(template_);
    test_https(template_);
    test_nonblocking(template_);
    test_client_certificate(template_);
    test_private(template_);
    test_proxy();
    test_console_profile(template_);
    test_host_redirects(template_);

    /* Everything deleted, nothing left in the pool (the host redirect list is outside it) */
    CHECK_EQ(sceHttpDeleteTemplate(template_), 0);
    SceHttpMemoryPoolStats stats;
    CHECK_EQ(sceHttpGetMemoryPoolStats(&stats), 0);
    CHECK_EQ(stats.currentInuseSize, 0);
    printf("pool: peak %u of %u bytes\n", stats.maxInuseSize, stats.poolSize);
    CHECK_EQ(sceHttpTerm(), 0);

    /* ux0:data/vitals/useragent.txt, read on the next sceHttpInit */
    printf("user agent file\n");
    vh_test_useragent_path = argv[8];
    CHECK_EQ(sceHttpInit(1024 * 1024), 0);
    CHECK(strstr(user_agent_of("Game/2.0"), "User-Agent: Game/2.0 Custom/1.0 (Test)\r\n") != NULL);
    CHECK(strstr(user_agent_of(NULL), "User-Agent: Custom/1.0 (Test)\r\n") != NULL);
    /* An empty agent still gets the space, as Sony's */
    CHECK(strstr(user_agent_of(""), "User-Agent:  Custom/1.0 (Test)\r\n") != NULL);
    CHECK_EQ(sceHttpTerm(), 0);

    /* A template costs what a template needs: the shell's Commerce2 makes over twenty in its pool,
     * and the PS Store fails when one doesn't fit */
    printf("small pool, many templates\n");
    CHECK_EQ(sceHttpInit(32 * 1024), 0);
    int templates[24];
    for (int i = 0; i < 24; ++i) {
        templates[i] = sceHttpCreateTemplate("commerce2/1.0", SCE_HTTP_VERSION_1_1, 0);
        CHECK(templates[i] > 0);
    }
    int small_connection = sceHttpCreateConnection(templates[0], "example.com", "https", 443, 1);
    CHECK(small_connection > 0);
    CHECK(sceHttpCreateRequest(small_connection, SCE_HTTP_METHOD_GET, "/", 0) > 0);
    for (int i = 0; i < 24; ++i)
        CHECK_EQ(sceHttpDeleteTemplate(templates[i]), 0);
    CHECK_EQ(sceHttpGetMemoryPoolStats(&stats), 0);
    CHECK_EQ(stats.currentInuseSize, 0);
    CHECK_EQ(sceHttpTerm(), 0);

    printf("%d checks, %d failed\n", g_checks, g_failures);
    return g_failures != 0;
}
