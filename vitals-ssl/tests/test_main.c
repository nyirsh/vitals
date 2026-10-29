#include "vs.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* vitals-ssl's connection functions, called as Sony's libhttp calls them, against tests/server.py:
 * test_main <port> <server certificate> <unrelated root> */

extern char vs_test_ca_path[512];
extern unsigned int vs_test_refused_pool;

static int g_checks, g_failures;
static int g_port;
static const char *g_server_pem, *g_other_root;

#define CHECK(condition)                                                                       \
    do {                                                                                       \
        ++g_checks;                                                                            \
        if (!(condition)) {                                                                    \
            ++g_failures;                                                                      \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition);                    \
        }                                                                                      \
    } while (0)

/* Every value compared is 32 bits: SCE error codes, sizes, options */
#define CHECK_EQ(actual, expected)                                                             \
    do {                                                                                       \
        uint32_t got_ = (uint32_t)(actual), want_ = (uint32_t)(expected);                      \
        ++g_checks;                                                                            \
        if (got_ != want_) {                                                                   \
            ++g_failures;                                                                      \
            fprintf(stderr, "%s:%d: %s is %08X, not %08X\n", __FILE__, __LINE__, #actual,      \
                    (unsigned int)got_, (unsigned int)want_);                                  \
        }                                                                                      \
    } while (0)

static int connect_to(int port, int receive_timeout_ms)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons((unsigned short)port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        perror("connect");
        exit(2);
    }
    if (receive_timeout_ms > 0) {
        struct timeval timeout = {receive_timeout_ms / 1000, (receive_timeout_ms % 1000) * 1000};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    }
    return fd;
}

typedef struct Connection {
    void *context;
    void *ssl;
    int fd;
} Connection;

static int g_alerts, g_last_alert;

static void info_callback(const void *ssl, int where, int value)
{
    (void)ssl;
    if (where & VS_CB_ALERT) {
        ++g_alerts;
        g_last_alert = value;
    }
}

/* As libhttp's setup (0x81008130): a context and a connection, the socket BIO with the host name */
static Connection open_connection(int port, const char *host, int verify, int timeout_ms)
{
    Connection connection = {0};
    void *library = NULL;
    CHECK_EQ(sceSslInternalIsInitalized(), 0);
    CHECK_EQ(sceSslInternalGetLibrary(&library), 0);
    connection.context = sceSslInternalCtxNew(library, sceSslInternalClientMethod());
    CHECK(connection.context != NULL);
    unsigned char seed[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    CHECK_EQ(sceSslInternalCtxSeedRandom(connection.context, seed, sizeof(seed)), 0);
    CHECK_EQ(sceSslInternalCtxSetOptions(connection.context, 0x20001FFBu), 0x20001FFBu);
    sceSslInternalCtxSetVerify(connection.context, verify);
    CHECK_EQ(sceSslInternalCtxCtrl(connection.context, VS_CTRL_SET_SESS_CACHE_MODE, 0, NULL), 0);
    connection.ssl = sceSslInternalNew(connection.context);
    CHECK(connection.ssl != NULL);
    CHECK_EQ(sceSslInternalSetOptions(connection.ssl, 0x40000), 0x40000);
    connection.fd = connect_to(port, timeout_ms);
    void *bio = sceSslInternalBioNewSocket(connection.fd, 0);
    CHECK(bio != NULL);
    CHECK_EQ(sceSslInternalBioCtrl(bio, VS_BIO_CTRL_SET_HOST, 0, (void *)host), 1);
    sceSslInternalSetBio(connection.ssl, bio, bio);
    sceSslInternalSetInfoCallback(connection.ssl, info_callback);
    sceSslInternalSetConnectState(connection.ssl);
    return connection;
}

static void close_connection(Connection *connection)
{
    (void)sceSslInternalShutdown(connection->ssl);
    sceSslInternalFree(connection->ssl);
    sceSslInternalCtxFree(connection->context);
    /* BIO_NOCLOSE: the socket is still the caller's */
    CHECK_EQ(close(connection->fd), 0);
}

/* Reads up to a newline */
static int read_line(void *ssl, char *line, int size)
{
    int length = 0;
    while (length < size - 1) {
        int result = sceSslInternalRead(ssl, line + length, 1);
        if (result <= 0)
            return result;
        if (line[length++] == '\n')
            break;
    }
    line[length] = '\0';
    return length;
}

static void write_text(void *ssl, const char *text)
{
    CHECK_EQ(sceSslInternalWrite(ssl, text, (int)strlen(text)), strlen(text));
}

static void test_init(void)
{
    SceSslMemoryPoolStats stats;
    void *library = NULL;
    CHECK_EQ(sceSslTerm(), VS_ERROR_BEFORE_INIT);
    CHECK_EQ(sceSslInternalIsInitalized(), VS_ERROR_BEFORE_INIT);
    CHECK_EQ(sceSslInternalGetLibrary(&library), VS_ERROR_BEFORE_INIT);
    CHECK_EQ(sceSslGetMemoryPoolStats(&stats), VS_ERROR_BEFORE_INIT);
    CHECK_EQ(sceSslInit(0), VS_ERROR_INVALID_VALUE);
    vs_test_refused_pool = 12345;
    CHECK_EQ(sceSslInit(12345), 0x80022001);
    CHECK_EQ(sceSslInternalIsInitalized(), VS_ERROR_BEFORE_INIT);
    CHECK_EQ(sceSslInit(256 * 1024), 0);
    CHECK_EQ(sceSslInit(256 * 1024), VS_ERROR_ALREADY_INITED);
    CHECK_EQ(sceSslInternalIsInitalized(), 0);
    CHECK_EQ(sceSslGetMemoryPoolStats(NULL), VS_ERROR_INVALID_VALUE);
    stats.reserved = 77;
    CHECK_EQ(sceSslGetMemoryPoolStats(&stats), 0);
    CHECK_EQ(stats.poolSize, 256 * 1024);
    CHECK_EQ(stats.reserved, 77);
    CHECK_EQ(sceSslInternalGetLibrary(NULL), VS_ERROR_INVALID_VALUE);
    CHECK_EQ(sceSslInternalGetLibrary(&library), 0);
    CHECK(library != NULL);
    CHECK_EQ(sceSslTerm(), 0);
    CHECK_EQ(sceSslInternalIsInitalized(), VS_ERROR_BEFORE_INIT);
    CHECK(sceSslInternalCtxNew(library, sceSslInternalClientMethod()) == NULL);
    CHECK_EQ(sceSslInit(256 * 1024), 0);
}

static void test_error_codes(void)
{
    CHECK_EQ(sceSslInternalErrorCode(0, 0), 0);
    CHECK_EQ(sceSslInternalErrorCode(0, 10001), 0x80435201);
    CHECK_EQ(sceSslInternalErrorCode(0, 10004), 0x80435204);
    CHECK_EQ(sceSslInternalErrorCode(0, 10005), VS_ERROR_OUT_OF_MEMORY);
    CHECK_EQ(sceSslInternalErrorCode(0, 10008), 0x80435208);
    CHECK_EQ(sceSslInternalErrorCode(0, 10023), 0x80435217);
    CHECK_EQ(sceSslInternalErrorCode(0, 10024), VS_ERROR_UNKNOWN_REASON);
    CHECK_EQ(sceSslInternalErrorCode(0, 10026), 0x8043521A);
    CHECK_EQ(sceSslInternalErrorCode(0, 10027), VS_ERROR_UNKNOWN_REASON);
    CHECK_EQ(sceSslInternalErrorCode(0, 10028), 0x8043521C);
    CHECK_EQ(sceSslInternalErrorCode(0, 10037), 0x80435225);
    CHECK_EQ(sceSslInternalErrorCode(0, 10038), VS_ERROR_UNKNOWN_REASON);
    CHECK_EQ(sceSslInternalErrorCode(0, 32), VS_ERROR_UNKNOWN_REASON);
    CHECK_EQ(sceSslInternalErrorCode(1, (int)0x80431075), 0x80431075);
    vs_note_out_of_memory();
    CHECK_EQ(sceSslInternalErrorCode(1, (int)0x80431075), VS_ERROR_OUT_OF_MEMORY);
    CHECK_EQ(sceSslInternalErrorCode(1, (int)0x80431075), 0x80431075);
    CHECK_EQ(sceSslInternalErrorCode(2, 0), VS_ERROR_INVALID_VALUE);
}

static void test_objects(void)
{
    void *library = NULL;
    CHECK_EQ(sceSslInternalGetLibrary(&library), 0);
    CHECK(sceSslInternalClientMethod() != sceSslInternalClientMethod2());
    CHECK(sceSslInternalCtxNew(NULL, sceSslInternalClientMethod()) == NULL);
    CHECK(sceSslInternalCtxNew(library, NULL) == NULL);
    void *context = sceSslInternalCtxNew(library, sceSslInternalClientMethod2());
    CHECK(context != NULL);
    CHECK_EQ(sceSslInternalCtxSeedRandom(context, NULL, 8), 32);
    CHECK_EQ(sceSslInternalCtxSeedRandom(context, "x", 0), 32);
    CHECK_EQ(sceSslInternalCtxSetOptions(context, 1), 1);
    CHECK_EQ(sceSslInternalCtxSetOptions(context, 4), 5);
    CHECK_EQ(sceSslInternalCtxCtrl(context, VS_CTRL_SET_SESS_CACHE_MODE, 3, NULL), 0);
    CHECK_EQ(sceSslInternalCtxCtrl(context, VS_CTRL_SET_SESS_CACHE_MODE, 0, NULL), 3);
    CHECK_EQ(sceSslInternalCtxCtrl(context, VS_CTRL_GET_SESS_CACHE_MODE, 0, NULL), 0);
    void *ssl = sceSslInternalNew(context);
    CHECK(ssl != NULL);
    CHECK(sceSslInternalNew(NULL) == NULL);
    /* The connection keeps the context until it's freed */
    sceSslInternalCtxFree(context);
    CHECK_EQ(sceSslInternalSetOptions(ssl, 2), 2);
    CHECK_EQ(sceSslInternalGetError(ssl, 1), VS_KIND_NONE);
    sceSslInternalFree(ssl);
    sceSslInternalFree(NULL);
    sceSslInternalCtxFree(NULL);

    void *bio = sceSslInternalBioNewSocket(42, 0);
    const char *host = NULL;
    int fd = 0;
    CHECK_EQ(sceSslInternalBioCtrl(NULL, VS_BIO_CTRL_SET_HOST, 0, "x"), 0);
    CHECK_EQ(sceSslInternalBioCtrl(bio, VS_BIO_C_GET_FD, 0, &fd), 42);
    CHECK_EQ(fd, 42);
    CHECK_EQ(sceSslInternalBioCtrl(bio, VS_BIO_CTRL_SET_HOST, 0, "example.com"), 1);
    CHECK_EQ(sceSslInternalBioCtrl(bio, VS_BIO_CTRL_GET_HOST, 0, &host), 1);
    CHECK(host != NULL && strcmp(host, "example.com") == 0);
    CHECK_EQ(sceSslInternalBioCtrl(bio, VS_BIO_CTRL_GET_CLOSE, 0, NULL), 0);
    CHECK_EQ(sceSslInternalBioCtrl(bio, 999, 0, NULL), 0);
    /* A BIO is freed with the connection that has it */
    context = sceSslInternalCtxNew(library, sceSslInternalClientMethod());
    ssl = sceSslInternalNew(context);
    sceSslInternalSetBio(ssl, bio, bio);
    sceSslInternalFree(ssl);
    sceSslInternalCtxFree(context);
}

/* A connection libhttp would make without checking the server: write, read, then the server's
 * close_notify ends it (6) */
static void test_echo(void)
{
    char line[128];
    Connection connection = open_connection(g_port, "vitals-ssl.test", 0, 5000);
    CHECK_EQ(sceSslInternalConnect(connection.ssl), 1);
    CHECK_EQ(sceSslInternalGetError(connection.ssl, 1), VS_KIND_NONE);
    CHECK(read_line(connection.ssl, line, sizeof(line)) > 0);
    CHECK(strcmp(line, "sni=vitals-ssl.test\n") == 0);
    write_text(connection.ssl, "hello\n");
    CHECK(read_line(connection.ssl, line, sizeof(line)) > 0);
    CHECK(strcmp(line, "hello\n") == 0);
    /* More than one record each way */
    static char big[40000], back[40001];
    for (size_t i = 0; i < sizeof(big) - 1; ++i)
        big[i] = (char)('a' + i % 26);
    big[sizeof(big) - 1] = '\n';
    CHECK_EQ(sceSslInternalWrite(connection.ssl, big, sizeof(big)), sizeof(big));
    int got = 0;
    while (got < (int)sizeof(big)) {
        int result = sceSslInternalRead(connection.ssl, back + got, 1500);
        if (result <= 0)
            break;
        got += result;
    }
    CHECK_EQ(got, sizeof(big));
    CHECK(memcmp(big, back, sizeof(big)) == 0);
    write_text(connection.ssl, "quit\n");
    CHECK(read_line(connection.ssl, line, sizeof(line)) > 0);
    CHECK(strcmp(line, "bye\n") == 0);
    int result = sceSslInternalRead(connection.ssl, line, sizeof(line));
    CHECK_EQ(result, 0);
    CHECK_EQ(sceSslInternalGetError(connection.ssl, result), VS_KIND_ZERO_RETURN);
    CHECK_EQ(sceSslInternalShutdown(connection.ssl), 1);
    close_connection(&connection);
}

/* The server closes the socket without close_notify: 0, and a system error (5) */
static void test_drop(void)
{
    char line[128];
    Connection connection = open_connection(g_port, "vitals-ssl.test", 0, 5000);
    CHECK(read_line(connection.ssl, line, sizeof(line)) > 0);
    write_text(connection.ssl, "drop\n");
    CHECK(read_line(connection.ssl, line, sizeof(line)) > 0);
    int result = sceSslInternalRead(connection.ssl, line, sizeof(line));
    CHECK(result <= 0);
    CHECK_EQ(sceSslInternalGetError(connection.ssl, result), result == 0 ? VS_KIND_SYSCALL : VS_KIND_WANT_READ);
    CHECK_EQ(sceSslInternalShutdown(connection.ssl), 0);
    close_connection(&connection);
}

/* A server that never answers: the receive's timeout comes back as SceNet's EAGAIN, which is how
 * libhttp sees it, and SSL_get_error says to read again (2) */
static void test_timeout(void)
{
    Connection connection = open_connection(g_port + 1, "vitals-ssl.test", 0, 300);
    int result = sceSslInternalConnect(connection.ssl);
    CHECK_EQ(result, VS_NET_ERROR_EAGAIN);
    CHECK_EQ(sceSslInternalGetError(connection.ssl, result), VS_KIND_WANT_READ);
    close_connection(&connection);
}

/* No SNI for an address, as Sony's; the certificate still names it */
static void test_address(void)
{
    char line[128];
    vs_test_ca_path[0] = '\0';
    snprintf(vs_test_ca_path, sizeof(vs_test_ca_path), "%s", g_server_pem);
    Connection connection = open_connection(g_port, "127.0.0.1", 1, 5000);
    CHECK_EQ(sceSslInternalConnect(connection.ssl), 1);
    CHECK(read_line(connection.ssl, line, sizeof(line)) > 0);
    CHECK(strcmp(line, "sni=-\n") == 0);
    close_connection(&connection);
    /* An address the certificate doesn't name: refused */
    connection = open_connection(g_port, "127.0.0.2", 1, 5000);
    int result = sceSslInternalConnect(connection.ssl);
    CHECK_EQ(result, -1);
    CHECK_EQ(sceSslInternalGetError(connection.ssl, result), VS_KIND_SSL);
    close_connection(&connection);
}

/* With the verify mode on, the server is checked against the CA bundle and the host name */
static void test_verify(void)
{
    char line[128];
    /* The server's own certificate in the bundle: trusted */
    snprintf(vs_test_ca_path, sizeof(vs_test_ca_path), "%s", g_server_pem);
    Connection connection = open_connection(g_port, "vitals-ssl.test", 1, 5000);
    CHECK_EQ(sceSslInternalConnect(connection.ssl), 1);
    CHECK(read_line(connection.ssl, line, sizeof(line)) > 0);
    close_connection(&connection);
    /* Another name: refused, a TLS failure (1) */
    connection = open_connection(g_port, "other.test", 1, 5000);
    int result = sceSslInternalConnect(connection.ssl);
    CHECK_EQ(result, -1);
    CHECK_EQ(sceSslInternalGetError(connection.ssl, result), VS_KIND_SSL);
    close_connection(&connection);

    /* A bundle without it (read again on the next sceSslInit): refused */
    CHECK_EQ(sceSslTerm(), 0);
    snprintf(vs_test_ca_path, sizeof(vs_test_ca_path), "%s", g_other_root);
    CHECK_EQ(sceSslInit(256 * 1024), 0);
    connection = open_connection(g_port, "vitals-ssl.test", 1, 5000);
    result = sceSslInternalConnect(connection.ssl);
    CHECK_EQ(result, -1);
    CHECK_EQ(sceSslInternalGetError(connection.ssl, result), VS_KIND_SSL);
    close_connection(&connection);
    /* Without the verify mode it connects */
    connection = open_connection(g_port, "vitals-ssl.test", 0, 5000);
    CHECK_EQ(sceSslInternalConnect(connection.ssl), 1);
    close_connection(&connection);
}

/* SSL_read connects first, as OpenSSL's */
static void test_implicit_connect(void)
{
    char line[128];
    Connection connection = open_connection(g_port, "vitals-ssl.test", 0, 5000);
    CHECK(read_line(connection.ssl, line, sizeof(line)) > 0);
    CHECK(strncmp(line, "sni=", 4) == 0);
    close_connection(&connection);
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s <port> <server certificate> <unrelated root>\n", argv[0]);
        return 2;
    }
    g_port = atoi(argv[1]);
    g_server_pem = argv[2];
    g_other_root = argv[3];
    test_init();
    test_error_codes();
    test_objects();
    test_echo();
    test_drop();
    test_timeout();
    test_implicit_connect();
    test_address();
    test_verify();
    CHECK_EQ(sceSslTerm(), 0);
    (void)g_alerts;
    (void)g_last_alert;
    printf("%d checks, %d failed\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
