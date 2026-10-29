#include "vs.h"

#include <mbedtls/x509_crt.h>

#include <arpa/inet.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* vitals-ssl's connection functions, called as Sony's libhttp calls them, against tests/server.py:
 * test_main <port> <server certificate> <unrelated root> <CA-signed chain> <bundle with the CA> */

extern char vs_test_ca_path[512];
extern unsigned int vs_test_refused_pool;

static int g_checks, g_failures;
static int g_port;
static const char *g_server_pem, *g_other_root, *g_chain_pem, *g_bundle;
static const char *g_client_pem, *g_client_key, *g_stranger_pem, *g_stranger_key;

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

/* 91C2531C's entry request */
typedef struct VsEntryRequestForTests {
    int index;
    void *entry;
} VsEntryRequestForTests;

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

/* ---- certificates ---- */

/* The chain's PEM file, and its certificates (leaf, CA) as Mbed TLS parses it: while vitals-ssl is
 * initialized, as Mbed TLS's RSA keys take mutexes from it */
static unsigned char g_chain_text[16384];
static size_t g_chain_length;
static mbedtls_x509_crt g_chain;

static void load_chain(void)
{
    mbedtls_x509_crt_init(&g_chain);
    CHECK_EQ(mbedtls_x509_crt_parse(&g_chain, g_chain_text, g_chain_length + 1), 0);
    CHECK(g_chain.next != NULL);
}

static void *parse_der(const mbedtls_x509_crt *crt)
{
    void *cert = NULL;
    unsigned int consumed = 0;
    CHECK_EQ(sceSslInternalCertFromBinary(vs_cert_library(), 0, 1, (unsigned int)crt->raw.len, crt->raw.p,
                                          &consumed, &cert), 0);
    CHECK_EQ(consumed, crt->raw.len);
    return cert;
}

/* A name's first entry's attribute as dotted text and its value, as libhttp's host check reads them */
static void first_entry(void *name, char *oid_text, char *value, size_t size)
{
    VsEntryRequestForTests request = {0, NULL};
    CHECK_EQ(sceSslInternalNameInfo(name, 11, &request), 0);
    struct { int tag; unsigned int length; const unsigned char *data; } item;
    CHECK_EQ(sceSslInternalEntryInfo(request.entry, 1, &item), 0);
    uint64_t oid[4]; /* 16 bytes on the Vita, more with 64-bit pointers */
    CHECK_EQ(sceSslInternalOidSet(oid, 1, item.data, item.length), 0);
    CHECK_EQ(sceSslInternalOidText(oid, 0, 24, oid_text), 0);
    CHECK_EQ(sceSslInternalEntryInfo(request.entry, 2, &item), 0);
    CHECK(item.length < size);
    memcpy(value, item.data, item.length);
    value[item.length] = '\0';
    CHECK_EQ(sceSslInternalEntryFree(request.entry), 0);
}

static void test_certificate_objects(void)
{
    load_chain();
    const mbedtls_x509_crt *leaf_crt = &g_chain, *ca_crt = g_chain.next;
    void *leaf = parse_der(leaf_crt), *ca = parse_der(ca_crt), *other = NULL;
    unsigned int consumed = 0;
    static const unsigned char junk[] = {0x30, 0x03, 0x02, 0x01, 0x01};
    CHECK_EQ(sceSslInternalCertFromBinary(NULL, 0, 1, sizeof(junk), junk, &consumed, &other), 10001);
    CHECK(other == NULL);
    CHECK_EQ(sceSslInternalCertFromBinary(NULL, 0, 1, 0, NULL, &consumed, &other), 10017);

    /* Serial number and DER */
    struct { unsigned int length; const unsigned char *data; } item = {0, NULL};
    CHECK_EQ(sceSslInternalCertInfo(leaf, 2, &item), 0);
    CHECK_EQ(item.length, leaf_crt->serial.len);
    CHECK(item.data != NULL && memcmp(item.data, leaf_crt->serial.p, item.length) == 0);
    unsigned int length = 0;
    CHECK_EQ(sceSslInternalCertToBinary(leaf, 4, 0, NULL, &length), 0);
    CHECK_EQ(length, leaf_crt->raw.len);
    unsigned char *der = malloc(length);
    CHECK_EQ(sceSslInternalCertToBinary(leaf, 4, length - 1, der, &length), 10006);
    CHECK_EQ(sceSslInternalCertToBinary(leaf, 4, length, der, &length), 0);
    CHECK(memcmp(der, leaf_crt->raw.p, length) == 0);
    free(der);
    CHECK_EQ(sceSslInternalCertInfo(leaf, 0x1234, &item), 10011);
    CHECK_EQ(sceSslInternalCertInfo(NULL, 2, &item), 10017);

    /* Names: the leaf's issuer is the CA's subject */
    void *issuer = NULL, *subject = NULL, *ca_subject = NULL;
    CHECK_EQ(sceSslInternalCertIssuer(leaf, 1, &issuer), 0);
    CHECK_EQ(sceSslInternalCertSubject(leaf, 1, &subject), 0);
    CHECK_EQ(sceSslInternalCertInfo(ca, 0x800B, &ca_subject), 0);
    CHECK_EQ(sceSslInternalNameEqual(issuer, ca_subject), 1);
    CHECK_EQ(sceSslInternalNameEqual(issuer, subject), 0);
    CHECK_EQ(sceSslInternalNameEqual(issuer, NULL), 0);
    int count = 0;
    CHECK_EQ(sceSslInternalNameInfo(subject, 10, &count), 0);
    CHECK_EQ(count, 1);
    CHECK_EQ(sceSslInternalNameInfo(issuer, 10, &count), 0);
    CHECK_EQ(count, 2);
    char oid_text[24], value[64];
    first_entry(subject, oid_text, value, sizeof(value));
    CHECK(strcmp(oid_text, "2.5.4.3") == 0);
    CHECK(strcmp(value, "chain.test") == 0);
    first_entry(issuer, oid_text, value, sizeof(value));
    CHECK(strcmp(oid_text, "2.5.4.10") == 0);
    CHECK(strcmp(value, "vitals-ssl") == 0);
    VsEntryRequestForTests request = {5, NULL};
    CHECK_EQ(sceSslInternalNameInfo(subject, 11, &request), 10008);
    CHECK_EQ(sceSslInternalNameInfo(subject, 12, &count), 10011);
    uint64_t oid[4]; /* 16 bytes on the Vita, more with 64-bit pointers */
    char small[4];
    static const unsigned char cn[] = {0x55, 0x04, 0x03};
    CHECK_EQ(sceSslInternalOidSet(oid, 1, cn, sizeof(cn)), 0);
    CHECK_EQ(sceSslInternalOidText(oid, 0, sizeof(small), small), 10006);
    CHECK_EQ(sceSslInternalNameFree(issuer), 0);
    CHECK_EQ(sceSslInternalNameFree(subject), 0);
    CHECK_EQ(sceSslInternalNameFree(ca_subject), 0);
    CHECK_EQ(sceSslInternalNameFree(NULL), 10017);

    /* Extensions: subjectAltName's value, as libhttp parses it; basicConstraints */
    void *extension = NULL;
    CHECK_EQ(sceSslInternalExtensionNew(vs_cert_library(), -1, &extension), 0);
    CHECK_EQ(sceSslInternalCertInfo(leaf, 0x4003, extension), 0);
    CHECK_EQ(sceSslInternalExtensionInfo(extension, 0x8002, &item), 0);
    static const unsigned char names[] = {0x30, 0x0C, 0x82, 0x0A, 'c', 'h', 'a', 'i', 'n', '.', 't', 'e', 's', 't'};
    CHECK_EQ(item.length, sizeof(names));
    CHECK(item.data != NULL && memcmp(item.data, names, sizeof(names)) == 0);
    CHECK_EQ(sceSslInternalExtensionInfo(extension, 0x8007, &count), 10011);
    CHECK_EQ(sceSslInternalCertInfo(ca, 0x4003, extension), 10008);
    CHECK_EQ(sceSslInternalExtensionInfo(extension, 0x8002, &item), 10008);
    int critical = 0, is_ca = -1, path_length = 0;
    CHECK_EQ(sceSslInternalCertInfo(ca, 0x4005, extension), 0);
    CHECK_EQ(sceSslInternalExtensionInfo(extension, 0x8001, &critical), 0);
    CHECK_EQ(critical, 1);
    CHECK_EQ(sceSslInternalExtensionInfo(extension, 0x8007, &is_ca), 0);
    CHECK_EQ(is_ca, 1);
    CHECK_EQ(sceSslInternalExtensionInfo(extension, 0x8008, &path_length), 0);
    CHECK_EQ(path_length, INT_MAX);
    CHECK_EQ(sceSslInternalCertInfo(leaf, 0x4005, extension), 0);
    CHECK_EQ(sceSslInternalExtensionInfo(extension, 0x8007, &is_ca), 0);
    CHECK_EQ(is_ca, 0);
    CHECK_EQ(sceSslInternalExtensionFree(extension), 0);
    int signature = 0;
    CHECK_EQ(sceSslInternalCertInfo(leaf, 0x8007, &signature), 0);
    CHECK(signature != 7 && signature != 8);

    /* Keys and signatures: the CA's key made the leaf's, the leaf's didn't */
    void *ca_key = NULL, *leaf_key = NULL;
    int valid = -1;
    CHECK_EQ(sceSslInternalCertInfo(ca, 0x8009, &ca_key), 0);
    CHECK_EQ(sceSslInternalCertPublicKey(leaf, 1, &leaf_key), 0);
    CHECK_EQ(sceSslInternalCertVerifySignature(leaf, ca_key, &valid), 0);
    CHECK_EQ(valid, 1);
    CHECK_EQ(sceSslInternalCertVerifySignature(ca, ca_key, &valid), 0);
    CHECK_EQ(valid, 1);
    CHECK_EQ(sceSslInternalCertVerifySignature(leaf, leaf_key, &valid), 0);
    CHECK_EQ(valid, 0);
    CHECK_EQ(sceSslInternalCertVerifySignature(leaf, NULL, &valid), 10017);
    CHECK_EQ(sceSslInternalKeyFree(ca_key), 0);
    CHECK_EQ(sceSslInternalKeyFree(leaf_key), 0);

    /* Times: now is between the leaf's dates, as libhttp's date checks compare them */
    void *provider = NULL, *now = NULL, *date = NULL;
    unsigned char clock[12], value8[8];
    int order = 2;
    CHECK_EQ(sceSslInternalTimeProvider(vs_cert_library(), 0, &provider), 0);
    CHECK_EQ(sceSslInternalTimeNew(provider, &now), 0);
    CHECK_EQ(sceSslInternalTimeNew(provider, &date), 0);
    CHECK_EQ(sceSslInternalTimeNow(clock), 0);
    CHECK_EQ(sceSslInternalTimeExport(clock, 3, value8, 7), 10006);
    CHECK_EQ(sceSslInternalTimeExport(clock, 3, value8, 8), 0);
    CHECK_EQ(sceSslInternalTimeImport(now, 3, value8, 8), 0);
    CHECK_EQ(sceSslInternalCertNotAfter(leaf, date), 0);
    CHECK_EQ(sceSslInternalTimeCompare(date, now, &order), 0);
    CHECK_EQ(order, 1);
    /* Made within the second, so notBefore can be now */
    CHECK_EQ(sceSslInternalCertNotBefore(leaf, date), 0);
    CHECK_EQ(sceSslInternalTimeCompare(date, now, &order), 0);
    CHECK(order == -1 || order == 0);
    CHECK_EQ(sceSslInternalTimeCompare(now, date, &order), 0);
    CHECK(order == 1 || order == 0);
    CHECK_EQ(sceSslInternalTimeCompare(date, date, &order), 0);
    CHECK_EQ(order, 0);
    char text[20];
    unsigned int text_length = 0;
    int64_t known = 951782400 + 3723; /* 2000-02-29 01:02:03 */
    CHECK_EQ(sceSslInternalTimeImport(date, 3, &known, 8), 0);
    CHECK_EQ(sceSslInternalTimeText(date, 6, text, &text_length, 20), 0);
    CHECK_EQ(text_length, 15);
    CHECK(strcmp(text, "20000229010203Z") == 0);
    CHECK_EQ(sceSslInternalTimeText(date, 6, text, &text_length, 15), 10006);
    CHECK_EQ(sceSslInternalTimeFree(now), 0);
    CHECK_EQ(sceSslInternalTimeFree(date), 0);
    CHECK_EQ(sceSslInternalTimeProviderFree(provider), 0);

    /* SceSsl's getters on the same certificate */
    const char *serial = NULL;
    unsigned serial_length = 0;
    CHECK_EQ(sceSslGetSerialNumber(leaf, &serial, &serial_length), 0);
    CHECK_EQ(serial_length, leaf_crt->serial.len);
    SceRtcTick before = {0}, after = {0};
    CHECK_EQ(sceSslGetNotBefore(leaf, &before), 0);
    CHECK_EQ(sceSslGetNotAfter(leaf, &after), 0);
    /* Two days apart, in microseconds since year 1 */
    CHECK(after.tick - before.tick == 2ull * 86400 * 1000000);
    CHECK(before.tick > 62135596800ull * 1000000);
    SceSslCertName *name = sceSslGetIssuerName(leaf);
    CHECK(name != NULL);
    CHECK_EQ(sceSslGetNameEntryCount(name), 2);
    char attribute[24], entry_value[8], small_attribute[7];
    unsigned value_length = 0;
    /* Sony's names, SSLeay's long ones */
    CHECK_EQ(sceSslGetNameEntryInfo(name, 0, attribute, sizeof(attribute), NULL, 0, &value_length), 0);
    CHECK(strcmp(attribute, "organizationName") == 0);
    CHECK_EQ(sceSslGetNameEntryInfo(name, 1, small_attribute, sizeof(small_attribute), NULL, 0, NULL), 0);
    CHECK(strcmp(small_attribute, "common") == 0);
    CHECK_EQ(sceSslGetNameEntryInfo(name, 1, attribute, sizeof(attribute), entry_value, sizeof(entry_value),
                                    &value_length), 0);
    CHECK(strcmp(attribute, "commonName") == 0);
    CHECK(strcmp(entry_value, "vitals-") == 0);
    CHECK_EQ(value_length, strlen("vitals-ssl test CA"));
    CHECK_EQ(sceSslGetNameEntryInfo(name, 2, attribute, sizeof(attribute), entry_value, sizeof(entry_value),
                                    &value_length), SCE_SSL_ERROR_INVALID_VALUE);
    CHECK_EQ(sceSslFreeSslCertName(name), 0);
    CHECK(sceSslGetSubjectName(NULL) == NULL);
    CHECK_EQ(sceSslGetNameEntryCount(NULL), SCE_SSL_ERROR_INVALID_VALUE);

    CHECK_EQ(sceSslInternalCertFree(leaf), 0);
    CHECK_EQ(sceSslInternalCertFree(ca), 0);
    mbedtls_x509_crt_free(&g_chain);
}

/* The CA store on a bundle of the unrelated root and the CA */
static void test_certificate_store(void)
{
    CHECK_EQ(sceSslTerm(), 0);
    snprintf(vs_test_ca_path, sizeof(vs_test_ca_path), "%s", g_bundle);
    CHECK_EQ(sceSslInit(256 * 1024), 0);
    load_chain();
    void *leaf = parse_der(&g_chain), *issuer = NULL;
    CHECK_EQ(sceSslInternalCertIssuer(leaf, 1, &issuer), 0);

    /* By name: the size, then the PEM text, as libhttp's lookup (0x81014292) asks */
    char **entries = NULL;
    unsigned int total = 0;
    CHECK_EQ(sceSslInternalGetCertificateAuthorityByName(issuer, NULL, NULL, 0, &total, 0), 1);
    CHECK(total > 0);
    char *buffer = malloc(total + 15000);
    CHECK_EQ(sceSslInternalGetCertificateAuthorityByName(issuer, &entries, buffer, 10, &total, 0),
             VS_ERROR_INVALID_VALUE);
    CHECK_EQ(sceSslInternalGetCertificateAuthorityByName(issuer, &entries, buffer, total + 15000, &total, 0), 1);
    CHECK(entries != NULL && strncmp(entries[0], "-----BEGIN CERTIFICATE-----\n", 28) == 0);
    mbedtls_x509_crt found;
    mbedtls_x509_crt_init(&found);
    CHECK_EQ(mbedtls_x509_crt_parse(&found, (const unsigned char *)entries[0], strlen(entries[0]) + 1), 0);
    CHECK(found.raw.len == g_chain.next->raw.len &&
          memcmp(found.raw.p, g_chain.next->raw.p, found.raw.len) == 0);
    mbedtls_x509_crt_free(&found);
    /* Asked again, the next root with the name: there's none, so the caller stops */
    CHECK_EQ(sceSslInternalGetCertificateAuthorityByName(issuer, &entries, buffer, total + 15000, &total, 0), 0);
    vs_certificate_lookups_reset();
    CHECK_EQ(sceSslInternalGetCertificateAuthorityByName(issuer, &entries, buffer, total + 15000, &total, 0), 1);
    vs_certificate_lookups_reset();
    void *subject = NULL;
    CHECK_EQ(sceSslInternalCertSubject(leaf, 1, &subject), 0);
    CHECK_EQ(sceSslInternalGetCertificateAuthorityByName(subject, NULL, NULL, 0, &total, 0), 0);
    CHECK_EQ(sceSslInternalNameFree(subject), 0);
    free(buffer);

    /* By number: all, the first of group 1, nothing past the bundle's two */
    CHECK_EQ(sceSslInternalGetCertificateAuthority(0, 0xFFFFFFFFu, NULL, NULL, 0, &total), 2);
    buffer = malloc(total);
    CHECK_EQ(sceSslInternalGetCertificateAuthority(0, 0xFFFFFFFFu, &entries, buffer, total, &total), 2);
    CHECK(strncmp(entries[0], "-----BEGIN CERTIFICATE-----", 27) == 0);
    CHECK(strncmp(entries[1], "-----BEGIN CERTIFICATE-----", 27) == 0);
    CHECK(strstr(entries[0], "-----END CERTIFICATE-----") != NULL);
    free(buffer);
    CHECK_EQ(sceSslInternalGetCertificateAuthority(1, 2, NULL, NULL, 0, &total), 1);
    CHECK_EQ(sceSslInternalGetCertificateAuthority(1, 4, NULL, NULL, 0, &total), 0x80010086);
    CHECK_EQ(sceSslInternalGetCertificateAuthority(2, 1, NULL, NULL, 0, &total), 0x80010086);
    const void *revoked = &total;
    unsigned int revoked_count = 9;
    CHECK_EQ(sceSslInternalCaRevoked(5, 4, &revoked, &revoked_count), 0);
    CHECK(revoked == NULL && revoked_count == 0);

    CHECK_EQ(sceSslInternalNameFree(issuer), 0);
    CHECK_EQ(sceSslInternalCertFree(leaf), 0);
    mbedtls_x509_crt_free(&g_chain);
}

/* A verify callback as libhttp's does the chain part: the issuer from the CA store by name, its key
 * over the server certificate's signature */
static int g_callback_calls, g_callback_count, g_callback_refuse;
/* As libhttp's argument starts: the flags, then the host name */
static const void *g_check_argument[2] = {(const void *)0x65, "chain.test"};

static int check_chain(void *ssl, void *certificates[], int count, void *argument, int *reason)
{
    ++g_callback_calls;
    g_callback_count = count;
    const void *library = NULL;
    CHECK_EQ(sceSslInternalGetItem(ssl, 1, &library), 0);
    CHECK(library != NULL && argument == g_check_argument);
    if (g_callback_refuse) {
        *reason = 4;
        return 0;
    }
    void *issuer = NULL, *found = NULL, *key = NULL;
    char **entries = NULL;
    unsigned int total = 0;
    int valid = 0;
    CHECK_EQ(sceSslInternalCertIssuer(certificates[0], 1, &issuer), 0);
    if (sceSslInternalGetCertificateAuthorityByName(issuer, NULL, NULL, 0, &total, 0) == 1) {
        char *buffer = malloc(total);
        mbedtls_x509_crt pem;
        mbedtls_x509_crt_init(&pem);
        if (sceSslInternalGetCertificateAuthorityByName(issuer, &entries, buffer, total, &total, 0) == 1 &&
            mbedtls_x509_crt_parse(&pem, (const unsigned char *)entries[0], strlen(entries[0]) + 1) == 0) {
            found = parse_der(&pem);
            CHECK_EQ(sceSslInternalCertInfo(found, 0x8009, &key), 0);
            CHECK_EQ(sceSslInternalCertVerifySignature(certificates[0], key, &valid), 0);
            sceSslInternalKeyFree(key);
            sceSslInternalCertFree(found);
        }
        mbedtls_x509_crt_free(&pem);
        free(buffer);
    }
    sceSslInternalNameFree(issuer);
    *reason = valid ? 0 : 10;
    return valid;
}

static Connection open_checked(const char *host)
{
    Connection connection = open_connection(g_port + 2, host, 1, 5000);
    sceSslInternalCtxSetCertVerifyCallback(connection.context, check_chain, g_check_argument);
    return connection;
}

static void test_verify_callback(void)
{
    char line[128];
    /* The bundle has the CA: the callback finds it and accepts, whatever Mbed TLS would say of the
     * name, which the callback checks or not */
    g_callback_calls = 0;
    Connection connection = open_checked("not-the-name.test");
    CHECK_EQ(sceSslInternalConnect(connection.ssl), 1);
    CHECK_EQ(g_callback_calls, 1);
    CHECK_EQ(g_callback_count, 2);
    CHECK_EQ(((VsSsl *)connection.ssl)->verify_result, 0);
    CHECK(read_line(connection.ssl, line, sizeof(line)) > 0);
    CHECK(strcmp(line, "sni=not-the-name.test\n") == 0);
    close_connection(&connection);
    /* No host on the BIO, as the firmware's libhttp: the name comes from the callback's argument */
    connection = open_connection(g_port + 2, NULL, 1, 5000);
    sceSslInternalCtxSetCertVerifyCallback(connection.context, check_chain, g_check_argument);
    CHECK_EQ(sceSslInternalConnect(connection.ssl), 1);
    CHECK(read_line(connection.ssl, line, sizeof(line)) > 0);
    CHECK(strcmp(line, "sni=chain.test\n") == 0);
    close_connection(&connection);
    /* It refuses: a TLS failure, with its reason kept */
    g_callback_refuse = 1;
    connection = open_checked("chain.test");
    int result = sceSslInternalConnect(connection.ssl);
    CHECK_EQ(result, -1);
    CHECK_EQ(sceSslInternalGetError(connection.ssl, result), VS_KIND_SSL);
    CHECK_EQ(((VsSsl *)connection.ssl)->verify_result, 4);
    sceSslInternalSetVerifyResult(connection.ssl, 7);
    CHECK_EQ(((VsSsl *)connection.ssl)->verify_result, 7);
    close_connection(&connection);
    g_callback_refuse = 0;
    /* A bundle without the CA: the callback finds no issuer and refuses */
    CHECK_EQ(sceSslTerm(), 0);
    snprintf(vs_test_ca_path, sizeof(vs_test_ca_path), "%s", g_other_root);
    CHECK_EQ(sceSslInit(256 * 1024), 0);
    connection = open_checked("chain.test");
    CHECK_EQ(sceSslInternalConnect(connection.ssl), -1);
    CHECK_EQ(((VsSsl *)connection.ssl)->verify_result, 10);
    close_connection(&connection);
    /* Without the verify mode the callback isn't called */
    g_callback_calls = 0;
    connection = open_connection(g_port + 2, "chain.test", 0, 5000);
    sceSslInternalCtxSetCertVerifyCallback(connection.context, check_chain, g_check_argument);
    CHECK_EQ(sceSslInternalConnect(connection.ssl), 1);
    CHECK_EQ(g_callback_calls, 0);
    close_connection(&connection);
    const void *item = &item;
    CHECK_EQ(sceSslInternalGetItem(NULL, 1, &item), 10017);
}

/* ---- client certificates ---- */

static char *read_text(const char *path, size_t *length)
{
    FILE *file = fopen(path, "rb");
    char *text = calloc(1, 16384);
    *length = file != NULL && text != NULL ? fread(text, 1, 16383, file) : 0;
    if (file != NULL)
        fclose(file);
    return text;
}

/* As libhttp's client certificate callback (0x81009088): the loaded certificate and key, given only
 * when one of the server's CA names is the certificate's issuer */
static const char *g_offer_pem, *g_offer_key;
static int g_offer_calls, g_offer_names, g_offer_chosen;

static int offer_certificate(void *ssl, void **certificate, void **key)
{
    ++g_offer_calls;
    const void *library = NULL;
    CHECK_EQ(sceSslInternalGetItem(ssl, 5, &library), 0);
    size_t length = 0;
    char *pem = read_text(g_offer_pem, &length);
    void *cert = NULL, *private_key = NULL, *issuer = NULL;
    unsigned int consumed = 0;
    /* PEM as an app loads it */
    CHECK_EQ(sceSslInternalCertFromBinary(library, 0, 1, (unsigned int)length, (unsigned char *)pem, &consumed,
                                          &cert), 0);
    free(pem);
    char *text = read_text(g_offer_key, &length);
    void *buffer = sceSslInternalBufferNew();
    CHECK(buffer != NULL);
    /* Written in two parts, as libhttp loops until all of it is */
    CHECK_EQ(sceSslInternalBufferWrite(buffer, text, 10), 10);
    CHECK_EQ(sceSslInternalBufferWrite(buffer, text + 10, (int)length - 10), length - 10);
    CHECK_EQ(sceSslInternalKeyFromBuffer(buffer, library, &private_key, 6, 0x1100), 0);
    CHECK_EQ(sceSslInternalBufferFree(buffer), 0);
    free(text);
    CHECK_EQ(sceSslInternalKeyMatches(cert, private_key), 1);
    CHECK_EQ(sceSslInternalCertIssuer(cert, 1, &issuer), 0);
    g_offer_names = sceSslInternalGetCaNameCount(ssl);
    int chosen = 0;
    for (int i = 0; i < g_offer_names && !chosen; ++i) {
        void *name = NULL;
        CHECK_EQ(sceSslInternalGetCaName(ssl, i, &name), 0);
        chosen = sceSslInternalNameEqual(name, issuer) == 1;
    }
    void *name = NULL;
    CHECK_EQ(sceSslInternalGetCaName(ssl, g_offer_names, &name), 10008);
    sceSslInternalNameFree(issuer);
    g_offer_chosen = chosen;
    if (!chosen) {
        sceSslInternalKeyFree(private_key);
        sceSslInternalCertFree(cert);
        return 0;
    }
    *certificate = cert;
    *key = private_key;
    return 1;
}

/* An HTTP request to s_server -www: its page when the handshake was accepted */
static int asked_page(int port, const char *pem, const char *key)
{
    char page[256];
    g_offer_pem = pem;
    g_offer_key = key;
    g_offer_calls = g_offer_names = g_offer_chosen = 0;
    Connection connection = open_connection(port, "vitals-ssl.test", 0, 5000);
    sceSslInternalCtxSetClientCertCallback(connection.context, offer_certificate);
    int ok = 0;
    if (sceSslInternalConnect(connection.ssl) == 1 &&
        sceSslInternalWrite(connection.ssl, "GET / HTTP/1.0\r\n\r\n", 18) == 18) {
        int got = sceSslInternalRead(connection.ssl, page, sizeof(page) - 1);
        ok = got > 0 && strncmp(page, "HTTP/1.0 200", 12) == 0;
    }
    close_connection(&connection);
    return ok;
}

static void test_client_certificate(void)
{
    for (int offset = 0; offset < 2; ++offset) {
        int port = g_port + 3 + offset;
        /* Signed by the CA the server names: sent, and accepted */
        CHECK_EQ(asked_page(port, g_client_pem, g_client_key), 1);
        CHECK_EQ(g_offer_calls, 1);
        CHECK_EQ(g_offer_names, 1);
        CHECK_EQ(g_offer_chosen, 1);
        /* By another: not sent, so the server refuses */
        CHECK_EQ(asked_page(port, g_stranger_pem, g_stranger_key), 0);
        CHECK_EQ(g_offer_calls, 1);
        CHECK_EQ(g_offer_chosen, 0);
    }
    /* A server that doesn't ask: the callback isn't called */
    g_offer_pem = g_client_pem;
    g_offer_key = g_client_key;
    g_offer_calls = 0;
    Connection connection = open_connection(g_port, "vitals-ssl.test", 0, 5000);
    sceSslInternalCtxSetClientCertCallback(connection.context, offer_certificate);
    CHECK_EQ(sceSslInternalConnect(connection.ssl), 1);
    CHECK_EQ(g_offer_calls, 0);
    close_connection(&connection);
    /* Outside the callback there are no names */
    CHECK_EQ(sceSslInternalGetCaNameCount(NULL), 0);
    /* A wrong key, and buffers */
    size_t length = 0;
    char *text = read_text(g_stranger_key, &length);
    void *buffer = sceSslInternalBufferNew(), *key = NULL, *cert = NULL;
    CHECK_EQ(sceSslInternalBufferWrite(buffer, text, (int)length), length);
    CHECK_EQ(sceSslInternalKeyFromBuffer(buffer, NULL, &key, 6, 0x1100), 0);
    free(text);
    text = read_text(g_client_pem, &length);
    unsigned int consumed = 0;
    CHECK_EQ(sceSslInternalCertFromBinary(NULL, 0, 1, (unsigned int)length, (unsigned char *)text, &consumed, &cert),
             0);
    free(text);
    CHECK_EQ(sceSslInternalKeyMatches(cert, key), 0);
    CHECK_EQ(sceSslInternalBufferWrite(buffer, NULL, 4), (uint32_t)-1);
    CHECK_EQ(sceSslInternalBufferFree(buffer), 0);
    buffer = sceSslInternalBufferNew();
    CHECK_EQ(sceSslInternalBufferWrite(buffer, "junk", 4), 4);
    void *bad = NULL;
    CHECK_EQ(sceSslInternalKeyFromBuffer(buffer, NULL, &bad, 6, 0x1100), 10001);
    CHECK(bad == NULL);
    CHECK_EQ(sceSslInternalBufferFree(buffer), 0);
    CHECK_EQ(sceSslInternalBufferFree(NULL), 10017);
    sceSslInternalKeyFree(key);
    sceSslInternalCertFree(cert);
}

int main(int argc, char **argv)
{
    if (argc != 10) {
        fprintf(stderr, "usage: %s <port> <server certificate> <unrelated root> <chain> <bundle> <client "
                        "certificate> <its key> <another one> <its key>\n", argv[0]);
        return 2;
    }
    g_port = atoi(argv[1]);
    g_server_pem = argv[2];
    g_other_root = argv[3];
    g_chain_pem = argv[4];
    g_bundle = argv[5];
    g_client_pem = argv[6];
    g_client_key = argv[7];
    g_stranger_pem = argv[8];
    g_stranger_key = argv[9];
    FILE *file = fopen(g_chain_pem, "rb");
    g_chain_length = file != NULL ? fread(g_chain_text, 1, sizeof(g_chain_text) - 1, file) : 0;
    if (file != NULL)
        fclose(file);
    if (g_chain_length == 0) {
        fprintf(stderr, "can't read %s\n", g_chain_pem);
        return 2;
    }
    test_init();
    test_error_codes();
    test_objects();
    test_echo();
    test_drop();
    test_timeout();
    test_implicit_connect();
    test_address();
    test_verify();
    test_certificate_objects();
    test_certificate_store();
    test_verify_callback();
    test_client_certificate();
    CHECK_EQ(sceSslTerm(), 0);
    (void)g_alerts;
    (void)g_last_alert;
    printf("%d checks, %d failed\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
