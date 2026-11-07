/* vitals' libssl's host tests: the library built for this machine (platform_posix.c and its
 * neighbours in place of the console's), called as Sony's PS3 libhttp calls it
 * (dumps/ps3/4.93-cex/libhttp.prx: its context at 0x24808, connecting at 0x2491c, reading at 0x24520,
 * closing at 0x2435c), against server.py (run_tests.py starts it):
 *     test_main <port> <certificates' folder> <the CA's subject hash>
 * The server echoes lines after sending "sni=<name>\n", "quit" ends with close_notify, "drop"
 * closes the socket without it; the next port never answers; the one after serves chain.test's
 * certificate and the CA that signed it (run_tests.py makes them, and the CA's subject hash with
 * `openssl x509 -subject_hash_old`). */

#include "ca_store.h"
#include "core.h"
#include "ssl_api.h"

#include <mbedtls/platform_time.h>
#include <mbedtls/platform_util.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* pool_posix.c's */
extern size_t vs_test_pool_used, vs_test_pool_peak;
extern uint32_t vs_test_refused_pool;
/* platform_posix.c's */
extern char vs_test_sony_cert_directory[512], vs_test_bundle_path[512], vs_test_custom_path[512], vs_test_title_id[10];

static int g_failures, g_checks;
static int g_port;
/* What the pool holds between connections: psa_crypto_init's random generator and key slots, which
 * last until cellSslEnd (the slots grow on the first handshake); a connection gives back the rest */
static size_t g_between_connections;
static const char *g_directory;
static unsigned long g_ca_hash;
/* libhttp's check, which libhttp_context gives the context when it's set */
static int (*g_check)(void *ssl, void *certificates[], int count, void *argument, int *reason);
static int g_check_argument;
static unsigned char g_pool[512 * 1024];

#define CHECK(condition)                                                                       \
	do {                                                                                       \
		++g_checks;                                                                            \
		if (!(condition)) {                                                                    \
			++g_failures;                                                                      \
			fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition);                    \
		}                                                                                      \
	} while (0)

#define CHECK_EQ(actual, expected)                                                             \
	do {                                                                                       \
		long long a_ = (long long)(actual), e_ = (long long)(expected);                       \
		++g_checks;                                                                            \
		if (a_ != e_) {                                                                        \
			++g_failures;                                                                      \
			fprintf(stderr, "%s:%d: %s is %lld (0x%llx), expected %lld (0x%llx)\n", __FILE__, \
			        __LINE__, #actual, a_, (unsigned long long)a_, e_, (unsigned long long)e_);  \
		}                                                                                      \
	} while (0)

/* What libhttp's SSL_get_error cases give a game: its connect's (0x2491c), read's (0x24520) */
#define KIND_NONE 0
#define KIND_SSL 1
#define KIND_WANT_READ 2
#define KIND_SYSCALL 5
#define KIND_ZERO_RETURN 6

static int connect_to(int port)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in address = {0};
	address.sin_family = AF_INET;
	address.sin_port = htons((uint16_t)port);
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (fd < 0 || connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
		perror("connect");
		exit(2);
	}
	return fd;
}

/* libhttp's context (0x24808) */
static void *libhttp_context(int verify)
{
	void *context = SSL_CTX_new(TLSv1_client_method());
	if (context == NULL)
		return NULL;
	(void)SSL_CTX_set_options(context, 0x2000FFFF);
	(void)SSL_CTX_ctrl(context, 44, 0, NULL);
	SSL_CTX_set_verify_mode(context, verify ? 5 : 0);
	if (verify && g_check != NULL)
		SSL_CTX_set_app_verify_cb(context, g_check, &g_check_argument);
	(void)SSL_CTX_set_options(context, 0x40000);
	return context;
}

typedef struct Connection {
	void *context, *ssl;
	int fd;
} Connection;

/* libhttp's connect (0x2491c): a socket BIO that doesn't close the socket, the host name with
 * BIO_ctrl 100, its connection as the BIO's callback argument */
static int libhttp_connect(Connection *connection, int port, const char *host, int verify, int nonblocking)
{
	connection->context = libhttp_context(verify);
	connection->fd = connect_to(port);
	if (nonblocking)
		fcntl(connection->fd, F_SETFL, fcntl(connection->fd, F_GETFL) | O_NONBLOCK);
	connection->ssl = SSL_new(connection->context);
	CHECK(connection->ssl != NULL);
	CHECK_EQ(SSL_set_ssl_method(connection->ssl, TLSv1_client_method()), 1);
	void *bio = BIO_new_socket(connection->fd, 0);
	CHECK(bio != NULL);
	CHECK_EQ(BIO_ctrl(bio, 100, 0, (void *)host), 1);
	BIO_set_cb_arg(bio, connection);
	SSL_set_bio(connection->ssl, bio, bio);
	SSL_set_connect_state(connection->ssl);
	for (;;) {
		int result = SSL_do_handshake(connection->ssl);
		int kind = SSL_get_error(connection->ssl, result);
		if (kind == KIND_NONE)
			return 1;
		/* libhttp's non-blocking case: errno EAGAIN, call again */
		if (kind == KIND_WANT_READ && errno == EAGAIN && nonblocking) {
			usleep(1000);
			continue;
		}
		return -kind;
	}
}

/* libhttp's close (0x2435c), then it closes the socket itself */
static void libhttp_close(Connection *connection)
{
	(void)SSL_shutdown(connection->ssl);
	CHECK_EQ(SSL_clear(connection->ssl), 1);
	CHECK_EQ(SSL_set_session(connection->ssl, NULL), 1);
	SSL_set_bio(connection->ssl, NULL, NULL);
	SSL_free(connection->ssl);
	SSL_CTX_free(connection->context);
	close(connection->fd);
}

/* One line, through SSL_read */
static int read_line(void *ssl, char *line, size_t size)
{
	size_t at = 0;
	while (at + 1 < size) {
		int result = SSL_read(ssl, line + at, 1);
		if (result <= 0)
			return result;
		if (line[at++] == '\n')
			break;
	}
	line[at] = '\0';
	return (int)at;
}

static void write_text(void *ssl, const char *text)
{
	CHECK_EQ(SSL_write(ssl, text, (int)strlen(text)), (long long)strlen(text));
}

static void test_init(void)
{
	CHECK_EQ(_cellSslIsInitd(), 0);
	const unsigned char *data = NULL;
	size_t data_length = 0;
	CHECK_EQ(cellSslCertGetSerialNumber(&data, &data, &data_length), (int)0x80740001);
	CHECK_EQ(cellSsl_4EE83087(1, 2), (int)0x80740001);
	uint32_t free_size = 7;
	CHECK_EQ(cellSslGetMemoryInfo(&free_size, NULL, NULL), 0);
	CHECK_EQ(free_size, 0);
	CHECK(SSL_CTX_new(TLSv1_client_method()) == NULL);
	CHECK_EQ(cellSslEnd(), (int)0x80740001);
	CHECK_EQ(cellSslInit(NULL, sizeof(g_pool)), (int)0x80740004);
	CHECK_EQ(cellSslInit(g_pool, 0), (int)0x80740004);
	vs_test_refused_pool = 4096;
	CHECK_EQ(cellSslInit(g_pool, 4096), (int)0x80740035);
	vs_test_refused_pool = 0;
	CHECK_EQ(cellSslInit(g_pool, sizeof(g_pool)), 0);
	CHECK_EQ(_cellSslIsInitd(), 1);
	CHECK_EQ(cellSslInit(g_pool, sizeof(g_pool)), (int)0x80740002);
	CHECK_EQ(cellSslEnd(), 0);
	CHECK_EQ(_cellSslIsInitd(), 0);
	CHECK_EQ(cellSslInit(g_pool, sizeof(g_pool)), 0);
	g_between_connections = vs_test_pool_used;
}

/* The error Sony's would queue: library 20 (SSL), the function, the reason */
static void check_error(unsigned long function, unsigned long reason, int line)
{
	unsigned long error = ERR_get_error();
	++g_checks;
	if (error != (20ul << 24 | function << 12 | reason)) {
		++g_failures;
		fprintf(stderr, "%s:%d: error 0x%lx, expected function %lu reason %lu\n", __FILE__, line, error, function,
		        reason);
	}
}
#define CHECK_ERROR(function, reason) check_error(function, reason, __LINE__)

static void test_objects(void)
{
	CHECK(TLSv1_client_method() != NULL && SSLv3_client_method() != NULL && cellSsl_C5F77319() != NULL);
	ERR_clear_error();
	CHECK(SSL_CTX_new(NULL) == NULL);
	CHECK_ERROR(168, 196);
	/* Sony's SSL_CTX_new's defaults */
	void *fresh = SSL_CTX_new(TLSv1_client_method());
	CHECK_EQ(SSL_CTX_ctrl(fresh, 45, 0, NULL), 2);
	CHECK_EQ(SSL_CTX_ctrl(fresh, 43, 0, NULL), 20480);
	CHECK_EQ(SSL_CTX_ctrl(fresh, 42, 100, NULL), 20480);
	CHECK_EQ(SSL_CTX_ctrl(fresh, 43, 0, NULL), 100);
	CHECK_EQ(SSL_CTX_ctrl(fresh, 55, 0, NULL), 1);
	CHECK_EQ(SSL_CTX_ctrl(fresh, 56, 7, NULL), 1);
	CHECK_EQ(SSL_CTX_ctrl(fresh, 56, 0, NULL), 7);
	CHECK_EQ(SSL_CTX_ctrl(fresh, 20, 0, NULL), 0);
	SSL_CTX_free(fresh);
	void *context = libhttp_context(0);
	CHECK(context != NULL);
	CHECK_EQ(SSL_CTX_set_options(context, 0), 0x2004FFFF);
	CHECK_EQ(SSL_CTX_ctrl(context, 44, 2, NULL), 0);
	CHECK_EQ(SSL_CTX_ctrl(context, 45, 0, NULL), 2);
	void *ssl = SSL_new(context);
	CHECK(ssl != NULL);
	CHECK(SSL_new(NULL) == NULL);
	CHECK_ERROR(186, 195);
	/* The method's version before a handshake, named as Sony's names it */
	CHECK_EQ(SSL_version(ssl), 0x0303);
	CHECK(strcmp(SSL_get_version(ssl), "TLSv12") == 0);
	CHECK_EQ(SSL_state(ssl), 0x5000);
	CHECK(strcmp(SSL_state_string_long(ssl), "unknown state") == 0);
	CHECK_EQ(SSL_want(ssl), 1);
	CHECK(SSL_get_current_cipher(ssl) == NULL);
	CHECK(strcmp(SSL_CIPHER_get_name(NULL), "(NONE)") == 0);
	CHECK_EQ(SSL_CIPHER_get_id(NULL), 0xFFFFFFFFul);
	CHECK_EQ(SSL_get_error(ssl, 1), KIND_NONE);
	/* No connect state: no handshake, reason 144 */
	CHECK_EQ(SSL_do_handshake(ssl), -1);
	CHECK_EQ(SSL_get_error(ssl, -1), KIND_SSL);
	CHECK_ERROR(180, 144);
	CHECK_EQ(SSL_set_ssl_method(ssl, NULL), 0);
	CHECK_EQ(SSL_set_ssl_method(ssl, cellSsl_C5F77319()), 1);
	CHECK_EQ(SSL_version(ssl), 0x0300);
	CHECK(strcmp(SSL_get_version(ssl), "SSLv3") == 0);
	/* SSL_clear keeps it */
	CHECK_EQ(SSL_clear(ssl), 1);
	CHECK_EQ(SSL_version(ssl), 0x0300);
	/* No connection: 1; before any handshake (libhttp's option 0x40000 set) 1 too, and then writing
	 * fails as shut down, reason 207 */
	CHECK_EQ(SSL_shutdown(NULL), 1);
	CHECK_EQ(SSL_shutdown(ssl), 1);
	CHECK_EQ(SSL_write(ssl, "x", 1), -1);
	CHECK_ERROR(209, 207);
	char none[1];
	CHECK_EQ(SSL_read(ssl, none, 1), 0);
	void *plain = SSL_CTX_new(TLSv1_client_method());
	void *unshut = SSL_new(plain);
	CHECK_EQ(SSL_shutdown(unshut), -1);
	SSL_free(unshut);
	SSL_CTX_free(plain);

	void *bio = BIO_new_socket(-1, 1);
	CHECK(bio != NULL);
	CHECK_EQ(BIO_ctrl(NULL, 8, 0, NULL), 0);
	CHECK_EQ(BIO_ctrl(bio, 8, 0, NULL), 1);
	CHECK_EQ(BIO_ctrl(bio, 9, 0, NULL), 1);
	CHECK_EQ(BIO_ctrl(bio, 8, 0, NULL), 0);
	/* The host name is copied, as Sony's */
	char name[] = "example.com";
	CHECK_EQ(BIO_ctrl(bio, 100, 0, name), 1);
	name[0] = 'X';
	const char *host = NULL;
	CHECK_EQ(BIO_ctrl(bio, 123, 0, &host), 1);
	CHECK(host != NULL && strcmp(host, "example.com") == 0);
	CHECK(host != name);
	CHECK_EQ(BIO_ctrl(bio, 100, 0, NULL), 1);
	CHECK_EQ(BIO_ctrl(bio, 123, 0, NULL), -1);
	CHECK_EQ(BIO_ctrl(bio, 100, 1, "443"), 1);
	CHECK_EQ(BIO_ctrl(bio, 123, 1, &host), 1);
	CHECK(strcmp(host, "443") == 0);
	int port = 8443, read_port = 0;
	CHECK_EQ(BIO_ctrl(bio, 100, 3, &port), 1);
	CHECK_EQ(BIO_ctrl(bio, 123, 3, &read_port), 1);
	CHECK_EQ(read_port, 8443);
	const unsigned char address[4] = {192, 168, 1, 20};
	CHECK_EQ(BIO_ctrl(bio, 100, 2, (void *)address), 1);
	CHECK_EQ(BIO_ctrl(bio, 123, 0, &host), 1);
	CHECK(strcmp(host, "192.168.1.20") == 0);
	CHECK_EQ(BIO_ctrl(bio, 100, 0, name), 1);
	CHECK_EQ(BIO_ctrl(bio, 11, 0, NULL), 1);
	CHECK_EQ(BIO_ctrl(bio, 12, 0, NULL), 1);
	CHECK_EQ(BIO_ctrl(bio, 128, 0, NULL), 1);
	CHECK_EQ(BIO_ctrl(bio, 77, 0, NULL), 0);
	CHECK_EQ(BIO_get_retry_reason(bio), 0);
	int fd = 0;
	CHECK_EQ(BIO_ctrl(bio, 105, 0, &fd), -1);
	CHECK_EQ(fd, -1);
	int here = 0;
	BIO_set_cb_arg(bio, &here);
	CHECK(BIO_get_cb_arg(bio) == &here);
	CHECK(BIO_get_cb_arg(NULL) == NULL);
	SSL_set_bio(ssl, bio, bio);
	CHECK(SSL_get_rbio(ssl) == bio);
	/* Replaced: the old one is freed (ASan would say otherwise) */
	SSL_set_bio(ssl, NULL, NULL);
	CHECK(SSL_get_rbio(ssl) == NULL);
	CHECK_EQ(BIO_free(NULL), 0);
	CHECK_EQ(BIO_free(BIO_new_socket(-1, 0)), 1);

	SSL_free(ssl);
	SSL_CTX_free(context);
	/* Everything given back but what psa_crypto_init keeps */
	CHECK_EQ(vs_test_pool_used, g_between_connections);
}

static void test_echo(void)
{
	Connection connection;
	CHECK_EQ(libhttp_connect(&connection, g_port, "vitals-ssl.test", 0, 0), 1);
	CHECK_EQ(SSL_version(connection.ssl), 0x0304);
	CHECK(strcmp(SSL_get_version(connection.ssl), "TLSv13") == 0);
	CHECK_EQ(SSL_state(connection.ssl), 3);
	const void *cipher = SSL_get_current_cipher(connection.ssl);
	CHECK(cipher != NULL);
	CHECK(strstr(SSL_CIPHER_get_name(cipher), "AES") != NULL || strstr(SSL_CIPHER_get_name(cipher), "CHACHA") != NULL);
	int bits = 0;
	CHECK(SSL_CIPHER_get_bits(cipher, &bits) >= 128 && bits >= 128);
	/* The suite's number, TLS 1.3's 0x13xx, without OpenSSL's 0x03 above it, as Sony's */
	CHECK((SSL_CIPHER_get_id(cipher) & 0xFFFFFF00u) == 0x1300u);
	int cell = 0;
	CHECK_EQ(_cellSslConvertCipherId(SSL_CIPHER_get_id(cipher), &cell), 0);
	CHECK_EQ(cell, -1);
	CHECK(strcmp(SSL_CIPHER_get_version(cipher), "TLSv1/SSLv3") == 0);
	char description[128];
	CHECK(SSL_CIPHER_description(cipher, description, sizeof(description)) == description);
	CHECK(strncmp(description, SSL_CIPHER_get_name(cipher), strlen(SSL_CIPHER_get_name(cipher))) == 0);
	CHECK(strstr(description, " TLSv13 Kx=any      Au=any  Enc=AES") != NULL ||
	      strstr(description, " TLSv13 Kx=any      Au=any  Enc=CHACHA20") != NULL);
	CHECK(strstr(description, "Mac=AEAD") != NULL);
	fprintf(stderr, "cipher: %s\n", description);
	char small[64];
	CHECK(SSL_CIPHER_description(cipher, small, sizeof(small)) == NULL);
	CHECK_ERROR(216, 16);

	char line[256];
	CHECK(read_line(connection.ssl, line, sizeof(line)) > 0);
	CHECK(strcmp(line, "sni=vitals-ssl.test\n") == 0);
	write_text(connection.ssl, "hello\n");
	CHECK(read_line(connection.ssl, line, sizeof(line)) > 0);
	CHECK(strcmp(line, "hello\n") == 0);

	/* A request's headers for the debug log (VS_TEST_LOG shows them), its secrets as their length */
	write_text(connection.ssl, "GET /login?user=me&token=abc123 HTTP/1.1\r\nHost: vitals-ssl.test\r\n"
	                           "Cookie: session=1\r\nAuthorization: Bearer xyz\r\nContent-Length: 0\r\n\r\n");
	for (int i = 0; i < 6; ++i)
		CHECK(read_line(connection.ssl, line, sizeof(line)) > 0);

	/* SSL_peek gives what the next SSL_read gives */
	write_text(connection.ssl, "peeked\n");
	char peeked[4] = {0};
	CHECK_EQ(SSL_peek(connection.ssl, peeked, 3), 3);
	CHECK(memcmp(peeked, "pee", 3) == 0);
	CHECK_EQ(SSL_peek(connection.ssl, peeked, 2), 2);
	CHECK(read_line(connection.ssl, line, sizeof(line)) > 0);
	CHECK(strcmp(line, "peeked\n") == 0);

	/* More than one record each way */
	static char big[40000], back[40000];
	for (size_t i = 0; i < sizeof(big) - 1; ++i)
		big[i] = (char)('a' + i % 26);
	big[sizeof(big) - 1] = '\n';
	CHECK_EQ(SSL_write(connection.ssl, big, sizeof(big)), sizeof(big));
	int got = 0;
	while (got < (int)sizeof(back)) {
		int result = SSL_read(connection.ssl, back + got, (int)sizeof(back) - got);
		if (result <= 0)
			break;
		got += result;
	}
	CHECK_EQ(got, sizeof(back));
	CHECK(memcmp(big, back, sizeof(big)) == 0);

	/* The server's close_notify: 0, then SSL_get_error 6 */
	write_text(connection.ssl, "quit\n");
	CHECK(read_line(connection.ssl, line, sizeof(line)) > 0);
	CHECK(strcmp(line, "bye\n") == 0);
	CHECK_EQ(SSL_read(connection.ssl, line, sizeof(line)), 0);
	CHECK_EQ(SSL_get_error(connection.ssl, 0), KIND_ZERO_RETURN);
	CHECK_EQ(SSL_shutdown(connection.ssl), 1);
	libhttp_close(&connection);
	g_between_connections = vs_test_pool_used;
	fprintf(stderr, "pool: %zu bytes at most during a connection\n", vs_test_pool_peak);
}

/* The server closes the socket without close_notify: 0, SSL_get_error 5 */
static void test_drop(void)
{
	Connection connection;
	CHECK_EQ(libhttp_connect(&connection, g_port, "vitals-ssl.test", 0, 0), 1);
	char line[256];
	CHECK(read_line(connection.ssl, line, sizeof(line)) > 0);
	write_text(connection.ssl, "drop\n");
	CHECK(read_line(connection.ssl, line, sizeof(line)) > 0);
	int result = SSL_read(connection.ssl, line, sizeof(line));
	CHECK_EQ(result, 0);
	CHECK_EQ(SSL_get_error(connection.ssl, result), KIND_SYSCALL);
	libhttp_close(&connection);
}

/* PSN sign-in's hosts get the console's own ClientHello (connection.c, console_profile): the one a
 * console signing in sends, captured from the XMB on 4.93, byte for byte but for
 * the 32 random bytes (zero here, at 11 to 42). Any other host keeps TLS 1.3 offered */
static const unsigned char k_console_hello[] = {
	0x16, 0x03, 0x03, 0x00, 0x82, 0x01, 0x00, 0x00, 0x7E, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x3D,
	0x00, 0x3C, 0x00, 0x35, 0x00, 0x2F, 0x00, 0x0A, 0x00, 0x05, 0x00, 0x04, 0x00, 0xFF, 0x01, 0x00,
	0x00, 0x45, 0x00, 0x00, 0x00, 0x33, 0x00, 0x31, 0x00, 0x00, 0x2E, 0x49, 0x56, 0x30, 0x30, 0x30,
	0x31, 0x2D, 0x4E, 0x50, 0x58, 0x53, 0x30, 0x31, 0x30, 0x30, 0x31, 0x2D, 0x30, 0x30, 0x2E, 0x61,
	0x75, 0x74, 0x68, 0x2E, 0x6E, 0x70, 0x2E, 0x61, 0x63, 0x2E, 0x70, 0x6C, 0x61, 0x79, 0x73, 0x74,
	0x61, 0x74, 0x69, 0x6F, 0x6E, 0x2E, 0x6E, 0x65, 0x74, 0x00, 0x0D, 0x00, 0x0A, 0x00, 0x08, 0x04,
	0x01, 0x06, 0x01, 0x05, 0x01, 0x02, 0x01,
};

/* The ClientHello the handshake sends for host, over a socket pair: the handshake's end is
 * non-blocking, so SSL_do_handshake gives up waiting for the answer, which never comes */
static size_t client_hello(const char *host, unsigned char *hello, size_t size)
{
	int pair[2];
	CHECK_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, pair), 0);
	fcntl(pair[0], F_SETFL, fcntl(pair[0], F_GETFL) | O_NONBLOCK);
	void *context = libhttp_context(0);
	void *ssl = SSL_new(context);
	CHECK(ssl != NULL);
	void *bio = BIO_new_socket(pair[0], 0);
	CHECK_EQ(BIO_ctrl(bio, 100, 0, (void *)host), 1);
	SSL_set_bio(ssl, bio, bio);
	SSL_set_connect_state(ssl);
	CHECK_EQ(SSL_do_handshake(ssl), -1);
	struct timeval timeout = {5, 0};
	setsockopt(pair[1], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	size_t got = 0;
	while (got < 5 || got < 5 + (((size_t)hello[3] << 8) | hello[4])) {
		ssize_t n = read(pair[1], hello + got, size - got);
		if (n <= 0)
			break;
		got += (size_t)n;
	}
	close(pair[1]);
	SSL_free(ssl);
	SSL_CTX_free(context);
	close(pair[0]);
	return got;
}

static void test_console_hello(void)
{
	static const char host[] = "IV0001-NPXS01001-00.auth.np.ac.playstation.net";
	unsigned char hello[2048];
	size_t got = client_hello(host, hello, sizeof(hello));
	CHECK_EQ(got, sizeof(k_console_hello));
	if (got == sizeof(k_console_hello)) {
		memset(hello + 11, 0, 32);
		for (size_t i = 0; i < got; ++i)
			if (hello[i] != k_console_hello[i]) {
				fprintf(stderr, "console ClientHello: byte %zu is 0x%02X, the console's 0x%02X\n", i, hello[i],
				        k_console_hello[i]);
				CHECK(0);
				break;
			}
	}
	/* Without case too, and not for a host that only contains the name */
	got = client_hello("iv0001-npxs01001-00.AUTH.NP.AC.PLAYSTATION.NET", hello, sizeof(hello));
	CHECK_EQ(got, sizeof(k_console_hello));
	/* Any other host: TLS 1.3 offered (supported_versions, 0x002B, in the extensions) */
	static const unsigned char supported_versions[] = {0x00, 0x2B};
	got = client_hello("np.ac.playstation.net.example", hello, sizeof(hello));
	CHECK(got > sizeof(k_console_hello));
	CHECK(memmem(hello, got, supported_versions, sizeof(supported_versions)) != NULL);
}

/* A non-blocking socket: SSL_do_handshake gives -1, SSL_get_error 2 and errno EAGAIN on the caller's
 * thread (the handshake ran on another), until it's connected, as libhttp's loop expects */
static void test_nonblocking(void)
{
	Connection connection;
	CHECK_EQ(libhttp_connect(&connection, g_port, "vitals-ssl.test", 0, 1), 1);
	char line[256];
	int result;
	while ((result = SSL_read(connection.ssl, line, 4)) < 0 && SSL_get_error(connection.ssl, result) == KIND_WANT_READ &&
	       errno == EAGAIN)
		usleep(1000);
	CHECK(result > 0);
	CHECK(memcmp(line, "sni=", 4) == 0);
	libhttp_close(&connection);
}

/* A receive timeout (libhttp sets one) is the socket's EAGAIN too: -1 and SSL_get_error 2 */
static void test_timeout(void)
{
	Connection connection;
	connection.context = libhttp_context(0);
	connection.fd = connect_to(g_port + 1);
	struct timeval timeout = {0, 200000};
	setsockopt(connection.fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	connection.ssl = SSL_new(connection.context);
	void *bio = BIO_new_socket(connection.fd, 0);
	SSL_set_bio(connection.ssl, bio, bio);
	SSL_set_connect_state(connection.ssl);
	int result = SSL_do_handshake(connection.ssl);
	CHECK_EQ(result, -1);
	CHECK_EQ(SSL_get_error(connection.ssl, result), KIND_WANT_READ);
	CHECK_EQ(errno, EAGAIN);
	CHECK_EQ(SSL_want(connection.ssl), 3);
	libhttp_close(&connection);
}

/* An address as the host: no SNI, as Sony's */
static void test_address(void)
{
	Connection connection;
	CHECK_EQ(libhttp_connect(&connection, g_port, "127.0.0.1", 0, 0), 1);
	char line[256];
	CHECK(read_line(connection.ssl, line, sizeof(line)) > 0);
	CHECK(strcmp(line, "sni=-\n") == 0);
	libhttp_close(&connection);
	/* Not addresses: names, sent as SNI */
	CHECK_EQ(libhttp_connect(&connection, g_port, "127.0.0.1.example", 0, 0), 1);
	CHECK(read_line(connection.ssl, line, sizeof(line)) > 0);
	CHECK(strcmp(line, "sni=127.0.0.1.example\n") == 0);
	libhttp_close(&connection);
	/* Every connection since the first gave all its memory back */
	CHECK_EQ(vs_test_pool_used, g_between_connections);
}

/* Until the certificate functions are written, a context that checks the server gets no connection:
 * SSL_get_error 1, with an error queued */
static void test_verify_refused(void)
{
	ERR_clear_error();
	CHECK_EQ(ERR_peek_error(), 0);
	Connection connection;
	CHECK_EQ(libhttp_connect(&connection, g_port, "vitals-ssl.test", 1, 0), -KIND_SSL);
	CHECK(ERR_peek_error() != 0);
	CHECK((ERR_peek_error() >> 24) == 20);
	CHECK(ERR_get_error() != 0);
	CHECK_EQ(ERR_get_error(), 0);
	libhttp_close(&connection);
}

static void test_convert(void)
{
	static const int cells[][2] = {{10, 0}, {5, 1}, {4, 2}, {9, 3}, {98, 4}, {100, 5}, {8, 6}, {6, 7}, {3, 8},
	                               {0, -1}, {0x1301, -1}, {0xC02F, -1}};
	for (size_t i = 0; i < sizeof(cells) / sizeof(cells[0]); ++i) {
		int out = 99;
		CHECK_EQ(_cellSslConvertCipherId((unsigned long)cells[i][0], &out), 0);
		CHECK_EQ(out, cells[i][1]);
	}
	static const int versions[][2] = {{0x0300, 1}, {0x0301, 0}, {0x0303, 0}, {0x0304, 0}, {0x0200, -1}, {0, -1}};
	for (size_t i = 0; i < sizeof(versions) / sizeof(versions[0]); ++i) {
		int out = 99;
		CHECK_EQ(_cellSslConvertSslVersion(versions[i][0], &out), 0);
		CHECK_EQ(out, versions[i][1]);
	}
}

/* gmtime.c against the system's, over X.509's years */
static void test_gmtime(void)
{
	static const int64_t fixed[] = {0, -1, 951782400, 951868799, 4107542400, 253402300799, -62167219200,
	                                -2208988800, 1700000000};
	for (int i = 0; i < 20000 + (int)(sizeof(fixed) / sizeof(fixed[0])); ++i) {
		int64_t seconds = i < (int)(sizeof(fixed) / sizeof(fixed[0]))
		                      ? fixed[i]
		                      : -62167219200 + (int64_t)((double)rand() / RAND_MAX * (253402300799.0 + 62167219200.0));
		mbedtls_time_t value = seconds;
		time_t system_value = (time_t)seconds;
		struct tm ours, theirs;
		CHECK(mbedtls_platform_gmtime_r(&value, &ours) == &ours);
		CHECK(gmtime_r(&system_value, &theirs) != NULL);
		int same = ours.tm_year == theirs.tm_year && ours.tm_mon == theirs.tm_mon && ours.tm_mday == theirs.tm_mday &&
		           ours.tm_hour == theirs.tm_hour && ours.tm_min == theirs.tm_min && ours.tm_sec == theirs.tm_sec &&
		           ours.tm_wday == theirs.tm_wday && ours.tm_yday == theirs.tm_yday;
		if (!same)
			fprintf(stderr, "gmtime %lld: %d-%d-%d %d %d vs %d-%d-%d %d %d\n", (long long)seconds, ours.tm_year,
			        ours.tm_mon, ours.tm_mday, ours.tm_wday, ours.tm_yday, theirs.tm_year, theirs.tm_mon,
			        theirs.tm_mday, theirs.tm_wday, theirs.tm_yday);
		CHECK(same);
	}
	mbedtls_time_t outside = 253402300800;
	struct tm result;
	CHECK(mbedtls_platform_gmtime_r(&outside, &result) == NULL);
}

/* ---- certificates ---- */

/* A file of the certificates' folder, NUL-terminated; exits when it isn't there */
static unsigned char *read_file(const char *name, size_t *length)
{
	char path[1024];
	snprintf(path, sizeof(path), "%s/%s", g_directory, name);
	FILE *file = fopen(path, "rb");
	if (file == NULL) {
		perror(path);
		exit(2);
	}
	fseek(file, 0, SEEK_END);
	long size = ftell(file);
	fseek(file, 0, SEEK_SET);
	unsigned char *data = malloc((size_t)size + 1);
	if (data == NULL || fread(data, 1, (size_t)size, file) != (size_t)size)
		exit(2);
	fclose(file);
	data[size] = '\0';
	*length = (size_t)size;
	return data;
}

/* A PEM file's first certificate, read as libhttp reads a game's CA list */
static void *read_certificate(const char *name)
{
	size_t length;
	unsigned char *text = read_file(name, &length);
	int used = 0;
	void *cert = cellSsl_9447404F(text, text + length, &used);
	free(text);
	if (cert == NULL)
		fprintf(stderr, "%s: not a certificate\n", name);
	return cert;
}

/* SSL-C's BER item, as libhttp reads it (certificate.c's) */
typedef struct BerItem {
	uint32_t length;
	const unsigned char *data;
	unsigned char unused, header[23];
	uint32_t tag;
	unsigned char flags, header_length, more_flags, reserved;
} BerItem;

/* What libhttp's check found, and the CA it trusts (its game's list) */
static void *g_trusted;
static int g_check_calls, g_check_chain, g_check_refuses;

/* libhttp's check (0x25088), as it goes: the host name from the read BIO (123), subjectAltName's
 * names against it, the dates against now, the issuer among its CAs, the signature with the CA's key,
 * and the CA's basicConstraints */
static int libhttp_check(void *ssl, void *certificates[], int count, void *argument, int *reason)
{
	++g_check_calls;
	g_check_chain = count;
	CHECK(argument == &g_check_argument);
	void *bio = SSL_get_rbio(ssl);
	const char *host = BIO_ptr_ctrl(bio, 123, 0);
	CHECK(host != NULL && strcmp(host, "chain.test") == 0);
	CHECK(BIO_get_cb_arg(bio) != NULL);
	void *leaf = certificates[0];

	int matched = 0;
	const unsigned char *names = NULL;
	int length = 0;
	if (SSLCERT_get_extension(leaf, "\x55\x1d\x11", NULL, &names, &length) == 1) {
		BerItem item;
		CHECK_EQ(BER_read_item(&item, names, (unsigned)length), 0);
		int left = length - item.header_length;
		const unsigned char *at = item.data;
		while (left > 0 && BER_read_item(&item, at, (unsigned)left) == 0) {
			if (item.length == strlen(host) && memcmp(item.data, host, item.length) == 0)
				matched = 1;
			left -= (int)(item.header_length + item.length);
			at += item.header_length + item.length;
		}
	}
	CHECK(matched);

	void *now = R_time_new();
	CHECK(now != NULL);
	int type = 0;
	const unsigned char *date = NULL;
	void *after = R_time_new(), *before = R_time_new();
	CHECK_EQ(SSLCERT_get_notAfter(leaf, &type, &date, &length), 1);
	CHECK_EQ(R_time_import(date, length, type, after), 0);
	CHECK_EQ(SSLCERT_get_notBefore(leaf, &type, &date, &length), 1);
	CHECK_EQ(R_time_import(date, length, type, before), 0);
	CHECK_EQ(R_time_cmp(now, after), -1);
	/* The certificate was made moments ago: valid from that second on */
	CHECK(R_time_cmp(before, now) <= 0);
	R_time_free(now);
	R_time_free(after);
	R_time_free(before);

	CHECK_EQ(SSLCERT_NAME_cmp(SSLCERT_get_issuer_name(leaf), SSLCERT_get_subject_name(g_trusted)), 0);
	CHECK_EQ(SSLCERT_verify(leaf, SSLCERT_get_pubkey(g_trusted)), 1);
	int critical = 0, path = 10, ca = 0;
	CHECK_EQ(SSLCERT_get_basic_constraints_int(g_trusted, &critical, &path, &ca), 1);
	/* The BOOLEAN's own byte, as Sony's */
	CHECK_EQ(ca, 0xFF);
	CHECK_EQ(critical, 1);
	CHECK_EQ(cellSsl_2E8CC56D(leaf), 0);
	if (g_check_refuses) {
		*reason = 10;
		return 0;
	}
	return 1;
}

static void test_certificates(void)
{
	/* A game's CA list: the CA, then text that isn't one, which ends the list (reason 108) */
	size_t length;
	unsigned char *ca_text = read_file("ca.pem", &length);
	char *list = malloc(length + 32);
	memcpy(list, ca_text, length);
	strcpy(list + length, "\n# the end\n");
	size_t list_length = strlen(list);
	int used = 0;
	void *ca = cellSsl_9447404F((unsigned char *)list, (unsigned char *)list + list_length, &used);
	CHECK(ca != NULL);
	CHECK(used > 0 && (size_t)used < list_length && list[used] == '\n');
	int used_first = used;
	ERR_clear_error();
	CHECK(cellSsl_9447404F((unsigned char *)list + used, (unsigned char *)list + list_length, &used) == NULL);
	CHECK_EQ(ERR_peek_error() & 0xFFF, 108);
	CHECK_EQ(ERR_get_error() >> 24, 9);
	/* A block that isn't a certificate Mbed TLS reads (as Sony's MD2-signed roots aren't) is stepped
	 * over, and the next given, used counting both */
	static const char unreadable[] = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
	char *both = malloc(sizeof(unreadable) + strlen(list) + 1);
	strcpy(both, unreadable);
	strcat(both, list);
	int both_used = 0;
	void *second = cellSsl_9447404F((unsigned char *)both, (unsigned char *)both + strlen(both), &both_used);
	CHECK(second != NULL);
	CHECK_EQ(both_used, (int)(sizeof(unreadable) - 1) + used_first);
	CHECK_EQ(SSLCERT_NAME_cmp(SSLCERT_get_subject_name(second), SSLCERT_get_subject_name(ca)), 0);
	SSLCERT_free(second);
	free(both);
	free(list);
	free(ca_text);

	/* Its names: O and CN */
	void *subject = SSLCERT_get_subject_name(ca);
	CHECK(subject != NULL);
	CHECK(SSLCERT_get_subject_name(NULL) == NULL);
	CHECK_EQ(SSLCERT_NAME_get_entry_count(subject), 2);
	CHECK_EQ(SSLCERT_NAME_get_entry_count(NULL), 0);
	CHECK(SSLCERT_NAME_get_entry(subject, 2) == NULL);
	CHECK(SSLCERT_NAME_get_entry(subject, -1) == NULL);
	void *entry = SSLCERT_NAME_get_entry(subject, 1);
	int tag = 0, oid_length = 0, value_type = 0, value_length = 0;
	const unsigned char *oid = NULL, *value = NULL;
	CHECK_EQ(SSLCERT_NAME_ENTRY_get_info(entry, &tag, &oid, &oid_length, &value_type, &value, &value_length), 1);
	CHECK_EQ(tag, 6);
	CHECK(oid_length == 3 && memcmp(oid, "\x55\x04\x03", 3) == 0);
	CHECK(strcmp(SSLCERT_OID_to_string(oid, oid_length, 0), "commonName") == 0);
	CHECK(strcmp(SSLCERT_OID_to_string(oid, oid_length, 1), "CN") == 0);
	CHECK(SSLCERT_OID_to_string((const unsigned char *)"\x55\x04\x09", 3, 0) == NULL);
	CHECK_EQ(value_type, 12);
	CHECK(value_length == 18 && memcmp(value, "vitals-ssl test CA", 18) == 0);
	CHECK_EQ(SSLCERT_NAME_ENTRY_get_info(entry, NULL, NULL, NULL, NULL, NULL, NULL), 1);
	CHECK_EQ(SSLCERT_NAME_hash(subject), g_ca_hash);
	CHECK_EQ(SSLCERT_NAME_cmp(subject, SSLCERT_get_issuer_name(ca)), 0);

	/* Its dates, and times */
	int type = 0;
	const unsigned char *date = NULL;
	CHECK_EQ(SSLCERT_get_notAfter(ca, &type, &date, &length == NULL ? NULL : &value_length), 1);
	CHECK_EQ(type, 23);
	CHECK(value_length == 13 && date[12] == 'Z');
	void *time = R_time_new();
	CHECK_EQ(R_time_import(date, value_length, type, time), 0);
	unsigned char text[32];
	CHECK_EQ(R_time_export(time, 23, text, sizeof(text)), 0);
	CHECK(memcmp(text, date, 13) == 0 && text[13] == '\0');
	CHECK_EQ(R_time_export(time, 24, text, sizeof(text)), 0);
	CHECK(strlen((char *)text) == 15 && memcmp(text, "20", 2) == 0);
	CHECK_EQ(R_time_export(time, 23, text, 13), 10006);
	CHECK_EQ(R_time_import(date, value_length, type, NULL), 10017);
	CHECK_EQ(R_time_import((const unsigned char *)"99130100000Z", 12, 23, time), 10001);
	CHECK_EQ(R_time_import((const unsigned char *)"20240229235959Z", 15, 24, time), 0);
	void *other = R_time_new();
	CHECK_EQ(R_time_cmp(time, other), -1);
	CHECK_EQ(R_time_cmp(other, time), 1);
	CHECK_EQ(R_time_cmp(time, time), 0);
	CHECK_EQ(R_time_export(time, 24, text, sizeof(text)), 0);
	CHECK(strcmp((char *)text, "20240229235959Z") == 0);
	R_time_free(time);
	R_time_free(other);

	/* BER items */
	BerItem item;
	CHECK_EQ(BER_read_item(&item, (const unsigned char *)"\x30\x03\x02\x01\x05", 5), 0);
	CHECK_EQ(item.length, 3);
	CHECK_EQ(item.header_length, 2);
	CHECK_EQ(item.tag, 16);
	CHECK_EQ(item.flags, 0x20);
	/* A long length, and as Sony's, at least one byte after the header */
	CHECK_EQ(BER_read_item(&item, (const unsigned char *)"\x04\x82\x01\x00", 4), 2);
	CHECK_EQ(BER_read_item(&item, (const unsigned char *)"\x04\x82\x01\x00\x00", 5), 0);
	CHECK_EQ(item.length, 256);
	CHECK_EQ(item.header_length, 4);
	CHECK_EQ(BER_read_item(&item, (const unsigned char *)"\x30", 1), 2);
	CHECK_EQ(BER_read_item(&item, (const unsigned char *)"\x04\x85\x01\x00\x00\x00\x00\x00", 8), 3);

	/* Extensions: the CA's basicConstraints, and no subjectAltName; the leaf's subjectAltName */
	const unsigned char *names = NULL;
	CHECK_EQ(SSLCERT_get_extension(ca, "\x55\x1d\x11", NULL, &names, &value_length), 0);
	void *leaf = read_certificate("leaf.pem");
	int critical = 1;
	CHECK_EQ(SSLCERT_get_extension(leaf, "\x55\x1d\x11", &critical, &names, &value_length), 1);
	CHECK_EQ(critical, 0);
	CHECK(names != NULL && names[0] == 0x30);
	int path = 10, is_ca = 1;
	CHECK_EQ(SSLCERT_get_basic_constraints_int(leaf, &critical, &path, &is_ca), 1);
	CHECK_EQ(is_ca, 0);
	CHECK_EQ(path, 10);

	/* Signatures: the CA signed the leaf, not the other way round */
	CHECK_EQ(SSLCERT_verify(leaf, SSLCERT_get_pubkey(ca)), 1);
	CHECK_EQ(SSLCERT_verify(ca, SSLCERT_get_pubkey(leaf)), 0);
	CHECK_EQ(SSLCERT_verify(leaf, NULL), -1);
	CHECK(SSLCERT_get_pubkey(ca) == SSLCERT_get_pubkey(ca));
	/* A certificate's own key stays the certificate's */
	EVP_PKEY_free(SSLCERT_get_pubkey(ca));
	CHECK_EQ(SSLCERT_verify(leaf, SSLCERT_get_pubkey(ca)), 1);
	CHECK_EQ(cellSsl_2E8CC56D(ca), 0);
	SSLCERT_free(leaf);
	SSLCERT_free(ca);
	SSLCERT_free(NULL);
}

/* libhttp's check on a connection: called once with the server's chain, the server's certificate
 * first; when it refuses, no connection (SSL_get_error 1) */
static void test_verify_chain(void)
{
	/* The debug log's check of where the issuer is reads Mozilla's bundle, whose index stays until
	 * cellSslEnd (as libhttp's own lookups keep it): built here first, so the connections below
	 * are still seen giving all their memory back */
	void *ca = read_certificate("ca.pem");
	size_t required = 0;
	(void)cellSsl_68D3409E(SSLCERT_get_issuer_name(ca), NULL, 0, &required, 1);
	SSLCERT_free(ca);
	g_between_connections = vs_test_pool_used;
	g_trusted = read_certificate("ca.pem");
	g_check = libhttp_check;
	Connection connection;
	CHECK_EQ(libhttp_connect(&connection, g_port + 2, "chain.test", 1, 0), 1);
	CHECK_EQ(g_check_calls, 1);
	CHECK_EQ(g_check_chain, 2);
	char line[256];
	CHECK(read_line(connection.ssl, line, sizeof(line)) > 0);
	CHECK(strcmp(line, "sni=chain.test\n") == 0);
	libhttp_close(&connection);
	g_check_refuses = 1;
	CHECK_EQ(libhttp_connect(&connection, g_port + 2, "chain.test", 1, 0), -KIND_SSL);
	CHECK_EQ(g_check_calls, 2);
	libhttp_close(&connection);
	g_check_refuses = 0;
	g_check = NULL;
	SSLCERT_free(g_trusted);
	ERR_clear_error();
	CHECK_EQ(vs_test_pool_used, g_between_connections);
}

/* libhttp's client certificate (0x26058): the key written into a memory BIO a byte at a time, read
 * back, matched with its certificate, and given to the context */
static void test_client_key(void)
{
	size_t length;
	unsigned char *key_text = read_file("client.key", &length);
	void *bio = BIO_new_mem();
	CHECK(bio != NULL);
	CHECK_EQ(BIO_ctrl(bio, 1, 0, NULL), 1);
	for (size_t i = 0; i < length; ++i)
		CHECK_EQ(BIO_printf(bio, "%c", key_text[i]), 1);
	CHECK_EQ(BIO_ctrl(bio, 10, 0, NULL), (long)length);
	void *key = _cellSslPemReadPrivateKey(bio);
	CHECK(key != NULL);
	CHECK(_cellSslPemReadPrivateKey(NULL) == NULL);
	CHECK_EQ(BIO_ctrl(bio, 1, 0, NULL), 1);
	CHECK_EQ(BIO_ctrl(bio, 2, 0, NULL), 1);
	CHECK(_cellSslPemReadPrivateKey(bio) == NULL);
	CHECK_EQ(BIO_free(bio), 1);
	free(key_text);
	void *client = read_certificate("client.pem"), *ca = read_certificate("ca.pem");
	CHECK_EQ(SSLCERT_check_private_key(client, key), 1);
	CHECK_EQ(SSLCERT_check_private_key(ca, key), 0);
	void *context = SSL_CTX_new(TLSv1_client_method());
	CHECK_EQ(SSL_CTX_use_certificate(context, client), 1);
	CHECK_EQ(SSL_CTX_use_PrivateKey(context, key), 1);
	CHECK_EQ(SSL_CTX_use_certificate(context, NULL), 0);
	EVP_PKEY_free(key);
	SSLCERT_free(client);
	SSLCERT_free(ca);
	SSL_CTX_free(context);
	CHECK_EQ(vs_test_pool_used, g_between_connections);
}

/* The public functions games call, on the CA's certificate */
static void test_public(void)
{
	void *ca = read_certificate("ca.pem");
	const unsigned char *data = NULL;
	size_t length = 0;
	CHECK_EQ(cellSslCertGetSerialNumber(ca, &data, &length), 0);
	CHECK(data != NULL && length > 0 && length <= 21);
	CHECK_EQ(cellSslCertGetSerialNumber(ca, NULL, &length), (int)0x80740004);
	CHECK_EQ(cellSslCertGetSerialNumber(NULL, &data, &length), (int)0x80740005);
	CHECK_EQ(cellSslCertGetPublicKey(ca, &data, &length), 0);
	CHECK(data[0] == 0x30 && length > 256);
	CHECK_EQ(cellSslCertGetRsaPublicKeyModulus(ca, &data, &length), 0);
	CHECK(length == 257 && data[0] == 0x00);
	CHECK_EQ(cellSslCertGetRsaPublicKeyExponent(ca, &data, &length), 0);
	CHECK(length == 3 && memcmp(data, "\x01\x00\x01", 3) == 0);

	/* Two days apart, as run_tests.py makes it, in microseconds since 0001-01-01 */
	uint64_t before = 0, after = 0;
	CHECK_EQ(cellSslCertGetNotBefore(ca, &before), 0);
	CHECK_EQ(cellSslCertGetNotAfter(ca, &after), 0);
	CHECK_EQ(after - before, UINT64_C(2) * 86400 * 1000000);
	CHECK(before > UINT64_C(0x00DCBFFEFF2BC000));
	CHECK_EQ(cellSslCertGetNotAfter(ca, NULL), (int)0x80740004);

	void *name = NULL;
	CHECK_EQ(cellSslCertGetSubjectName(ca, &name), 0);
	uint32_t count = 0;
	CHECK_EQ(cellSslCertGetNameEntryCount(name, &count), 0);
	CHECK_EQ(count, 2);
	const char *type = NULL;
	CHECK_EQ(cellSslCertGetNameEntryInfo(name, 1, &type, &data, &length, 0), 0);
	CHECK(strcmp(type, "commonName") == 0 && length == 18 && memcmp(data, "vitals-ssl test CA", 18) == 0);
	CHECK_EQ(cellSslCertGetNameEntryInfo(name, 0, &type, &data, &length, 1), 0);
	CHECK(strcmp(type, "O") == 0);
	CHECK_EQ(cellSslCertGetNameEntryInfo(name, 2, &type, &data, &length, 0), (int)0x80740006);
	CHECK_EQ(cellSslCertGetIssuerName(ca, &name), 0);
	char line[128];
	CHECK(strcmp(SSLCERT_NAME_oneline(name, line, sizeof(line)), "/O=vitals-ssl/CN=vitals-ssl test CA") == 0);

	unsigned char digest[20];
	uint32_t digest_length = 0;
	CHECK_EQ(cellSslCertGetMd5Fingerprint(ca, digest, &digest_length), 0);
	CHECK_EQ(digest_length, 16);
	/* sha256WithRSAEncryption, as OpenSSL numbers it */
	CHECK_EQ(cellSsl_C132E990(ca), 130);
	uint32_t free_size = 0, arena = 0, info[10];
	CHECK_EQ(cellSslGetMemoryInfo(&free_size, &arena, info), 0);
	CHECK(free_size > 0 && arena == sizeof(g_pool) && info[0] == arena);
	SSLCERT_free(ca);

	CHECK(strcmp(SSL_alert_type_string_long(2 << 8 | 42), "fatal") == 0);
	CHECK(strcmp(SSL_alert_desc_string_long(2 << 8 | 42), "bad certificate") == 0);
	CHECK(strcmp(SSL_alert_desc_string_long(70), "unknown") == 0);
	char error[256];
	CHECK(strcmp(ERR_error_string(20ul << 24 | 168ul << 12 | 196, error), "error:140A80C4:SSL routines:func(168):reason(196)") == 0);
	CHECK(ERR_func_error_string(20ul << 24) == NULL);
	CHECK(cellSsl_F422A5AB() != NULL && cellSsl_F422A5AB() != TLSv1_client_method());
	CHECK_EQ(cellSsl_4EE83087(1, 2), 0);
	cellSsl_E95B6A4C();
	CHECK_EQ(vs_test_pool_used, g_between_connections);
}

/* ---- the CA store ---- */

#define CA_UNKNOWN ((int)0x80740037)
#define CA_NO_BUFFER ((int)0x80740004)
#define CA_TOO_SMALL ((int)0x80740035)

/* The CA PEM 68D3409E gives for the name and mask: its size first, then it, which is compared
 * with expected (expected_length bytes) and parsed as libhttp parses it */
static void check_ca_by_name(const void *name, uint64_t mask, const unsigned char *expected, size_t expected_length)
{
	size_t required = 1;
	CHECK_EQ(cellSsl_68D3409E(name, NULL, 0, &required, mask), 0);
	CHECK_EQ(required, expected_length);
	char *buffer = malloc(expected_length + 1);
	CHECK_EQ(cellSsl_68D3409E(name, buffer, required - 1, &required, mask), CA_TOO_SMALL);
	CHECK_EQ(required, expected_length);
	required = 0;
	CHECK_EQ(cellSsl_68D3409E(name, buffer, expected_length + 1, &required, mask), 0);
	CHECK_EQ(required, expected_length);
	CHECK(memcmp(buffer, expected, expected_length) == 0 && buffer[expected_length] == '\0');
	CHECK_EQ(cellSsl_68D3409E(name, buffer, expected_length, NULL, mask), 0);
	int used = 0;
	void *ca = cellSsl_9447404F((unsigned char *)buffer, (unsigned char *)buffer + expected_length, &used);
	CHECK(ca != NULL);
	CHECK_EQ(SSLCERT_NAME_cmp(SSLCERT_get_subject_name(ca), name), 0);
	SSLCERT_free(ca);
	free(buffer);
}

/* With the console's own CA files: what Sony's table says of them */
static void test_sony_cas(void)
{
	size_t ca01_length, ca02_length, list_length, ca06_length;
	unsigned char *ca01 = read_file("sony/CA01.cer", &ca01_length);
	unsigned char *ca02 = read_file("sony/CA02.cer", &ca02_length);
	unsigned char *ca06 = read_file("sony/CA06.cer", &ca06_length);
	unsigned char *list = read_file("sony/CA_LIST.cer", &list_length);

	/* CA01 and CA02, one after the other */
	size_t required = 0;
	CHECK_EQ(cellSslCertificateLoader(3, NULL, 0, &required), 0);
	CHECK_EQ(required, ca01_length + ca02_length);
	char *buffer = malloc(ca01_length + ca02_length + 1);
	CHECK_EQ(cellSslCertificateLoader(3, buffer, ca01_length + ca02_length - 1, &required), CA_TOO_SMALL);
	CHECK_EQ(required, ca01_length + ca02_length);
	CHECK_EQ(cellSslCertificateLoader(3, buffer, ca01_length + ca02_length + 1, &required), 0);
	CHECK(memcmp(buffer, ca01, ca01_length) == 0 && memcmp(buffer + ca01_length, ca02, ca02_length) == 0);
	CHECK_EQ(buffer[ca01_length + ca02_length], 0);
	free(buffer);

	/* CA01 has flag 16: only a mask with its bit gets it */
	int used = 0, flag = 0;
	uint64_t mask = 0;
	void *ca = cellSsl_9447404F(ca01, ca01 + ca01_length, &used);
	CHECK(ca != NULL);
	void *name = SSLCERT_get_subject_name(ca);
	CHECK_EQ(cellSsl_205B060C(name, &mask, &flag), 0);
	CHECK_EQ(mask, 1);
	CHECK_EQ(flag, 16);
	CHECK_EQ(cellSsl_68D3409E(name, NULL, 0, &required, 2), CA_UNKNOWN);
	check_ca_by_name(name, 1, ca01, ca01_length);
	SSLCERT_free(ca);

	/* CA06 has no flag, but a mask of CA01 to CA05's bits alone gets only them */
	ca = cellSsl_9447404F(ca06, ca06 + ca06_length, &used);
	name = SSLCERT_get_subject_name(ca);
	CHECK_EQ(cellSsl_205B060C(name, &mask, &flag), 0);
	CHECK_EQ(mask, 0x20);
	CHECK_EQ(flag, 0);
	CHECK_EQ(cellSsl_68D3409E(name, NULL, 0, &required, 1), CA_UNKNOWN);
	check_ca_by_name(name, 0x40, ca06, ca06_length);
	SSLCERT_free(ca);

	/* CA_LIST.cer's first, mask 0: its part of the file */
	ca = cellSsl_9447404F(list + 25, list + list_length, &used);
	CHECK(ca != NULL);
	name = SSLCERT_get_subject_name(ca);
	mask = 5;
	flag = 5;
	CHECK_EQ(cellSsl_205B060C(name, &mask, &flag), 0);
	CHECK_EQ(mask, 0);
	CHECK_EQ(flag, 0);
	CHECK_EQ(cellSsl_68D3409E(name, NULL, 0, &required, 0x1F), CA_UNKNOWN);
	check_ca_by_name(name, UINT64_C(1) << 40, list + 25, 1224);
	SSLCERT_free(ca);

	/* The games Sony's knows get CA05 alone */
	size_t ca05_length;
	unsigned char *ca05 = read_file("sony/CA05.cer", &ca05_length);
	memcpy(vs_test_title_id, "BLUS31193", 10);
	CHECK_EQ(cellSslCertificateLoader(3, NULL, 0, &required), 0);
	CHECK_EQ(required, ca05_length);
	memset(vs_test_title_id, 0, 10);
	free(ca05);

	free(ca01);
	free(ca02);
	free(ca06);
	free(list);
}

static void test_ca_store(void)
{
	snprintf(vs_test_sony_cert_directory, sizeof(vs_test_sony_cert_directory), "%s/sony", g_directory);
	snprintf(vs_test_bundle_path, sizeof(vs_test_bundle_path), "%s/bundle.pem", g_directory);
	snprintf(vs_test_custom_path, sizeof(vs_test_custom_path), "%s/custom.pem", g_directory);
	vs_ca_store_end();
	memset(vs_test_title_id, 0, 10);
	char path[1024];
	snprintf(path, sizeof(path), "%s/sony/CA_LIST.cer", g_directory);
	int sony = access(path, R_OK) == 0;

	/* The loader's arguments, and bits no CA has */
	size_t required = 7;
	CHECK_EQ(cellSslCertificateLoader(1, NULL, 0, NULL), CA_NO_BUFFER);
	CHECK_EQ(cellSslCertificateLoader(0, NULL, 0, &required), 0);
	CHECK_EQ(required, 0);
	CHECK_EQ(cellSslCertificateLoader(UINT64_C(1) << 63, NULL, 0, &required), CA_UNKNOWN);
	CHECK_EQ(required, 0);

	/* The games Sony's knows: the loader gives them CA05 whatever their flags, and their mask
	 * becomes those flags; others' stays */
	memcpy(vs_test_title_id, "NPUA80661", 10);
	CHECK_EQ(cellSslCertificateLoader(UINT64_C(1) << 63 | 2, NULL, 0, &required), 0);
	uint64_t mask = 0x123;
	CHECK_EQ(cellSsl_CC6A0CB5(&mask), 0);
	CHECK_EQ(mask, UINT64_C(1) << 63 | 2);
	memset(vs_test_title_id, 0, 10);
	mask = 0x123;
	CHECK_EQ(cellSsl_CC6A0CB5(&mask), 0);
	CHECK_EQ(mask, 0x123);

	/* A name that isn't Sony's has mask and flag 0, which libhttp's check accepts */
	void *ca = read_certificate("ca.pem");
	void *name = SSLCERT_get_subject_name(ca);
	int flag = 3;
	mask = 3;
	CHECK_EQ(cellSsl_205B060C(name, &mask, NULL), CA_NO_BUFFER);
	CHECK_EQ(cellSsl_205B060C(name, NULL, &flag), CA_NO_BUFFER);
	CHECK_EQ(cellSsl_205B060C(name, &mask, &flag), 0);
	CHECK_EQ(mask, 0);
	CHECK_EQ(flag, 0);

	/* Mozilla's bundle: a root as the file has it, its lines LF or CRLF, whatever the mask */
	CHECK_EQ(cellSsl_68D3409E(name, NULL, 0, NULL, 1), CA_NO_BUFFER);
	size_t length;
	unsigned char *text = read_file("ca.pem", &length);
	check_ca_by_name(name, 1, text, length);
	free(text);
	SSLCERT_free(ca);
	ca = read_certificate("server-crlf.pem");
	text = read_file("server-crlf.pem", &length);
	check_ca_by_name(SSLCERT_get_subject_name(ca), 0, text, length);
	free(text);
	SSLCERT_free(ca);
	/* The user's custom-certs.pem, read after Mozilla's as they wrote it: its mistakes skipped */
	ca = read_certificate("client.pem");
	text = read_file("client.pem", &length);
	check_ca_by_name(SSLCERT_get_subject_name(ca), 0, text, length);
	free(text);
	/* Without it (missing), Mozilla's file is still the store */
	vs_ca_store_end();
	snprintf(vs_test_custom_path, sizeof(vs_test_custom_path), "%s/missing-custom.pem", g_directory);
	CHECK_EQ(cellSsl_68D3409E(SSLCERT_get_subject_name(ca), NULL, 0, &required, ~UINT64_C(0)), CA_UNKNOWN);
	SSLCERT_free(ca);
	ca = read_certificate("ca.pem");
	text = read_file("ca.pem", &length);
	check_ca_by_name(SSLCERT_get_subject_name(ca), 1, text, length);
	free(text);
	SSLCERT_free(ca);
	/* Nor Mozilla's: the user's alone */
	vs_ca_store_end();
	snprintf(vs_test_bundle_path, sizeof(vs_test_bundle_path), "%s/missing-bundle.pem", g_directory);
	snprintf(vs_test_custom_path, sizeof(vs_test_custom_path), "%s/custom.pem", g_directory);
	ca = read_certificate("client.pem");
	text = read_file("client.pem", &length);
	check_ca_by_name(SSLCERT_get_subject_name(ca), 0, text, length);
	free(text);
	SSLCERT_free(ca);
	vs_ca_store_end();
	snprintf(vs_test_bundle_path, sizeof(vs_test_bundle_path), "%s/bundle.pem", g_directory);
	/* A name in neither */
	ca = read_certificate("leaf.pem");
	CHECK_EQ(cellSsl_68D3409E(SSLCERT_get_subject_name(ca), NULL, 0, &required, ~UINT64_C(0)), CA_UNKNOWN);
	CHECK_EQ(required, 0);
	SSLCERT_free(ca);

	if (sony) {
		test_sony_cas();
	} else {
		/* Stand-ins for Sony's files: their size, but not what the table says */
		char buffer[64];
		CHECK_EQ(cellSslCertificateLoader(2, NULL, 0, &required), 0);
		CHECK_EQ(required, 9);
		CHECK_EQ(cellSslCertificateLoader(2, buffer, sizeof(buffer), &required), CA_UNKNOWN);
		CHECK_EQ(required, 9);
		memcpy(vs_test_title_id, "BCAS20160", 10);
		CHECK_EQ(cellSslCertificateLoader(2, NULL, 0, &required), 0);
		CHECK_EQ(required, 9);
		memset(vs_test_title_id, 0, 10);
		/* CA01 isn't there */
		CHECK_EQ(cellSslCertificateLoader(1, NULL, 0, &required), CA_UNKNOWN);
		fprintf(stderr, "ca store: Sony's CA files aren't here (dumps/ps3/4.93-cex/cert): only stand-ins tested\n");
	}
}

/* The CA store's other three (06B1E9BF, 404136C1, 86C38810), with CA02 and CA05, which are there
 * as Sony's files or their stand-ins */
static void test_ca_reading(void)
{
	CHECK_EQ(cellSsl_404136C1(0), 0);
	CHECK_EQ(cellSsl_404136C1(0x12), 0);
	CHECK_EQ(cellSsl_404136C1((UINT64_C(1) << 59) - 1), 0);
	CHECK_EQ(cellSsl_404136C1(UINT64_C(1) << 59), CA_UNKNOWN);
	CHECK_EQ(cellSsl_404136C1(UINT64_C(1) << 63 | 1), CA_UNKNOWN);

	size_t ca02_length, ca05_length;
	unsigned char *ca02 = read_file("sony/CA02.cer", &ca02_length), *ca05 = read_file("sony/CA05.cer", &ca05_length);

	/* 06B1E9BF: the loader, but a listed game still gets CA02, and CC6A0CB5 keeps the loader's flags */
	memcpy(vs_test_title_id, "BLUS31193", 10);
	size_t required = 0;
	CHECK_EQ(cellSslCertificateLoader(6, NULL, 0, &required), 0);
	CHECK_EQ(required, ca05_length);
	CHECK_EQ(cellSsl_06B1E9BF(2, NULL, 0, &required), 0);
	CHECK_EQ(required, ca02_length);
	char *buffer = calloc(1, ca02_length + 1);
	(void)cellSsl_06B1E9BF(2, buffer, ca02_length + 1, &required);
	CHECK(memcmp(buffer, ca02, ca02_length) == 0);
	free(buffer);
	uint64_t mask = 0;
	CHECK_EQ(cellSsl_CC6A0CB5(&mask), 0);
	CHECK_EQ(mask, 6);
	memset(vs_test_title_id, 0, 10);
	CHECK_EQ(cellSsl_06B1E9BF(2, NULL, 0, NULL), CA_NO_BUFFER);
	CHECK_EQ(cellSsl_06B1E9BF(UINT64_C(1) << 63, NULL, 0, &required), CA_UNKNOWN);

	/* 86C38810: one CA a call, in the table's order, through a few bytes at a time */
	void *bio = BIO_new_mem();
	char chunk[7];
	uint64_t flags = 0x12;
	CHECK_EQ(cellSsl_86C38810(&flags, bio, chunk, sizeof(chunk)), 0);
	CHECK_EQ(flags, 0x10);
	unsigned char *data = NULL;
	CHECK_EQ(BIO_ctrl(bio, 3, 0, &data), (long)ca02_length);
	CHECK(data != NULL && memcmp(data, ca02, ca02_length) == 0);
	CHECK_EQ(cellSsl_86C38810(&flags, bio, chunk, sizeof(chunk)), 0);
	CHECK_EQ(flags, 0);
	CHECK_EQ(BIO_ctrl(bio, 3, 0, &data), (long)(ca02_length + ca05_length));
	CHECK(data != NULL && memcmp(data + ca02_length, ca05, ca05_length) == 0);
	/* No CA with the bits: nothing written, the flags as they were */
	CHECK_EQ(cellSsl_86C38810(&flags, bio, chunk, sizeof(chunk)), 0);
	flags = UINT64_C(1) << 63;
	CHECK_EQ(cellSsl_86C38810(&flags, bio, chunk, sizeof(chunk)), 0);
	CHECK_EQ(flags, UINT64_C(1) << 63);
	CHECK_EQ(BIO_ctrl(bio, 10, 0, NULL), (long)(ca02_length + ca05_length));
	CHECK_EQ(cellSsl_86C38810(NULL, bio, chunk, sizeof(chunk)), CA_NO_BUFFER);
	flags = 2;
	CHECK_EQ(cellSsl_86C38810(&flags, bio, NULL, sizeof(chunk)), CA_NO_BUFFER);
	CHECK_EQ(cellSsl_86C38810(&flags, bio, chunk, 0), CA_NO_BUFFER);
	CHECK_EQ(cellSsl_86C38810(&flags, NULL, chunk, sizeof(chunk)), CA_TOO_SMALL);
	CHECK_EQ(flags, 2);
	CHECK_EQ(BIO_free(bio), 1);
	free(ca02);
	free(ca05);
}

/* 597BE64A: the CA key's signatures of signed.txt (run_tests.py's) */
static void test_rsa_verify(void)
{
	void *ca = read_certificate("ca.pem");
	void *key = SSLCERT_get_pubkey(ca);
	CHECK(key != NULL);
	size_t length, sha256_length, sha1_length;
	unsigned char *text = read_file("signed.txt", &length);
	unsigned char *sha256 = read_file("signed.sha256", &sha256_length), *sha1 = read_file("signed.sha1", &sha1_length);
	CHECK_EQ(cellSsl_597BE64A(130, text, (uint32_t)length, sha256, (uint32_t)sha256_length, key), 1);
	CHECK_EQ(cellSsl_597BE64A(65, text, (uint32_t)length, sha1, (uint32_t)sha1_length, key), 1);
	/* Another hash, other data, a signature cut short or changed, no key */
	CHECK_EQ(cellSsl_597BE64A(65, text, (uint32_t)length, sha256, (uint32_t)sha256_length, key), 0);
	CHECK_EQ(cellSsl_597BE64A(131, text, (uint32_t)length, sha256, (uint32_t)sha256_length, key), 0);
	CHECK_EQ(cellSsl_597BE64A(130, text, (uint32_t)length - 1, sha256, (uint32_t)sha256_length, key), 0);
	CHECK_EQ(cellSsl_597BE64A(130, text, (uint32_t)length, sha256, (uint32_t)sha256_length - 1, key), 0);
	sha256[10] ^= 1;
	CHECK_EQ(cellSsl_597BE64A(130, text, (uint32_t)length, sha256, (uint32_t)sha256_length, key), 0);
	CHECK_EQ(cellSsl_597BE64A(130, text, (uint32_t)length, sha256, (uint32_t)sha256_length, NULL), 0);
	CHECK_EQ(cellSsl_597BE64A(130, text, (uint32_t)length, NULL, (uint32_t)sha256_length, key), 0);
	/* MD2 (7) is Sony's, not Mbed TLS's; 6 is the key type, not a signature */
	CHECK_EQ(cellSsl_597BE64A(7, text, (uint32_t)length, sha1, (uint32_t)sha1_length, key), 0);
	CHECK_EQ(cellSsl_597BE64A(6, text, (uint32_t)length, sha1, (uint32_t)sha1_length, key), 0);
	free(text);
	free(sha256);
	free(sha1);
	SSLCERT_free(ca);
}

/* The XMB loads Sony's CAs with no cellSslInit before (and again after cellSslEnd): writing them
 * must work then too, SHA-1 check and all. PSA's hash doesn't work outside init, which signed the
 * console out of PSN */
static void test_loader_without_init(const char *when)
{
	size_t ca01_length = 0, required = 0;
	unsigned char *ca01 = read_file("sony/CA01.cer", &ca01_length);
	char *buffer = malloc(ca01_length + 1);
	int rc = cellSslCertificateLoader(1, buffer, ca01_length + 1, &required);
	if (rc != 0)
		printf("loader %s: 0x%08x\n", when, (unsigned)rc);
	CHECK_EQ(rc, 0);
	CHECK_EQ(required, ca01_length);
	CHECK(memcmp(buffer, ca01, ca01_length) == 0);
	free(buffer);
	free(ca01);
}

/* Every CA the loader knows, one mask bit at a time, as it writes them before cellSslInit, during
 * it and after cellSslEnd: the same bytes each time, and every one that has a size can be written */
typedef struct LoadedCas {
	int rc[64];
	size_t length[64];
	char *data[64];
} LoadedCas;

static void load_every_ca(LoadedCas *loaded)
{
	for (int bit = 0; bit < 64; ++bit) {
		size_t required = 0;
		loaded->data[bit] = NULL;
		loaded->length[bit] = 0;
		loaded->rc[bit] = cellSslCertificateLoader(UINT64_C(1) << bit, NULL, 0, &required);
		if (loaded->rc[bit] != 0 || required == 0)
			continue;
		loaded->length[bit] = required;
		loaded->data[bit] = malloc(required + 1);
		loaded->rc[bit] = cellSslCertificateLoader(UINT64_C(1) << bit, loaded->data[bit], required + 1, &required);
	}
}

static void check_every_ca(const char *when, const LoadedCas *loaded, const LoadedCas *reference)
{
	int written = 0;
	for (int bit = 0; bit < 64; ++bit) {
		int same = loaded->rc[bit] == reference->rc[bit] && loaded->length[bit] == reference->length[bit] &&
		           (loaded->data[bit] == NULL ||
		            memcmp(loaded->data[bit], reference->data[bit], loaded->length[bit]) == 0);
		if (!same)
			printf("loader %s: bit %d gives 0x%08x, %u bytes; during init 0x%08x, %u bytes\n", when, bit,
			       (unsigned)loaded->rc[bit], (unsigned)loaded->length[bit], (unsigned)reference->rc[bit],
			       (unsigned)reference->length[bit]);
		CHECK(same);
		written += loaded->data[bit] != NULL && loaded->rc[bit] == 0;
	}
	printf("loader %s: %d CAs written\n", when, written);
}

static void free_every_ca(LoadedCas *loaded)
{
	for (int bit = 0; bit < 64; ++bit)
		free(loaded->data[bit]);
}

int main(int argc, char **argv)
{
	if (argc != 4) {
		fprintf(stderr, "usage: %s <port> <certificates' folder> <the CA's subject hash>\n", argv[0]);
		return 2;
	}
	g_port = atoi(argv[1]);
	g_directory = argv[2];
	g_ca_hash = strtoul(argv[3], NULL, 16);
	/* The CA store's files from the start: the debug log's check of where a chain's issuer is
	 * (vs_ca_store_source) reads the bundle on the first connection, and keeps what it found */
	snprintf(vs_test_sony_cert_directory, sizeof(vs_test_sony_cert_directory), "%s/sony", g_directory);
	snprintf(vs_test_bundle_path, sizeof(vs_test_bundle_path), "%s/bundle.pem", g_directory);
	test_loader_without_init("before cellSslInit");
	static LoadedCas before, during, after;
	load_every_ca(&before);
	test_init();
	load_every_ca(&during);
	for (int bit = 0; bit < 64; ++bit)
		if (during.data[bit] != NULL)
			CHECK_EQ(during.rc[bit], 0);
	check_every_ca("before cellSslInit", &before, &during);
	test_objects();
	test_echo();
	test_drop();
	test_nonblocking();
	test_console_hello();
	test_timeout();
	test_address();
	test_verify_refused();
	test_convert();
	test_gmtime();
	test_certificates();
	test_verify_chain();
	test_client_key();
	test_public();
	test_ca_store();
	test_ca_reading();
	test_rsa_verify();
	CHECK_EQ(cellSslEnd(), 0);
	test_loader_without_init("after cellSslEnd");
	load_every_ca(&after);
	check_every_ca("after cellSslEnd", &after, &during);
	free_every_ca(&before);
	free_every_ca(&during);
	free_every_ca(&after);
	printf("%d checks, %d failed\n", g_checks, g_failures);
	return g_failures == 0 ? 0 : 1;
}
