#ifndef VITALS_SSL_VS_H
#define VITALS_SSL_VS_H

#include <mbedtls/ssl.h>

#include <stddef.h>
#include <stdint.h>

/* SSL-C's objects as Sony's libhttp uses them (the Vita's vitals-ssl/src/vs.h, for the PS3's API):
 * client methods, contexts (SSL_CTX), connections (SSL) and socket BIOs, all opaque to their
 * callers. Where Sony's PS3 libssl behaves differently from the Vita's, the function's comment says
 * so, with the address of Sony's code (dumps/ps3/4.93-cex/libssl.prx) */

/* The objects' first word, which tells them apart */
#define VS_METHOD_MAGIC 0x4D535356u
#define VS_CONTEXT_MAGIC 0x43535356u
#define VS_SSL_MAGIC 0x53535356u
#define VS_BIO_MAGIC 0x42535356u

/* SSL_get_error's kinds, as OpenSSL numbers them */
#define VS_KIND_NONE 0
#define VS_KIND_SSL 1
#define VS_KIND_WANT_READ 2
#define VS_KIND_WANT_WRITE 3
#define VS_KIND_X509_LOOKUP 4
#define VS_KIND_SYSCALL 5
#define VS_KIND_ZERO_RETURN 6

/* SSL_CTX_ctrl's session cache mode commands */
#define VS_CTRL_SET_SESS_CACHE_MODE 44
#define VS_CTRL_GET_SESS_CACHE_MODE 45

/* BIO_ctrl's commands: OpenSSL's, and Sony's host name (100 sets it, 123 reads it) */
#define VS_BIO_CTRL_GET_CLOSE 8
#define VS_BIO_CTRL_SET_CLOSE 9
#define VS_BIO_CTRL_SET_HOST 100
#define VS_BIO_C_SET_FD 104
#define VS_BIO_C_GET_FD 105
#define VS_BIO_CTRL_GET_HOST 123

/* SSL_set_info_callback's where bits, as OpenSSL numbers them */
#define VS_CB_READ 0x04
#define VS_CB_ALERT 0x4000

/* sys_net's EAGAIN: the socket would block, which Sony's socket BIO asks to retry (0xf9f8) */
#define VS_NET_EAGAIN 35

/* How the last operation on a connection failed, which SSL_get_error reports */
typedef enum VsFailure {
	VS_FAILED_NOTHING,
	VS_FAILED_WANT_READ,  /* the socket would block: EAGAIN on a receive */
	VS_FAILED_WANT_WRITE, /* or on a send */
	VS_FAILED_SOCKET,     /* any other socket error, whose errno the caller reads */
	VS_FAILED_EOF,        /* the server closed the socket */
	VS_FAILED_CLOSED,     /* the server's close_notify */
	VS_FAILED_TLS,        /* the TLS itself: a bad message, an alert, a refused certificate */
} VsFailure;

typedef struct VsMethod {
	uint32_t magic;
	/* SSL_version before a handshake, as Sony's method templates give it (0x5716c, 0x57a8c) */
	int version;
} VsMethod;

/* libhttp's certificate check, SSL_CTX_set_app_verify_cb's (0x25088): the server's chain, its
 * certificate first; 1 accepts, else it sets a reason (9, 10, 17, ...) */
typedef int (*VsVerifyCallback)(void *ssl, void *certificates[], int count, void *argument, int *reason);
typedef void (*VsInfoCallback)(const void *ssl, int where, int value);

typedef struct VsContext {
	uint32_t magic;
	const VsMethod *method;
	unsigned int references;
	uint32_t options;
	/* SSL_CTX_ctrl's: the session cache's mode and size, and SSL-C's two values 55 reads and 56
	 * sets, as Sony's SSL_CTX_new starts them (0x2df7c) */
	long cache_mode, cache_size, value_55, value_56;
	int verify_mode;
	VsVerifyCallback verify_callback;
	void *verify_argument;
	VsInfoCallback info_callback;
	/* SSL_CTX_use_certificate's and SSL_CTX_use_PrivateKey's copies, sent to a server that asks */
	mbedtls_x509_crt *own_certificate;
	mbedtls_pk_context *own_key;
} VsContext;

typedef struct VsBio {
	uint32_t magic;
	int fd;
	int close_on_free;
	/* A memory BIO (BIO_new_mem): what was written to it, kept NUL-terminated for PEM */
	int memory;
	unsigned char *data;
	size_t length, capacity;
	/* Sony's BIO_ctrl 100 (0xc220): a copy of the host name libhttp gives, which the ClientHello's
	 * SNI comes from, a port as text or a number, and an address's 4 bytes */
	char *host, *port_text;
	int port;
	unsigned char address[4];
	/* BIO_set_cb_arg's, which libhttp's certificate check reads back */
	void *callback_argument;
} VsBio;

typedef struct VsSsl {
	uint32_t magic;
	VsContext *context;
	const VsMethod *method;
	VsBio *rbio, *wbio;
	uint32_t options;
	VsInfoCallback info_callback;
	int connecting;
	int ready; /* mbedtls_ssl_setup done */
	int handshake_done;
	int close_notify; /* the server's close_notify arrived */
	int close_sent;
	VsFailure failure;
	int tls_result; /* Mbed TLS's error when failure is TLS */
	/* The reason libhttp's check gave when it refused the server */
	int verify_result;
	/* The debug log's: the HTTP headers sent and received, gathered until their blank line and then
	 * logged with secrets as their length (connection.c's log_headers); bodies aren't kept */
	struct VsHeaderLog {
		char *data;
		int length, done;
	} sent_headers, received_headers;
	/* The debug log's: one-byte reads in a row (libhttp reads the headers so), logged as one line */
	int one_byte_reads;
	/* The debug log's: the server's closing has been logged */
	int close_logged;
	/* The errno of the socket call that failed, set again when the handshake returns: libhttp reads
	 * it, and the calls Mbed TLS makes after the failing one mustn't have changed it */
	int socket_errno;
	mbedtls_ssl_context tls;
	mbedtls_ssl_config config;
	mbedtls_x509_crt_profile profile;
	/* A host that is an IPv4 address: no SNI, as Sony's */
	int is_address;
	/* SSL_peek's: data read and not yet given to SSL_read */
	unsigned char *peeked;
	int peeked_size, peeked_at;
	/* SSL_get_current_cipher's: OpenSSL's id (0x03000000 and the suite's number) and its name */
	struct VsCipher {
		uint32_t id;
		const char *name;
		int bits;
		int tls13;
	} cipher;
	const void *session;
} VsSsl;

/* core.c */
int vs_initialized(void);
/* The library's lock (recursive), for the objects shared between threads */
void vs_lock(void);
void vs_unlock(void);
/* SSL-C's error queue (core.c): an error for ERR_peek_error and SSL_get_error, as OpenSSL packs
 * it: library << 24 | function << 12 | reason */
#define VS_ERR_LIB_SYS 2
#define VS_ERR_LIB_BIO 32
#define VS_ERR_LIB_SSL 20
#define VS_ERR_PACK(library, function, reason)                                                    \
	((unsigned long)(library) << 24 | (unsigned long)(function) << 12 | (unsigned long)(reason))
void vs_error_push(unsigned long error);

/* The platform: platform/platform_ps3.c on the console, tests/host/platform_posix.c on a host */
int vs_platform_lock_create(void);
void vs_platform_lock_destroy(void);
void vs_platform_lock(void);
void vs_platform_unlock(void);
/* The socket's receive and send: what moved, 0 at its end, or -1 with the system's errno set
 * (which the caller reads, as Sony's libhttp does); vs_platform_net_errno reads it */
int vs_platform_recv(int fd, void *data, size_t size);
int vs_platform_send(int fd, const void *data, size_t size);
int vs_platform_net_errno(void);
void vs_platform_set_net_errno(int value);
/* A line of the debug log (VITALS_DEBUG 1 or 2) */
void vs_platform_log(const char *text);
/* The calling thread's stack: its size, and how much of it is left below the stack pointer (0 and 0
 * when the system doesn't say) */
void vs_platform_stack(uint32_t *size, uint32_t *left);
/* function(argument) on a thread of its own with a stack of stack bytes, at the caller's priority,
 * the caller waiting for it: 0, or the system's error (not 0) when no thread could be made (nothing
 * ran) */
int vs_platform_run_with_stack(void (*function)(void *), void *argument, uint32_t stack);
/* Files, for the CA certificates: a descriptor (negative when it can't be opened), what was read
 * (negative on failure), the size (negative on failure), and 0 or negative */
int vs_platform_file_open(const char *path);
int vs_platform_file_read(int fd, void *data, size_t size);
int vs_platform_file_seek(int fd, uint32_t offset);
int64_t vs_platform_file_size(int fd);
void vs_platform_file_close(int fd);
/* Where the CA certificates are: Sony's (/dev_flash/data/cert/), with the file's name after it, and
 * Mozilla's bundle (/dev_hdd0/vitals/system/cacert.pem) */
int vs_platform_sony_cert_path(char *path, size_t size, const char *file);
const char *vs_platform_bundle_path(void);
/* 1 when the memory at pointer can be read: Sony's public functions check their object so (syscall
 * 351, sys_memory_get_page_attribute) before using it */
int vs_platform_readable(const void *pointer);
/* The running game's title ID ("BLUS31193"), 9 characters and a NUL; "" when there's none */
void vs_platform_title_id(char id[10]);

/* BIO_write's, for the CA store: a memory BIO appends, a socket BIO sends; what was written, -1 when
 * it couldn't, -2 for a handle that isn't a BIO (SSL-C's) */
int vs_bio_write(void *handle, const void *data, size_t length);

/* The debug log's levels (VITALS_DEBUG): 0 none; 1 calls and what each connection does (the CA
 * store, the handshake and its result, which CA the chain comes from and why one was refused, the
 * server's alerts and closing, the pool's use, calls this libssl ignores); 2 also every read and
 * write (one-byte reads in a row as one line) and the HTTP headers that go by (secrets as their
 * length), and the details under level 1's lines */
#ifndef VITALS_DEBUG
#define VITALS_DEBUG 0
#endif
#if VITALS_DEBUG >= 1
void vs_log(const char *format, ...) __attribute__((format(printf, 1, 2)));
#define VS_LOG(...) vs_log(__VA_ARGS__)
#else
#define VS_LOG(...) ((void)0)
#endif
#if VITALS_DEBUG >= 2
#define VS_LOG2(...) vs_log(__VA_ARGS__)
#else
#define VS_LOG2(...) ((void)0)
#endif

#endif
