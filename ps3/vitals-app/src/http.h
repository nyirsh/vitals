#ifndef VITALS_APP_HTTP_H
#define VITALS_APP_HTTP_H

#include <stddef.h>
#include <stdint.h>

/* HTTPS through Sony's libhttp and libssl, as a game makes it, with Sony's CAs loaded the way games
 * load them: with vitals installed, its libssl answers (Mozilla's bundle and TLS 1.3 included) */

/* What a request did */
typedef struct {
	/* The response's status, 0 without one; the request's error (libhttp's), 0 when it worked */
	int http_code, error;
	/* libhttp's certificate flags (CELL_HTTPS_VERIFY_ERROR_*) when it refused the server */
	uint32_t verify_error;
	/* cellHttpTransactionGetSslVersion's: Sony's CELL_SSL_VERSION, 0 for TLS (any of 1.0 to 1.3) and
	 * 1 for SSL 3.0, as its API has no more; -1 without a connection. And the cipher's name, which
	 * says TLS 1.3 for vitals' TLS 1.3 suites (TLS1-3-...) */
	int ssl_version;
	char cipher[64];
	/* Every attempt's time together, and how many were made (timeouts are retried) */
	unsigned elapsed_ms, attempts;
	/* What was read into the body */
	size_t length;
} HttpResult;

/* Waits up to 10 seconds for an IP address: 0, or the error */
int http_network_start(void);
/* The same, asking stop while it waits: 1 from it ends the wait (the app's curl downloads,
 * console_network_start) */
int http_network_wait(int (*stop)(void));
/* The network, libhttp and libssl with Sony's CAs: 0, or the failing call's result */
int http_open(void);
void http_close(void);
/* GET url into body (capacity bytes, NUL-terminated after length; 0 reads no body, for a check
 * that only needs the status), certificate checks on, redirects not followed, as the Vita's
 * vitals-app makes its requests. A request that times out is made again, up to HTTP_ATTEMPTS in
 * all. 0 when a response came (any status), else the last attempt's error, also in
 * result->error */
#define HTTP_ATTEMPTS 3
int http_get(const char *url, char *body, size_t capacity, HttpResult *result);
/* Ends the request in progress, and any made after it until http_reset_cancel, from another
 * thread */
void http_cancel(void);
void http_reset_cancel(void);
/* The protocol a request used, as far as libhttp tells: "TLS 1.3", "TLS", "SSL 3.0" or "none" */
const char *http_protocol_name(int ssl_version, const char *cipher);
/* Milliseconds since boot */
uint64_t http_now_ms(void);

#endif
