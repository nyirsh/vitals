#ifndef VITALS_APP_DOWNLOAD_H
#define VITALS_APP_DOWNLOAD_H

#include <stddef.h>

/* HTTPS downloads through curl, the same on every console (the Vita's curl is on OpenSSL, the PS3's on
 * Mbed TLS): the app's own TLS, trusting only the CAs it's given, so a download works whatever the
 * console's own TLS is, vitals' included. The console's network must be up (console_network_start) */

typedef struct {
	const char *url;
	/* The only CAs trusted, in PEM: the Mozilla bundle the app carries */
	const char *ca;
	size_t ca_size;
	const char *user_agent;
	/* "Accept: ..." or NULL */
	const char *accept;
	/* For the whole transfer, 1 to 120 */
	long timeout_seconds;
	/* The largest body taken: a longer one fails the download */
	size_t limit;
	/* Set to nonzero by another thread, it ends the transfer at once; may be NULL */
	const volatile int *cancel;
	/* curl's notes on each step (the lookup, the connection, the TLS handshake), a line at a time, for
	 * the console's app log; NULL for none. Its own words only: no headers or data */
	void (*log)(const char *line);
} VitalsDownload;

typedef struct {
	/* The body, NUL-terminated, malloc's (vitals_download_free); NULL when it failed */
	char *data;
	size_t size;
	/* The HTTP status, 0 without a response, and curl's code (CURLE_OK, 0, when it worked) */
	long status;
	int error;
	/* What went wrong in curl's words ("Failed to connect to curl.se port 443 after 120 ms: ..."), or
	 * empty */
	char message[256];
} VitalsDownloaded;

/* GET request->url, certificate and host name checked, no redirects followed: 0 when an HTTP 200
 * came with at most request->limit bytes, else -1 (with what happened in *result) */
int vitals_download(const VitalsDownload *request, VitalsDownloaded *result);
void vitals_download_free(VitalsDownloaded *result);
/* curl's words for its code ("Couldn't resolve host name") */
const char *vitals_download_error(int error);

#endif
