/* HTTPS downloads through curl, the same on every console (download.h): as the Vita's certificate
 * update and new-release check made them */

#include "download.h"

#include <curl/curl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	char *data;
	size_t size, limit;
	int too_large;
	const volatile int *cancel;
} Body;

static size_t receive(char *bytes, size_t size, size_t count, void *opaque)
{
	Body *body = opaque;
	if (size != 0 && count > (body->limit + 1) / size) {
		body->too_large = 1;
		return 0;
	}
	size_t length = size * count;
	if (length > body->limit - body->size) {
		body->too_large = 1;
		return 0;
	}
	char *data = realloc(body->data, body->size + length + 1);
	if (data == NULL)
		return 0;
	body->data = data;
	memcpy(data + body->size, bytes, length);
	body->size += length;
	data[body->size] = '\0';
	return length;
}

/* curl's notes (CURLINFO_TEXT) to the request's log, a line at a time; headers and data never */
static int trace(CURL *curl, curl_infotype type, char *text, size_t size, void *opaque)
{
	const VitalsDownload *request = opaque;
	(void)curl;
	if (type != CURLINFO_TEXT || request->log == NULL)
		return 0;
	char line[256];
	while (size > 0 && (text[size - 1] == '\n' || text[size - 1] == '\r'))
		--size;
	snprintf(line, sizeof(line), "curl: %.*s", (int)(size < 240 ? size : 240), text);
	request->log(line);
	return 0;
}

/* Returning nonzero makes curl stop the transfer */
static int progress(void *opaque, curl_off_t total, curl_off_t now, curl_off_t upload_total, curl_off_t uploaded)
{
	const Body *body = opaque;
	(void)total, (void)now, (void)upload_total, (void)uploaded;
	return body->cancel != NULL && *body->cancel;
}

int vitals_download(const VitalsDownload *request, VitalsDownloaded *result)
{
	memset(result, 0, sizeof(*result));
	result->error = CURLE_FAILED_INIT;
	if (request == NULL || request->url == NULL || request->ca == NULL || request->ca_size == 0 ||
	    request->user_agent == NULL || request->timeout_seconds < 1 || request->timeout_seconds > 120 ||
	    request->limit == 0)
		return -1;
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
		return -1;
	Body body = {NULL, 0, request->limit, 0, request->cancel};
	struct curl_slist *headers = request->accept != NULL ? curl_slist_append(NULL, request->accept) : NULL;
	struct curl_blob ca = {(void *)request->ca, request->ca_size, CURL_BLOB_COPY};
	CURL *curl = curl_easy_init();
	CURLcode error = CURLE_FAILED_INIT;
	char message[CURL_ERROR_SIZE] = "";
	if (curl == NULL || (request->accept != NULL && headers == NULL))
		goto done;
#define SET(option, value)                                                                                                \
	do {                                                                                                                  \
		if ((error = curl_easy_setopt(curl, option, value)) != CURLE_OK)                                                  \
			goto done;                                                                                                    \
	} while (0)
	SET(CURLOPT_ERRORBUFFER, message);
	if (request->log != NULL) {
		SET(CURLOPT_DEBUGFUNCTION, trace);
		SET(CURLOPT_DEBUGDATA, (void *)request);
		SET(CURLOPT_VERBOSE, 1L);
	}
	SET(CURLOPT_URL, request->url);
	SET(CURLOPT_PROTOCOLS_STR, "https");
	SET(CURLOPT_FOLLOWLOCATION, 0L);
	SET(CURLOPT_FAILONERROR, 1L);
	SET(CURLOPT_PROXY, "");
	SET(CURLOPT_NETRC, (long)CURL_NETRC_IGNORED);
	SET(CURLOPT_SSL_VERIFYPEER, 1L);
	SET(CURLOPT_SSL_VERIFYHOST, 2L);
	SET(CURLOPT_SSLVERSION, (long)CURL_SSLVERSION_TLSv1_2);
	/* Only the given CAs: none of the build's or the system's */
	SET(CURLOPT_CAINFO, NULL);
	SET(CURLOPT_CAPATH, NULL);
	SET(CURLOPT_CAINFO_BLOB, &ca);
	SET(CURLOPT_SSL_SESSIONID_CACHE, 0L);
	/* No CA store kept between transfers: only where curl's TLS has one (OpenSSL, the host's), as Mbed
	 * TLS, both consoles', has none and refuses the option (CURLE_NOT_BUILT_IN) */
	(void)curl_easy_setopt(curl, CURLOPT_CA_CACHE_TIMEOUT, 0L);
	SET(CURLOPT_FRESH_CONNECT, 1L);
	SET(CURLOPT_FORBID_REUSE, 1L);
	SET(CURLOPT_CONNECTTIMEOUT, request->timeout_seconds < 10 ? request->timeout_seconds : 10L);
	SET(CURLOPT_TIMEOUT, request->timeout_seconds);
	SET(CURLOPT_NOSIGNAL, 1L);
	/* GitHub refuses API requests without a user agent */
	SET(CURLOPT_USERAGENT, request->user_agent);
	if (headers != NULL)
		SET(CURLOPT_HTTPHEADER, headers);
	SET(CURLOPT_WRITEFUNCTION, receive);
	SET(CURLOPT_WRITEDATA, &body);
	SET(CURLOPT_NOPROGRESS, 0L);
	SET(CURLOPT_XFERINFOFUNCTION, progress);
	SET(CURLOPT_XFERINFODATA, &body);
#undef SET
	error = curl_easy_perform(curl);
	(void)curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &result->status);
	if (error == CURLE_WRITE_ERROR && body.too_large)
		error = CURLE_FILESIZE_EXCEEDED;
	if (error == CURLE_OK && result->status != 200)
		error = CURLE_HTTP_RETURNED_ERROR;
	if (error == CURLE_OK && body.data == NULL)
		error = CURLE_GOT_NOTHING;
done:
	result->error = (int)error;
	snprintf(result->message, sizeof(result->message), "%s", message);
	if (request->log != NULL)
		request->log(message[0] != '\0' ? message : curl_easy_strerror(error));
	if (error == CURLE_OK) {
		result->data = body.data;
		result->size = body.size;
		body.data = NULL;
	}
	if (curl != NULL)
		curl_easy_cleanup(curl);
	curl_slist_free_all(headers);
	free(body.data);
	curl_global_cleanup();
	return error == CURLE_OK ? 0 : -1;
}

void vitals_download_free(VitalsDownloaded *result)
{
	free(result->data);
	result->data = NULL;
	result->size = 0;
}

const char *vitals_download_error(int error)
{
	return curl_easy_strerror((CURLcode)error);
}
