#include "version_check.h"
#include "release_version.h"

#include <curl/curl.h>

#include <stdlib.h>
#include <string.h>

/* Far larger than a release response; anything bigger is not one */
#define RELEASE_RESPONSE_LIMIT (256u * 1024u)

typedef struct Response {
    char *data;
    size_t size;
    const volatile int *cancel;
} Response;

static size_t receive(char *bytes, size_t size, size_t count, void *opaque) {
    Response *response = opaque;
    if (size != 0 && count > RELEASE_RESPONSE_LIMIT / size) return 0;
    size_t length = size * count;
    if (length > RELEASE_RESPONSE_LIMIT - response->size) return 0;
    char *data = realloc(response->data, response->size + length + 1);
    if (data == NULL) return 0;
    response->data = data;
    memcpy(data + response->size, bytes, length);
    response->size += length;
    data[response->size] = '\0';
    return length;
}

/* Returning nonzero makes curl stop the transfer */
static int progress(void *opaque, curl_off_t total, curl_off_t now, curl_off_t upload_total, curl_off_t uploaded) {
    const Response *response = opaque;
    (void)total, (void)now, (void)upload_total, (void)uploaded;
    return response->cancel != NULL && *response->cancel;
}

static int fetch(const char *url, const char *ca_path, const char *user_agent, long timeout,
    const volatile int *cancel, char *version, size_t size) {
    Response response = {NULL, 0, cancel};
    struct curl_slist *headers = curl_slist_append(NULL, "Accept: application/json");
    CURL *curl = curl_easy_init();
    long status = 0;
    int result = -1;

    if (curl == NULL || headers == NULL) goto done;
#define SET(option, value) do { if (curl_easy_setopt(curl, option, value) != CURLE_OK) goto done; } while (0)
    SET(CURLOPT_URL, url);
    SET(CURLOPT_PROTOCOLS_STR, "https");
    SET(CURLOPT_FOLLOWLOCATION, 0L);
    SET(CURLOPT_FAILONERROR, 1L);
    SET(CURLOPT_PROXY, "");
    SET(CURLOPT_NETRC, CURL_NETRC_IGNORED);
    SET(CURLOPT_SSL_VERIFYPEER, 1L);
    SET(CURLOPT_SSL_VERIFYHOST, 2L);
    SET(CURLOPT_SSLVERSION, (long)CURL_SSLVERSION_TLSv1_2);
    SET(CURLOPT_CAINFO, ca_path);
    SET(CURLOPT_CAPATH, NULL);
    SET(CURLOPT_CONNECTTIMEOUT, timeout);
    SET(CURLOPT_TIMEOUT, timeout);
    SET(CURLOPT_NOSIGNAL, 1L);
    /* GitHub refuses API requests without a user agent */
    SET(CURLOPT_USERAGENT, user_agent);
    SET(CURLOPT_HTTPHEADER, headers);
    SET(CURLOPT_WRITEFUNCTION, receive);
    SET(CURLOPT_WRITEDATA, &response);
    SET(CURLOPT_NOPROGRESS, 0L);
    SET(CURLOPT_XFERINFOFUNCTION, progress);
    SET(CURLOPT_XFERINFODATA, &response);
#undef SET
    if (curl_easy_perform(curl) == CURLE_OK &&
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status) == CURLE_OK && status == 200 &&
        response.data != NULL)
        result = vitals_release_tag(response.data, response.size, version, size);
done:
    if (curl != NULL) curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    free(response.data);
    return result;
}

int vitals_fetch_latest_release(const char *const *urls, size_t count, const char *ca_path,
    const char *user_agent, long timeout_seconds, const volatile int *cancel, char *version, size_t size) {
    int result = -1;

    if (urls == NULL || ca_path == NULL || user_agent == NULL || version == NULL || size == 0 ||
        timeout_seconds < 1 || timeout_seconds > 60)
        return -1;
    version[0] = '\0';
    /* The same TLS library as the certificate updater; choosing it after curl started is fine */
    CURLsslset backend = curl_global_sslset(CURLSSLBACKEND_OPENSSL, NULL, NULL);
    if ((backend != CURLSSLSET_OK && backend != CURLSSLSET_TOO_LATE) ||
        curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
        return -1;
    for (size_t i = 0; i < count && result != 0 && !(cancel != NULL && *cancel); ++i) {
        if (urls[i] != NULL)
            result = fetch(urls[i], ca_path, user_agent, timeout_seconds, cancel, version, size);
    }
    curl_global_cleanup();
    if (result != 0)
        version[0] = '\0';
    return result;
}
