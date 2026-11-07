#include "certificates.h"
#include "download.h"
#include "vitals/store_certs.h"

#include <curl/curl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CERTIFICATE_LIMIT 512

static void free_chain(STACK_OF(X509) *chain) {
    sk_X509_pop_free(chain, X509_free);
}

static int read_file(const char *path, unsigned char **data, size_t *size) {
    FILE *file = fopen(path, "rb");
    long length;
    int result = -1;
    *data = NULL;
    *size = 0;
    if (file == NULL) return -1;
    if (fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) <= 0 ||
        (unsigned long)length > VITALS_CA_BUNDLE_LIMIT || fseek(file, 0, SEEK_SET) != 0) goto done;
    *data = malloc((size_t)length + 1);
    if (*data == NULL) goto done;
    if (fread(*data, 1, (size_t)length, file) != (size_t)length || ferror(file)) goto done;
    (*data)[length] = 0;
    *size = (size_t)length;
    result = 0;
done:
    if (fclose(file) != 0) result = -1;
    if (result != 0) { free(*data); *data = NULL; *size = 0; }
    return result;
}

/* Reject partial parses, private-key blocks, non-CA certificates and embedded NULs */
static STACK_OF(X509) *parse_bundle(const unsigned char *data, size_t size) {
    static const char begin[] = "-----BEGIN CERTIFICATE-----";
    static const char end[] = "-----END CERTIFICATE-----";
    STACK_OF(X509) *chain = NULL;
    const char *cursor = (const char *)data;
    if (data == NULL || size == 0 || size > VITALS_CA_BUNDLE_LIMIT ||
        memchr(data, 0, size) != NULL) return NULL;
    chain = sk_X509_new_null();
    if (chain == NULL) return NULL;
    for (;;) {
        const char *first = strstr(cursor, "-----BEGIN");
        if (first == NULL) break;
        if (strncmp(first, begin, sizeof(begin) - 1) != 0 ||
            sk_X509_num(chain) >= CERTIFICATE_LIMIT) goto failed;
        const char *last = strstr(first + sizeof(begin) - 1, end);
        if (last == NULL) goto failed;
        size_t length = (size_t)(last - first) + sizeof(end) - 1;
        BIO *bio = BIO_new_mem_buf(first, (int)length);
        if (bio == NULL) goto failed;
        X509 *certificate = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (certificate == NULL) goto failed;
        if (X509_check_ca(certificate) <= 0 || !sk_X509_push(chain, certificate)) {
            X509_free(certificate);
            goto failed;
        }
        cursor = last + sizeof(end) - 1;
    }
    if (sk_X509_num(chain) == 0) goto failed;
    return chain;
failed:
    free_chain(chain);
    return NULL;
}

/* The latest bundle, through the app's shared download (../../shared/app/download.c), trusting only
 * the Mozilla certificates the app carries: none of curl's or OpenSSL's own, nor Sony's. Its text
 * (NUL-terminated, the caller's to free) when it's a whole bundle of CA certificates, else NULL */
static unsigned char *fetch_bundle(const char *url, const unsigned char *mozilla, size_t mozilla_size,
    long timeout, VitalsCertificateBundle *result, size_t *size, size_t *count) {
    unsigned char *text = NULL;
    *size = 0;
    if (url == NULL) { result->download_error = CURLE_COULDNT_CONNECT; return NULL; }
    VitalsDownload request = {url, (const char *)mozilla, mozilla_size, "vitals-certificate-updater", NULL,
        timeout, VITALS_CA_BUNDLE_LIMIT, NULL, NULL};
    VitalsDownloaded download;
    int failed = vitals_download(&request, &download);
    result->download_error = download.error;
    result->http_status = download.status;
    if (!failed) {
        STACK_OF(X509) *chain = parse_bundle((const unsigned char *)download.data, download.size);
        if (chain == NULL) {
            result->download_error = CURLE_SSL_CACERT_BADFILE;
        } else if ((text = malloc(download.size + 1)) != NULL) {
            memcpy(text, download.data, download.size);
            text[download.size] = 0;
            *size = download.size;
            *count = (size_t)sk_X509_num(chain);
        }
        free_chain(chain);
    }
    vitals_download_free(&download);
    return text;
}

int vitals_prepare_certificates(const char *sony_path, const char *mozilla_path,
    const char *url, long timeout_seconds, VitalsCertificateBundle *bundle) {
    unsigned char *sony_data = NULL, *mozilla_data = NULL, *downloaded = NULL;
    size_t sony_size = 0, mozilla_size = 0, downloaded_size = 0, downloaded_count = 0;
    STACK_OF(X509) *sony = NULL, *embedded = NULL;
    int result = -1;
    const char *failure_stage;
    int failure_errno;
    unsigned long failure_crypto_error;
    if (bundle == NULL) return -1;
    memset(bundle, 0, sizeof(*bundle));
    if (sony_path == NULL || mozilla_path == NULL || timeout_seconds < 1 || timeout_seconds > 60) return -1;
    errno = 0;
    ERR_clear_error();
    bundle->failure_stage = "reading embedded Sony certificates";
    if (read_file(sony_path, &sony_data, &sony_size) != 0) goto done;
    bundle->failure_stage = "reading embedded Mozilla certificates";
    if (read_file(mozilla_path, &mozilla_data, &mozilla_size) != 0) goto done;
    bundle->failure_stage = "parsing embedded Sony certificates";
    sony = parse_bundle(sony_data, sony_size);
    if (sony == NULL) goto done;
    bundle->failure_stage = "parsing embedded Mozilla certificates";
    embedded = parse_bundle(mozilla_data, mozilla_size);
    if (embedded == NULL) goto done;
    bundle->sony_count = (size_t)sk_X509_num(sony);
    downloaded = fetch_bundle(url, mozilla_data, mozilla_size, timeout_seconds, bundle, &downloaded_size,
        &downloaded_count);
    const unsigned char *selected = downloaded != NULL ? downloaded : mozilla_data;
    size_t selected_size = downloaded != NULL ? downloaded_size : mozilla_size;
    bundle->downloaded = downloaded != NULL;
    bundle->mozilla_count = downloaded != NULL ? downloaded_count : (size_t)sk_X509_num(embedded);
    ERR_clear_error();
    errno = 0;
    /* Sony's list is its own part of the store, as Sony ships it (Sony's code finds its CA
     * certificates at fixed byte offsets in it): Mozilla's bundle, as curl publishes it, without
     * what Sony's list already has, as the PS3's app writes its own (../../shared/src/store_certs.c) */
    bundle->failure_stage = "allocating Mozilla certificate output";
    bundle->data = malloc(selected_size + 1);
    if (bundle->data == NULL) goto done;
    VitalsStoreFilter filter;
    bundle->failure_stage = "leaving Sony's certificates out of Mozilla's";
    if (vitals_store_mozilla((const char *)selected, selected_size, (const char *)sony_data, sony_size,
            (char *)bundle->data, selected_size + 1, &bundle->size, &filter) != 0) goto done;
    bundle->data[bundle->size] = 0;
    bundle->added_count = filter.kept;
    bundle->combined_count = bundle->sony_count + filter.kept;
    bundle->failure_stage = NULL;
    result = 0;
done:
    failure_stage = bundle->failure_stage;
    failure_errno = errno;
    failure_crypto_error = ERR_peek_last_error();
    free_chain(embedded);
    free_chain(sony);
    free(downloaded);
    free(sony_data);
    free(mozilla_data);
    if (result != 0) {
        vitals_free_certificates(bundle);
        bundle->failure_stage = failure_stage;
        bundle->failure_errno = failure_errno;
        bundle->failure_crypto_error = failure_crypto_error;
    }
    return result;
}

void vitals_free_certificates(VitalsCertificateBundle *bundle) {
    if (bundle == NULL) return;
    free(bundle->data);
    memset(bundle, 0, sizeof(*bundle));
}
