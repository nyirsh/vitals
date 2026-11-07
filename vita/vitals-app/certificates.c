#include "certificates.h"
#include "download.h"

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

/* The user's certificates: every block that parses as a certificate, CA or not (a self-signed
 * server certificate is trusted as itself), up to the store's limit; anything else in the file
 * is skipped, so a mistake there never costs the system its roots */
static STACK_OF(X509) *parse_custom(const unsigned char *data, size_t size) {
    static const char begin[] = "-----BEGIN CERTIFICATE-----";
    static const char end[] = "-----END CERTIFICATE-----";
    STACK_OF(X509) *chain = sk_X509_new_null();
    const char *cursor = (const char *)data;
    /* read_file ends the data with a NUL, so the search stops at the end (or at a stray NUL) */
    if (chain == NULL || data == NULL || size == 0) return chain;
    while (sk_X509_num(chain) < CERTIFICATE_LIMIT) {
        const char *first = strstr(cursor, begin);
        if (first == NULL) break;
        const char *last = strstr(first + sizeof(begin) - 1, end);
        if (last == NULL) break;
        size_t length = (size_t)(last - first) + sizeof(end) - 1;
        cursor = last + sizeof(end) - 1;
        BIO *bio = BIO_new_mem_buf(first, (int)length);
        X509 *certificate = bio != NULL ? PEM_read_bio_X509(bio, NULL, NULL, NULL) : NULL;
        BIO_free(bio);
        if (certificate != NULL && !sk_X509_push(chain, certificate)) X509_free(certificate);
    }
    ERR_clear_error();
    return chain;
}

/* The latest bundle, through the app's shared download (../../shared/app/download.c), trusting only
 * the Mozilla certificates the app carries: none of curl's or OpenSSL's own, nor Sony's */
static STACK_OF(X509) *fetch_bundle(const char *url, const unsigned char *mozilla, size_t mozilla_size,
    long timeout, VitalsCertificateBundle *result) {
    STACK_OF(X509) *chain = NULL;
    if (url == NULL) { result->download_error = CURLE_COULDNT_CONNECT; return NULL; }
    VitalsDownload request = {url, (const char *)mozilla, mozilla_size, "vitals-certificate-updater", NULL,
        timeout, VITALS_CA_BUNDLE_LIMIT, NULL, NULL};
    VitalsDownloaded download;
    int failed = vitals_download(&request, &download);
    result->download_error = download.error;
    result->http_status = download.status;
    if (!failed) {
        chain = parse_bundle((const unsigned char *)download.data, download.size);
        if (chain == NULL) result->download_error = CURLE_SSL_CACERT_BADFILE;
    }
    vitals_download_free(&download);
    return chain;
}

/* Adds source's certificates that combined lacks; with skip_beyond_limit, those past the limit
 * are left out instead of failing */
static int append_unique(STACK_OF(X509) *combined, STACK_OF(X509) *source, int skip_beyond_limit) {
    for (int i = 0; i < sk_X509_num(source); ++i) {
        X509 *certificate = sk_X509_value(source, i);
        int duplicate = 0;
        for (int j = 0; j < sk_X509_num(combined); ++j) {
            if (X509_cmp(certificate, sk_X509_value(combined, j)) == 0) { duplicate = 1; break; }
        }
        if (duplicate) continue;
        if (sk_X509_num(combined) >= CERTIFICATE_LIMIT && skip_beyond_limit) break;
        if (sk_X509_num(combined) >= CERTIFICATE_LIMIT || !X509_up_ref(certificate)) return -1;
        if (!sk_X509_push(combined, certificate)) { X509_free(certificate); return -1; }
    }
    return 0;
}

int vitals_prepare_certificates(const char *sony_path, const char *mozilla_path,
    const char *custom_path, const char *url, long timeout_seconds, VitalsCertificateBundle *bundle) {
    unsigned char *sony_data = NULL, *mozilla_data = NULL, *custom_data = NULL;
    size_t sony_size = 0, mozilla_size = 0, custom_size = 0;
    STACK_OF(X509) *sony = NULL, *embedded = NULL, *downloaded = NULL, *custom = NULL, *combined = NULL;
    BIO *output = NULL;
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
    downloaded = fetch_bundle(url, mozilla_data, mozilla_size, timeout_seconds, bundle);
    STACK_OF(X509) *selected = downloaded == NULL ? embedded : downloaded;
    bundle->downloaded = downloaded != NULL;
    bundle->mozilla_count = (size_t)sk_X509_num(selected);
    ERR_clear_error();
    errno = 0;
    /* A missing, empty or unreadable custom file simply adds nothing */
    if (custom_path != NULL && read_file(custom_path, &custom_data, &custom_size) != 0) custom_size = 0;
    bundle->failure_stage = "parsing custom certificates";
    custom = parse_custom(custom_data, custom_size);
    if (custom == NULL) goto done;
    ERR_clear_error();
    errno = 0;
    bundle->failure_stage = "combining certificate identities";
    combined = sk_X509_new_null();
    if (combined == NULL || append_unique(combined, sony, 0) != 0) goto done;
    int sony_unique_count = sk_X509_num(combined);
    if (append_unique(combined, selected, 0) != 0) goto done;
    int mozilla_end = sk_X509_num(combined);
    if (append_unique(combined, custom, 1) != 0) goto done;
    bundle->custom_count = (size_t)(sk_X509_num(combined) - mozilla_end);
    bundle->failure_stage = "creating combined PEM buffer";
    output = BIO_new(BIO_s_mem());
    /* Sony's code finds its CA certificates at fixed byte offsets in this file, so it is copied
     * unchanged, comments and CRLFs included, and new roots are only appended after it */
    if (output == NULL || BIO_write(output, sony_data, (int)sony_size) != (int)sony_size) goto done;
    if (sony_data[sony_size - 1] != '\n' && BIO_puts(output, "\n") <= 0) goto done;
    if (BIO_puts(output, "# vitals: additional curl/Mozilla CA certificates\n") <= 0) goto done;
    bundle->failure_stage = "encoding combined certificates";
    for (int i = sony_unique_count; i < sk_X509_num(combined); ++i) {
        if (i == mozilla_end && BIO_puts(output, "# vitals: custom certificates (" VITALS_CUSTOM_CERTIFICATES_PATH ")\n") <= 0)
            goto done;
        if (!PEM_write_bio_X509(output, sk_X509_value(combined, i))) goto done;
    }
    char *bytes = NULL;
    bundle->failure_stage = "reading combined PEM buffer";
    long size = BIO_get_mem_data(output, &bytes);
    if (size <= 0 || (unsigned long)size > VITALS_CA_BUNDLE_LIMIT) goto done;
    bundle->failure_stage = "allocating combined certificate output";
    bundle->data = malloc((size_t)size + 1);
    if (bundle->data == NULL) goto done;
    memcpy(bundle->data, bytes, (size_t)size);
    bundle->data[size] = 0;
    bundle->size = (size_t)size;
    bundle->combined_count = (size_t)sk_X509_num(combined);
    bundle->failure_stage = NULL;
    result = 0;
done:
    failure_stage = bundle->failure_stage;
    failure_errno = errno;
    failure_crypto_error = ERR_peek_last_error();
    BIO_free(output);
    free_chain(combined);
    free_chain(custom);
    free_chain(downloaded);
    free_chain(embedded);
    free_chain(sony);
    free(sony_data);
    free(mozilla_data);
    free(custom_data);
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
