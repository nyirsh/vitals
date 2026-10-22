#ifndef VITALS_APP_CERTIFICATES_H
#define VITALS_APP_CERTIFICATES_H

#include <stddef.h>

#define VITALS_CA_UPDATE_URL "https://curl.se/ca/cacert.pem"
#define VITALS_CA_BUNDLE_LIMIT (4u * 1024u * 1024u)

typedef struct VitalsCertificateBundle {
    unsigned char *data;
    size_t size;
    size_t sony_count, mozilla_count, combined_count;
    int downloaded;
    int download_error;
    long http_status;
    const char *failure_stage;
    int failure_errno;
    unsigned long failure_crypto_error;
} VitalsCertificateBundle;

/* URL is NULL when networking is unavailable
 * Inputs always come from the VPK */
int vitals_prepare_certificates(const char *sony_path, const char *mozilla_path,
    const char *url, long timeout_seconds, VitalsCertificateBundle *bundle);
void vitals_free_certificates(VitalsCertificateBundle *bundle);

#endif
