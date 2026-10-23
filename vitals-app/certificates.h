#ifndef VITALS_APP_CERTIFICATES_H
#define VITALS_APP_CERTIFICATES_H

#include <stddef.h>

#define VITALS_CA_UPDATE_URL "https://curl.se/ca/cacert.pem"
/* The user's own certificates (for example their servers' self-signed ones), merged after Sony's
 * and Mozilla's; the file is optional */
#define VITALS_CUSTOM_CERTIFICATES_PATH "ux0:data/vitals/custom-certs.pem"
#define VITALS_CA_BUNDLE_LIMIT (4u * 1024u * 1024u)

typedef struct VitalsCertificateBundle {
    unsigned char *data;
    size_t size;
    size_t sony_count, mozilla_count, custom_count, combined_count;
    int downloaded;
    int download_error;
    long http_status;
    const char *failure_stage;
    int failure_errno;
    unsigned long failure_crypto_error;
} VitalsCertificateBundle;

/* URL is NULL when networking is unavailable
 * The Sony and Mozilla inputs always come from the VPK; custom_path is the user's file, which may
 * be NULL or missing, and whose unusable entries are skipped rather than failing the store */
int vitals_prepare_certificates(const char *sony_path, const char *mozilla_path,
    const char *custom_path, const char *url, long timeout_seconds, VitalsCertificateBundle *bundle);
void vitals_free_certificates(VitalsCertificateBundle *bundle);

#endif
