#ifndef VITALS_APP_CERTIFICATES_H
#define VITALS_APP_CERTIFICATES_H

#include <stddef.h>

#define VITALS_CA_UPDATE_URL "https://curl.se/ca/cacert.pem"
#define VITALS_CA_BUNDLE_LIMIT (4u * 1024u * 1024u)

typedef struct VitalsCertificateBundle {
    unsigned char *data;
    size_t size;
    /* Sony's, Mozilla's (the selected bundle's), those of Mozilla's written (Sony's lacks them), and
     * the store's without the user's own (Sony's and those written) */
    size_t sony_count, mozilla_count, added_count, combined_count;
    int downloaded;
    int download_error;
    long http_status;
    const char *failure_stage;
    int failure_errno;
    unsigned long failure_crypto_error;
} VitalsCertificateBundle;

/* The second part of vitals' certificate store (vitals/ca_store.h): Mozilla's certificates that
 * Sony's list lacks, as PEM, in bundle->data. Mozilla's are the latest bundle downloaded from url,
 * or, when that fails or url is NULL (networking unavailable), the VPK's own; Sony's always come
 * from the VPK, and are written by the installer as they are */
int vitals_prepare_certificates(const char *sony_path, const char *mozilla_path,
    const char *url, long timeout_seconds, VitalsCertificateBundle *bundle);
void vitals_free_certificates(VitalsCertificateBundle *bundle);

#endif
