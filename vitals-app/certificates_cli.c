#include "certificates.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Host-only exercise of the exact installer preparation code; no system writes */
int main(int argc, char **argv) {
    VitalsCertificateBundle bundle;
    /* sony mozilla url output [timeout [custom]] */
    if (argc < 5 || argc > 7) return 2;
    const char *url = strcmp(argv[3], "offline") == 0 ? NULL : argv[3];
    long timeout = argc >= 6 ? strtol(argv[5], NULL, 10) : 30;
    const char *custom = argc == 7 ? argv[6] : NULL;
    if (vitals_prepare_certificates(argv[1], argv[2], custom, url, timeout, &bundle) != 0) {
        fprintf(stderr, "Certificate preparation failed: %s; errno=%d crypto=0x%08lX\n",
            bundle.failure_stage != NULL ? bundle.failure_stage : "invalid input",
            bundle.failure_errno, bundle.failure_crypto_error);
        return 1;
    }
    FILE *file = fopen(argv[4], "wb");
    if (file == NULL) { vitals_free_certificates(&bundle); return 1; }
    int result = fwrite(bundle.data, 1, bundle.size, file) == bundle.size ? 0 : 1;
    if (fclose(file) != 0) result = 1;
    printf("downloaded=%d error=%d http=%ld sony=%zu mozilla=%zu custom=%zu combined=%zu bytes=%zu\n",
        bundle.downloaded, bundle.download_error, bundle.http_status, bundle.sony_count,
        bundle.mozilla_count, bundle.custom_count, bundle.combined_count, bundle.size);
    vitals_free_certificates(&bundle);
    return result;
}
