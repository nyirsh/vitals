#ifndef VITALS_CA_INDEX_H
#define VITALS_CA_INDEX_H

#include <mbedtls/x509_crt.h>
#include <stddef.h>
#include <stdint.h>

/* The CA bundle is not kept parsed in memory
 * Only a small index (subject hash plus file position of each PEM block) is built
 * at start-up; a root is parsed on demand from the file while a handshake verifies
 * a certificate chain */

#define VITALS_CA_INDEX_MAX_ENTRIES 512u
#define VITALS_CA_INDEX_MAX_BLOCK 8192u
#define VITALS_CA_INDEX_PATH_SIZE 0x124u

typedef struct VitalsCaEntry {
    uint32_t name_hash;
    uint32_t offset;
    uint32_t length;
} VitalsCaEntry;

typedef struct VitalsCaIndex {
    VitalsCaEntry *entries;
    size_t count;
    char path[VITALS_CA_INDEX_PATH_SIZE];
} VitalsCaIndex;

int vitals_ca_index_build(VitalsCaIndex *index, const char *path);
void vitals_ca_index_free(VitalsCaIndex *index);

/* An mbedtls_x509_crt_ca_cb_t: returns a newly allocated chain of candidate issuers, which
 * Mbed TLS frees after use */
int vitals_ca_index_find(void *context, const mbedtls_x509_crt *child,
    mbedtls_x509_crt **candidates);

#endif
