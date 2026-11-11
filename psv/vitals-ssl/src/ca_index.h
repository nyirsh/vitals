#ifndef VITALS_CA_INDEX_H
#define VITALS_CA_INDEX_H

#include <mbedtls/x509_crt.h>
#include <stddef.h>
#include <stdint.h>

/* The CA bundle is not kept parsed in memory
 * Only a small index (subject hash plus file position of each PEM block) is built
 * at start-up; a root is parsed on demand from the file while a handshake verifies
 * a certificate chain. The file is read through a function: on the Vita, the kernel plugin's
 * vitals_ca_read, as games can't open the store's folder themselves */

#define VITALS_CA_INDEX_MAX_ENTRIES 512u
#define VITALS_CA_INDEX_MAX_BLOCK 8192u

/* Up to size bytes of the bundle from offset into buffer: how many (0 past its end), or a negative
 * error */
typedef int (*VitalsCaRead)(void *context, uint32_t offset, void *buffer, uint32_t size);

typedef struct VitalsCaEntry {
    uint32_t name_hash;
    uint32_t offset;
    uint32_t length;
} VitalsCaEntry;

typedef struct VitalsCaIndex {
    VitalsCaEntry *entries;
    size_t count;
    VitalsCaRead read;
    void *context;
} VitalsCaIndex;

int vitals_ca_index_build(VitalsCaIndex *index, VitalsCaRead read, void *context);
/* Reads a block of the bundle through the index's function: 0, or -1 when it isn't all there */
int vitals_ca_index_read(const VitalsCaIndex *index, uint32_t offset, void *buffer, uint32_t size);
/* A VitalsCaRead for a file the process can open itself, context its path (the host tests) */
int vitals_ca_file_read(void *path, uint32_t offset, void *buffer, uint32_t size);
void vitals_ca_index_free(VitalsCaIndex *index);

/* An mbedtls_x509_crt_ca_cb_t: returns a newly allocated chain of candidate issuers, which
 * Mbed TLS frees after use */
int vitals_ca_index_find(void *context, const mbedtls_x509_crt *child,
    mbedtls_x509_crt **candidates);

/* 1 when certificate is self-signed and its exact copy is among the trusted certificates find
 * returns: such a server certificate is trusted as itself, even when it is not a CA
 * Mbed TLS applies this rule to a fixed trusted list but not when trust comes from a callback, so
 * the providers apply it themselves */
int vitals_ca_trusts_exact(mbedtls_x509_crt_ca_cb_t find, void *context,
    const mbedtls_x509_crt *certificate);

#endif
