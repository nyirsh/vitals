#ifndef VITALS_SSL_SHA1_H
#define VITALS_SSL_SHA1_H

/* SHA-1 on its own, for checking Sony's CA files (ca_store.c): no allocation and nothing to
 * initialize, so it works where PSA's doesn't, before cellSslInit and after cellSslEnd, which is
 * when the XMB loads its CAs */

#include <stddef.h>
#include <stdint.h>

typedef struct VsSha1 {
	uint32_t state[5];
	uint64_t length; /* bytes so far */
	unsigned char block[64];
	size_t used;
} VsSha1;

void vs_sha1_start(VsSha1 *sha1);
void vs_sha1_update(VsSha1 *sha1, const void *data, size_t size);
void vs_sha1_finish(VsSha1 *sha1, unsigned char digest[20]);

#endif
