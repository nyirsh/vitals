#ifndef VH_MD5_H
#define VH_MD5_H

#include <stddef.h>
#include <stdint.h>

typedef struct VhMd5
{
    uint32_t state[4];
    /* Bytes hashed so far */
    uint64_t length;
    unsigned char buffer[64];
} VhMd5;

void vh_md5_init(VhMd5 *md5);
void vh_md5_update(VhMd5 *md5, const void *data, size_t size);
/* The digest; the context is wiped */
void vh_md5_finish(VhMd5 *md5, unsigned char digest[16]);
/* A digest as lowercase hex */
void vh_md5_hex(const unsigned char digest[16], char out[33]);

#endif
