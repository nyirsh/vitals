#include "md5.h"

#include <string.h>

/* MD5 (RFC 1321), for HTTP Digest authentication: the only hash this library needs, so it needs no
 * crypto library (TLS is libssl's) */

static const uint32_t g_sines[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

/* Each round's four rotations */
static const unsigned char g_shifts[4][4] = {{7, 12, 17, 22}, {5, 9, 14, 20}, {4, 11, 16, 23}, {6, 10, 15, 21}};

static uint32_t rotate(uint32_t value, unsigned int bits)
{
    return value << bits | value >> (32u - bits);
}

static void block(VhMd5 *md5, const unsigned char data[64])
{
    uint32_t words[16];
    for (int i = 0; i < 16; ++i)
        words[i] = (uint32_t)data[i * 4] | (uint32_t)data[i * 4 + 1] << 8 | (uint32_t)data[i * 4 + 2] << 16 |
                   (uint32_t)data[i * 4 + 3] << 24;
    uint32_t a = md5->state[0], b = md5->state[1], c = md5->state[2], d = md5->state[3];
    for (unsigned int i = 0; i < 64; ++i) {
        uint32_t f;
        unsigned int word;
        switch (i / 16) {
        case 0:
            f = (b & c) | (~b & d);
            word = i;
            break;
        case 1:
            f = (d & b) | (~d & c);
            word = (5 * i + 1) % 16;
            break;
        case 2:
            f = b ^ c ^ d;
            word = (3 * i + 5) % 16;
            break;
        default:
            f = c ^ (b | ~d);
            word = (7 * i) % 16;
            break;
        }
        uint32_t next = d;
        d = c;
        c = b;
        b += rotate(a + f + g_sines[i] + words[word], g_shifts[i / 16][i % 4]);
        a = next;
    }
    md5->state[0] += a;
    md5->state[1] += b;
    md5->state[2] += c;
    md5->state[3] += d;
}

void vh_md5_init(VhMd5 *md5)
{
    md5->state[0] = 0x67452301;
    md5->state[1] = 0xefcdab89;
    md5->state[2] = 0x98badcfe;
    md5->state[3] = 0x10325476;
    md5->length = 0;
}

void vh_md5_update(VhMd5 *md5, const void *data, size_t size)
{
    const unsigned char *at = data;
    size_t have = (size_t)(md5->length % 64u);
    md5->length += size;
    if (have != 0) {
        size_t take = 64u - have < size ? 64u - have : size;
        memcpy(md5->buffer + have, at, take);
        at += take;
        size -= take;
        if (have + take < 64u)
            return;
        block(md5, md5->buffer);
    }
    for (; size >= 64u; at += 64, size -= 64u)
        block(md5, at);
    memcpy(md5->buffer, at, size);
}

void vh_md5_finish(VhMd5 *md5, unsigned char digest[16])
{
    /* 0x80, zeros up to 56 bytes into a block, then the length in bits, little-endian */
    uint64_t bits = md5->length * 8u;
    static const unsigned char padding[64] = {0x80};
    size_t have = (size_t)(md5->length % 64u);
    vh_md5_update(md5, padding, have < 56u ? 56u - have : 120u - have);
    unsigned char length[8];
    for (int i = 0; i < 8; ++i)
        length[i] = (unsigned char)(bits >> (8 * i));
    vh_md5_update(md5, length, sizeof(length));
    for (int i = 0; i < 4; ++i)
        for (int k = 0; k < 4; ++k)
            digest[i * 4 + k] = (unsigned char)(md5->state[i] >> (8 * k));
    memset(md5, 0, sizeof(*md5));
}

void vh_md5_hex(const unsigned char digest[16], char out[33])
{
    static const char digits[] = "0123456789abcdef";
    for (int i = 0; i < 16; ++i) {
        out[i * 2] = digits[digest[i] >> 4];
        out[i * 2 + 1] = digits[digest[i] & 15];
    }
    out[32] = '\0';
}
