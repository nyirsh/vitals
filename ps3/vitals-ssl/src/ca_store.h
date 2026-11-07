#ifndef VITALS_SSL_CA_STORE_H
#define VITALS_SSL_CA_STORE_H

#include <stddef.h>
#include <stdint.h>

/* The CA store (ca_store.c): Sony's CA certificates and Mozilla's bundle, as libhttp's check asks
 * for them */

/* cellSslCertificateLoader: the CA certificates the flags pick, as PEM, into buffer, and the size
 * they take into *required */
int cellSslCertificateLoader(uint64_t flags, char *buffer, size_t size, size_t *required);

/* NID 0x205B060C: a name's CA mask and flag among Sony's CAs */
int cellSsl_205B060C(const void *name, uint64_t *mask, int *flag);

/* NID 0x68D3409E: the PEM of the CA with that subject name, among those the mask allows, into
 * buffer, and its size into *required */
int cellSsl_68D3409E(const void *name, char *buffer, size_t size, size_t *required, uint64_t mask);

/* NID 0xCC6A0CB5: libhttp's CA mask, at the end of loading a game's CA list */
int cellSsl_CC6A0CB5(uint64_t *mask);

/* NID 0x06B1E9BF: cellSslCertificateLoader without keeping the flags or the games' CA05 */
int cellSsl_06B1E9BF(uint64_t flags, char *buffer, size_t size, size_t *required);
/* NID 0x404136C1: 0 when each of the flags' bits is one of Sony's CAs */
int cellSsl_404136C1(uint64_t flags);
/* NID 0x86C38810: the first CA with one of *flags' bits, into the BIO, its bit out of *flags */
int cellSsl_86C38810(uint64_t *flags, void *bio, char *buffer, uint32_t size);

/* Forgets the bundle's index, which the pool held: cellSslEnd's */
void vs_ca_store_end(void);

/* For the debug log: where the CA with that subject (its DER, tag and all) is, "Sony's CA05",
 * "Sony's CA_LIST.cer", "Mozilla's bundle", or NULL for neither, in text (24 bytes) */
const char *vs_ca_store_source(const unsigned char *der, size_t length, char text[24]);

#endif
