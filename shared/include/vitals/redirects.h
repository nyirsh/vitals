#ifndef VITALS_REDIRECTS_H
#define VITALS_REDIRECTS_H

/* The host redirect list; games may not open ux0:data themselves (their sandbox refuses it with
 * 0x80010013), so the kernel plugin reads it for the provider through vitals_redirects_read */
#define VITALS_REDIRECTS_PATH "ux0:data/vitals/redirects.txt"
/* The most one read returns */
#define VITALS_REDIRECTS_CHUNK 256u

/* A system call exported by the kernel plugin: copies up to size bytes of the list, from offset,
 * into buffer in the caller's memory; returns the number of bytes copied, 0 past the end, or a
 * negative error (the file system's own when the list is missing or unreadable) */
int vitals_redirects_read(unsigned int offset, void *buffer, unsigned int size);

#endif
