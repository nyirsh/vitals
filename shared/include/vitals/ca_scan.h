#ifndef VITALS_CA_SCAN_H
#define VITALS_CA_SCAN_H

#include <stddef.h>
#include <stdint.h>

/* The certificate blocks of a CA store's file, for both consoles' libssl to index: each
 * "-----BEGIN CERTIFICATE-----" line through its "-----END CERTIFICATE-----" line, with where it is
 * in the file, read through a callback a piece at a time. What isn't a block (comments, titles, a
 * private key, a block over VITALS_CA_SCAN_BLOCK bytes, one that never ends) is passed over; whether
 * a block is a certificate is the caller's to find out. Plain C, no allocation: the caller gives the
 * scanner's memory */

/* The longest block, and the longest line that counts (a longer one is passed over, ending any
 * block it's in) */
#define VITALS_CA_SCAN_BLOCK 8192u
#define VITALS_CA_SCAN_LINE 160u
/* Up to size bytes of the file from offset into buffer: how many (0 at its end), or negative when
 * it can't be read. The offsets asked for follow one another from 0 */
typedef int (*VitalsCaScanRead)(void *context, uint32_t offset, void *buffer, uint32_t size);
/* A block: its lines joined with '\n' (a line's '\r' dropped), length bytes and a NUL after them,
 * and its place in the file, from its BEGIN line's start to past its END line's line break. 0 to go
 * on, anything else to stop the scan with it */
typedef int (*VitalsCaScanFound)(void *context, const unsigned char *block, size_t length, uint32_t start,
                                 uint32_t end);

/* The scanner's memory, with chunk_size bytes after it for the reads: each asks for at most that
 * (the Vita's go through a system call, so it reads 4 KiB at a time; the PS3, in a game's pool, 512
 * bytes) */
typedef struct VitalsCaScanner {
	uint32_t chunk_size;
	unsigned char line[VITALS_CA_SCAN_LINE];
	unsigned char block[VITALS_CA_SCAN_BLOCK + 2];
	unsigned char chunk[];
} VitalsCaScanner;

/* What to allocate for a scanner reading chunk_size bytes at a time */
#define VITALS_CA_SCANNER_SIZE(chunk_size) (sizeof(VitalsCaScanner) + (chunk_size))

/* Every block of the file, to found, read scanner->chunk_size bytes at a time (set by the caller,
 * not 0). limit is the file's largest size: reading past it fails. 0 at the file's end, -1 when it
 * can't be read (or is over limit), or what found stopped with */
int vitals_ca_scan(VitalsCaScanner *scanner, uint32_t limit, VitalsCaScanRead read, void *read_context,
                   VitalsCaScanFound found, void *found_context);

#endif
