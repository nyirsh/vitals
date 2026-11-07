/* The certificate blocks of a CA store's file (vitals/ca_scan.h), for the Vita's and the PS3's libssl */

#include "vitals/ca_scan.h"

#include <string.h>

static const char k_begin[] = "-----BEGIN CERTIFICATE-----";
static const char k_end[] = "-----END CERTIFICATE-----";

typedef struct {
	VitalsCaScanner *scanner;
	VitalsCaScanRead read;
	void *context;
	uint32_t limit, base;
	size_t at, length;
} Reader;

/* 1 for a byte, 0 at the end, -1 when it can't be read */
static int next_byte(Reader *reader, unsigned char *byte)
{
	if (reader->at == reader->length) {
		uint32_t next = reader->base + (uint32_t)reader->length;
		if (next >= reader->limit)
			return -1;
		uint32_t chunk = reader->scanner->chunk_size;
		uint32_t want = reader->limit - next < chunk ? reader->limit - next : chunk;
		int count = reader->read(reader->context, next, reader->scanner->chunk, want);
		if (count < 0 || (uint32_t)count > want)
			return -1;
		if (count == 0)
			return 0;
		reader->base = next;
		reader->length = (size_t)count;
		reader->at = 0;
	}
	*byte = reader->scanner->chunk[reader->at++];
	return 1;
}

static int starts_with(const unsigned char *line, size_t length, const char *prefix, size_t prefix_length)
{
	return length >= prefix_length && memcmp(line, prefix, prefix_length) == 0;
}

int vitals_ca_scan(VitalsCaScanner *scanner, uint32_t limit, VitalsCaScanRead read, void *read_context,
                   VitalsCaScanFound found, void *found_context)
{
	if (scanner == NULL || scanner->chunk_size == 0 || read == NULL || found == NULL)
		return -1;
	Reader reader = {scanner, read, read_context, limit, 0, 0, 0};
	unsigned char *line = scanner->line, *block = scanner->block;
	size_t block_length = 0;
	uint32_t block_start = 0;
	int in_block = 0;
	for (;;) {
		size_t length = 0;
		int overflow = 0, status;
		uint32_t line_start = reader.base + (uint32_t)reader.at;
		unsigned char byte;
		while ((status = next_byte(&reader, &byte)) == 1 && byte != '\n') {
			if (length < VITALS_CA_SCAN_LINE)
				line[length++] = byte;
			else
				overflow = 1;
		}
		if (status < 0)
			return -1;
		if (status == 0 && length == 0 && !overflow)
			return 0;
		if (length > 0 && line[length - 1] == '\r')
			--length;
		if (!in_block && !overflow && starts_with(line, length, k_begin, sizeof(k_begin) - 1)) {
			in_block = 1;
			block_start = line_start;
			block_length = 0;
		}
		if (in_block) {
			if (overflow || block_length + length + 1 > VITALS_CA_SCAN_BLOCK) {
				in_block = 0;
			} else {
				memcpy(block + block_length, line, length);
				block_length += length;
				block[block_length++] = '\n';
				if (starts_with(line, length, k_end, sizeof(k_end) - 1)) {
					in_block = 0;
					block[block_length] = '\0';
					int result = found(found_context, block, block_length, block_start,
					                   reader.base + (uint32_t)reader.at);
					if (result != 0)
						return result;
				}
			}
		}
		if (status == 0)
			return 0;
	}
}
