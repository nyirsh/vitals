/* The CA store's scanner (shared/src/ca_scan.c), as both consoles' libssl index with it: each
 * certificate block with its place in the file, read in pieces of any size, with LF or CRLF lines,
 * and what isn't a block passed over */

#include "vitals/ca_scan.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CERT(body) "-----BEGIN CERTIFICATE-----\n" body "\n-----END CERTIFICATE-----\n"

typedef struct {
	const char *text;
	size_t length;
	uint32_t expected;
	int fail_at;
} File;

static int file_read(void *context, uint32_t offset, void *buffer, uint32_t size)
{
	File *file = context;
	/* The offsets follow one another */
	assert(offset == file->expected);
	if (file->fail_at >= 0 && offset >= (uint32_t)file->fail_at)
		return -5;
	size_t count = offset >= file->length ? 0 : file->length - offset;
	if (count > size)
		count = size;
	memcpy(buffer, file->text + offset, count);
	file->expected += (uint32_t)count;
	return (int)count;
}

typedef struct {
	char blocks[8][9000];
	uint32_t starts[8], ends[8];
	int count, stop_at;
} Found;

static int found(void *context, const unsigned char *block, size_t length, uint32_t start, uint32_t end)
{
	Found *f = context;
	assert(block[length] == '\0' && strlen((const char *)block) == length && f->count < 8);
	memcpy(f->blocks[f->count], block, length + 1);
	f->starts[f->count] = start;
	f->ends[f->count] = end;
	if (++f->count == f->stop_at)
		return 7;
	return 0;
}

static VitalsCaScanner *scanner(uint32_t chunk)
{
	VitalsCaScanner *s = calloc(1, VITALS_CA_SCANNER_SIZE(chunk));
	assert(s != NULL);
	s->chunk_size = chunk;
	return s;
}

static int scan(const char *text, size_t length, uint32_t chunk, uint32_t limit, Found *f, int fail_at)
{
	File file = {text, length, 0, fail_at};
	VitalsCaScanner *s = scanner(chunk);
	memset(f->blocks, 0, sizeof(f->blocks));
	f->count = 0;
	int result = vitals_ca_scan(s, limit, file_read, &file, found, f);
	free(s);
	return result;
}

int main(void)
{
	static Found f;
	f.stop_at = -1;

	/* Comments and titles around two blocks, one with CRLF lines, read a byte at a time and more */
	const char text[] = "# roots\r\nRoot A\n" CERT("QUFBQQ==") "Root B\r\n"
	                    "-----BEGIN CERTIFICATE-----\r\nQkJC\r\nQg==\r\n-----END CERTIFICATE-----\r\n# end\n";
	for (uint32_t chunk = 1; chunk <= 4096; chunk = chunk * 3 + 1) {
		assert(scan(text, strlen(text), chunk, UINT32_MAX, &f, -1) == 0 && f.count == 2);
		assert(strcmp(f.blocks[0], CERT("QUFBQQ==")) == 0);
		assert(strcmp(f.blocks[1], "-----BEGIN CERTIFICATE-----\nQkJC\nQg==\n-----END CERTIFICATE-----\n") == 0);
		/* Their places in the file, CRs and all */
		const char *second = strstr(text, "-----BEGIN CERTIFICATE-----\r\n");
		assert(f.starts[0] == (uint32_t)(strstr(text, CERT("QUFBQQ==")) - text));
		assert(f.ends[0] == f.starts[0] + strlen(CERT("QUFBQQ==")));
		assert(f.starts[1] == (uint32_t)(second - text));
		assert(f.ends[1] == (uint32_t)(strstr(text, "# end") - text));
	}

	/* What isn't a block: a private key, a block that never ends (to the file's end), a file
	 * without its last line break */
	const char others[] = "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n" CERT("Q0NDQw==")
	                      "-----BEGIN CERTIFICATE-----\nnever ends\n";
	assert(scan(others, strlen(others), 512, UINT32_MAX, &f, -1) == 0 && f.count == 1);
	assert(strcmp(f.blocks[0], CERT("Q0NDQw==")) == 0);
	const char unended[] = "-----BEGIN CERTIFICATE-----\nRERE\n-----END CERTIFICATE-----";
	assert(scan(unended, strlen(unended), 512, UINT32_MAX, &f, -1) == 0 && f.count == 1);
	assert(strcmp(f.blocks[0], "-----BEGIN CERTIFICATE-----\nRERE\n-----END CERTIFICATE-----\n") == 0);
	assert(f.ends[0] == strlen(unended));
	assert(scan("", 0, 512, UINT32_MAX, &f, -1) == 0 && f.count == 0);

	/* A line over VITALS_CA_SCAN_LINE ends the block it's in, and a block over VITALS_CA_SCAN_BLOCK
	 * is passed over; the next is still found */
	static char big[40000];
	size_t used = 0;
	used += (size_t)snprintf(big + used, sizeof(big) - used, "-----BEGIN CERTIFICATE-----\n");
	memset(big + used, 'A', VITALS_CA_SCAN_LINE + 5);
	used += VITALS_CA_SCAN_LINE + 5;
	used += (size_t)snprintf(big + used, sizeof(big) - used, "\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n");
	for (int i = 0; i < 200; ++i)
		used += (size_t)snprintf(big + used, sizeof(big) - used, "%064d\n", i);
	used += (size_t)snprintf(big + used, sizeof(big) - used, "-----END CERTIFICATE-----\n" CERT("RUVFRQ=="));
	assert(scan(big, used, 4096, UINT32_MAX, &f, -1) == 0 && f.count == 1);
	assert(strcmp(f.blocks[0], CERT("RUVFRQ==")) == 0);

	/* The finder stops the scan with what it says */
	f.stop_at = 1;
	assert(scan(text, strlen(text), 64, UINT32_MAX, &f, -1) == 7 && f.count == 1);
	f.stop_at = -1;

	/* A file that can't be read, or is over its limit, fails */
	assert(scan(text, strlen(text), 16, UINT32_MAX, &f, 40) == -1);
	assert(scan(text, strlen(text), 16, 20, &f, -1) == -1);
	VitalsCaScanner *s = scanner(16);
	s->chunk_size = 0;
	File file = {text, strlen(text), 0, -1};
	assert(vitals_ca_scan(s, UINT32_MAX, file_read, &file, found, &f) == -1);
	assert(vitals_ca_scan(NULL, UINT32_MAX, file_read, &file, found, &f) == -1);
	free(s);

	puts("CA store scanner: blocks and their places, any read size, LF or CRLF, what isn't a block passed over PASS");
	return 0;
}
