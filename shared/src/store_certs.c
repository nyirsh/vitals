/* Mozilla's part of the CA store, without Sony's (vitals/store_certs.h): plain C on the PEM text, for
 * both consoles' apps and the host tests alike */

#include "vitals/store_certs.h"

#include <string.h>

static const char k_begin[] = "-----BEGIN CERTIFICATE-----", k_end[] = "-----END CERTIFICATE-----",
                  k_marker_start[] = VITALS_EARLIER_CUSTOM_MARKER;

/* Where needle starts in data from offset from, or length when it isn't there */
static size_t find(const char *data, size_t length, size_t from, const char *needle)
{
	size_t size = strlen(needle);
	for (size_t at = from; at + size <= length; ++at)
		if (data[at] == needle[0] && memcmp(data + at, needle, size) == 0)
			return at;
	return length;
}

/* The same, only where it starts a line */
static size_t find_line(const char *data, size_t length, size_t from, const char *needle)
{
	for (size_t at = find(data, length, from, needle); at < length; at = find(data, length, at + 1, needle))
		if (at == 0 || data[at - 1] == '\n')
			return at;
	return length;
}

static int is_base64(char c)
{
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' ||
	       c == '=';
}

static int is_space(char c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/* A certificate's PEM block: from its BEGIN line to the end of its END line, and its base64 text
 * between them */
typedef struct {
	size_t start, end, body, body_end;
} Block;

/* The next block from offset from: 1 with a whole one (only base64 and spaces between its lines,
 * some base64), 0 with a broken one (block still says where it ends, to skip it), -1 with none */
static int next_block(const char *data, size_t length, size_t from, Block *block)
{
	size_t start = find_line(data, length, from, k_begin);
	if (start == length)
		return -1;
	block->start = start;
	block->body = start + sizeof(k_begin) - 1;
	size_t close = find(data, length, block->body, k_end),
	       again = find_line(data, length, block->body, k_begin);
	if (close == length || again < close) {
		/* No end, or another block before it: this one's broken, up to the next */
		block->end = block->body_end = again;
		return 0;
	}
	block->body_end = close;
	size_t end = close + sizeof(k_end) - 1;
	while (end < length && data[end] != '\n')
		++end;
	block->end = end < length ? end + 1 : end;
	unsigned letters = 0;
	for (size_t i = block->body; i < close; ++i) {
		if (is_base64(data[i]))
			++letters;
		else if (!is_space(data[i]))
			return 0;
	}
	/* Anything after the END marker on its line but spaces makes it a broken block too */
	for (size_t i = close + sizeof(k_end) - 1; i < block->end; ++i)
		if (!is_space(data[i]))
			return 0;
	return letters != 0;
}

/* Whether two blocks hold the same certificate: the same base64, wherever their lines break */
static int same_body(const char *a, const Block *x, const char *b, const Block *y)
{
	size_t i = x->body, j = y->body;
	for (;;) {
		while (i < x->body_end && is_space(a[i]))
			++i;
		while (j < y->body_end && is_space(b[j]))
			++j;
		if (i == x->body_end || j == y->body_end)
			return i == x->body_end && j == y->body_end;
		if (a[i++] != b[j++])
			return 0;
	}
}

/* Whether data, up to length, has a whole block with block's certificate */
static int holds(const char *data, size_t length, const char *source, const Block *block)
{
	Block other;
	int status;
	for (size_t at = 0; (status = next_block(data, length, at, &other)) >= 0; at = other.end)
		if (status == 1 && same_body(data, &other, source, block))
			return 1;
	return 0;
}

static int put(char *out, size_t capacity, size_t *used, const char *data, size_t length)
{
	if (length > capacity - *used)
		return 0;
	memcpy(out + *used, data, length);
	*used += length;
	return 1;
}

int vitals_store_mozilla(const char *bundle, size_t bundle_length, const char *sony, size_t sony_length,
                         char *out, size_t capacity, size_t *length, VitalsStoreFilter *filter)
{
	memset(filter, 0, sizeof(*filter));
	*length = 0;
	size_t own = find_line(bundle, bundle_length, 0, k_marker_start), used = 0, at = 0;
	filter->cut_custom = own != bundle_length;
	Block block;
	int status;
	while ((status = next_block(bundle, own, at, &block)) >= 0) {
		/* What's before the block, then the block unless it's Sony's */
		if (!put(out, capacity, &used, bundle + at, block.start - at))
			return -1;
		if (status == 1 && sony != NULL && holds(sony, sony_length, bundle, &block)) {
			++filter->sony;
		} else {
			if (!put(out, capacity, &used, bundle + block.start, block.end - block.start))
				return -1;
			filter->kept += status == 1;
		}
		at = block.end;
	}
	if (!put(out, capacity, &used, bundle + at, own - at))
		return -1;
	if (used != 0 && out[used - 1] != '\n' && !put(out, capacity, &used, "\n", 1))
		return -1;
	*length = used;
	return 0;
}
