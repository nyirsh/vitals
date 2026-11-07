/* gzip bodies (RFC 1952) and the DEFLATE inside them (RFC 1951), decoded in one go, for a client
 * with gzip on (cellHttpClientSetGzipEncoding): Sony's libhttp hands such a body to the game
 * decoded. No zlib on the PS3's side of vitals, so this is its own decoder: stored, fixed and
 * dynamic Huffman blocks, the gzip header's optional fields, and its CRC-32 and size checked */

#include "vh.h"

#include <string.h>

typedef struct Bits {
	const unsigned char *data;
	size_t size, at;
	uint32_t buffer;
	int count;
} Bits;

typedef struct Output {
	unsigned char *data;
	size_t size, capacity;
} Output;

/* A Huffman code as counts of each length and the symbols in order */
typedef struct Huffman {
	uint16_t counts[16];
	uint16_t symbols[320];
} Huffman;

static int bit(Bits *bits)
{
	if (bits->count == 0) {
		if (bits->at >= bits->size)
			return -1;
		bits->buffer = bits->data[bits->at++];
		bits->count = 8;
	}
	int value = (int)(bits->buffer & 1);
	bits->buffer >>= 1;
	--bits->count;
	return value;
}

static int read_bits(Bits *bits, int need, uint32_t *value)
{
	uint32_t result = 0;
	for (int i = 0; i < need; ++i) {
		int one = bit(bits);
		if (one < 0)
			return -1;
		result |= (uint32_t)one << i;
	}
	*value = result;
	return 0;
}

static int put(Output *out, unsigned char byte)
{
	if (out->size == out->capacity) {
		size_t capacity = out->capacity != 0 ? out->capacity * 2 : 4096;
		unsigned char *grown = vh_alloc(capacity);
		if (grown == NULL)
			return -1;
		if (out->size > 0)
			memcpy(grown, out->data, out->size);
		vh_free(out->data);
		out->data = grown;
		out->capacity = capacity;
	}
	out->data[out->size++] = byte;
	return 0;
}

/* The code for the lengths given: 0, or -1 for lengths no code has */
static int build(Huffman *code, const uint8_t *lengths, int count)
{
	memset(code->counts, 0, sizeof(code->counts));
	for (int i = 0; i < count; ++i)
		code->counts[lengths[i]]++;
	code->counts[0] = 0;
	int left = 1;
	for (int length = 1; length < 16; ++length) {
		left <<= 1;
		left -= code->counts[length];
		if (left < 0)
			return -1;
	}
	uint16_t offsets[16];
	offsets[1] = 0;
	for (int length = 1; length < 15; ++length)
		offsets[length + 1] = (uint16_t)(offsets[length] + code->counts[length]);
	for (int i = 0; i < count; ++i)
		if (lengths[i] != 0)
			code->symbols[offsets[lengths[i]]++] = (uint16_t)i;
	return 0;
}

static int decode(Bits *bits, const Huffman *code)
{
	int value = 0, first = 0, index = 0;
	for (int length = 1; length < 16; ++length) {
		int one = bit(bits);
		if (one < 0)
			return -1;
		value |= one;
		int count = code->counts[length];
		if (value - count < first)
			return code->symbols[index + (value - first)];
		index += count;
		first += count;
		first <<= 1;
		value <<= 1;
	}
	return -1;
}

static const uint16_t k_length_base[29] = {3,  4,  5,  6,  7,  8,  9,  10, 11,  13,  15,  17,  19,  23, 27,
                                           31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
static const uint8_t k_length_extra[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
static const uint16_t k_distance_base[30] = {1,   2,   3,   4,   5,   7,    9,    13,   17,   25,   33,   49,   65,    97,    129,
                                             193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
static const uint8_t k_distance_extra[30] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

static int codes(Bits *bits, Output *out, const Huffman *lengths, const Huffman *distances)
{
	for (;;) {
		int symbol = decode(bits, lengths);
		if (symbol < 0)
			return -1;
		if (symbol < 256) {
			if (put(out, (unsigned char)symbol) != 0)
				return -1;
			continue;
		}
		if (symbol == 256)
			return 0;
		symbol -= 257;
		if (symbol >= 29)
			return -1;
		uint32_t extra = 0;
		if (read_bits(bits, k_length_extra[symbol], &extra) != 0)
			return -1;
		size_t length = k_length_base[symbol] + extra;
		int distance_symbol = decode(bits, distances);
		if (distance_symbol < 0 || distance_symbol >= 30)
			return -1;
		if (read_bits(bits, k_distance_extra[distance_symbol], &extra) != 0)
			return -1;
		size_t distance = k_distance_base[distance_symbol] + extra;
		if (distance > out->size)
			return -1;
		for (size_t i = 0; i < length; ++i)
			if (put(out, out->data[out->size - distance]) != 0)
				return -1;
	}
}

static int fixed(Bits *bits, Output *out)
{
	static Huffman lengths, distances;
	static int built;
	if (!built) {
		uint8_t sizes[288];
		int i = 0;
		for (; i < 144; ++i)
			sizes[i] = 8;
		for (; i < 256; ++i)
			sizes[i] = 9;
		for (; i < 280; ++i)
			sizes[i] = 7;
		for (; i < 288; ++i)
			sizes[i] = 8;
		build(&lengths, sizes, 288);
		for (i = 0; i < 30; ++i)
			sizes[i] = 5;
		build(&distances, sizes, 30);
		built = 1;
	}
	return codes(bits, out, &lengths, &distances);
}

static int dynamic(Bits *bits, Output *out)
{
	static const uint8_t order[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
	uint32_t literal_count, distance_count, code_count;
	if (read_bits(bits, 5, &literal_count) != 0 || read_bits(bits, 5, &distance_count) != 0 ||
	    read_bits(bits, 4, &code_count) != 0)
		return -1;
	literal_count += 257;
	distance_count += 1;
	code_count += 4;
	if (literal_count > 286 || distance_count > 30)
		return -1;
	uint8_t sizes[320];
	memset(sizes, 0, sizeof(sizes));
	for (uint32_t i = 0; i < code_count; ++i) {
		uint32_t size;
		if (read_bits(bits, 3, &size) != 0)
			return -1;
		sizes[order[i]] = (uint8_t)size;
	}
	Huffman code_code;
	if (build(&code_code, sizes, 19) != 0)
		return -1;
	uint32_t at = 0;
	while (at < literal_count + distance_count) {
		int symbol = decode(bits, &code_code);
		if (symbol < 0)
			return -1;
		if (symbol < 16) {
			sizes[at++] = (uint8_t)symbol;
			continue;
		}
		uint32_t repeat = 0, extra = 0;
		uint8_t value = 0;
		if (symbol == 16) {
			if (at == 0 || read_bits(bits, 2, &extra) != 0)
				return -1;
			value = sizes[at - 1];
			repeat = 3 + extra;
		} else if (symbol == 17) {
			if (read_bits(bits, 3, &extra) != 0)
				return -1;
			repeat = 3 + extra;
		} else {
			if (read_bits(bits, 7, &extra) != 0)
				return -1;
			repeat = 11 + extra;
		}
		if (at + repeat > literal_count + distance_count)
			return -1;
		while (repeat-- > 0)
			sizes[at++] = value;
	}
	if (sizes[256] == 0)
		return -1;
	Huffman lengths, distances;
	if (build(&lengths, sizes, (int)literal_count) != 0 || build(&distances, sizes + literal_count, (int)distance_count) != 0)
		return -1;
	return codes(bits, out, &lengths, &distances);
}

static int stored(Bits *bits, Output *out)
{
	bits->count = 0;
	if (bits->at + 4 > bits->size)
		return -1;
	unsigned length = (unsigned)bits->data[bits->at] | (unsigned)bits->data[bits->at + 1] << 8;
	unsigned complement = (unsigned)bits->data[bits->at + 2] | (unsigned)bits->data[bits->at + 3] << 8;
	bits->at += 4;
	if ((length ^ 0xffffu) != complement || bits->at + length > bits->size)
		return -1;
	for (unsigned i = 0; i < length; ++i)
		if (put(out, bits->data[bits->at++]) != 0)
			return -1;
	return 0;
}

static uint32_t crc32_of(const unsigned char *data, size_t size)
{
	uint32_t crc = 0xffffffffu;
	for (size_t i = 0; i < size; ++i) {
		crc ^= data[i];
		for (int k = 0; k < 8; ++k)
			crc = crc & 1 ? (crc >> 1) ^ 0xedb88320u : crc >> 1;
	}
	return ~crc;
}

int vh_gunzip(const unsigned char *data, size_t size, unsigned char **out, size_t *out_size)
{
	*out = NULL;
	*out_size = 0;
	if (size < 18 || data[0] != 0x1f || data[1] != 0x8b || data[2] != 8)
		return -1;
	int flags = data[3];
	size_t at = 10;
	if (flags & 4) {
		if (at + 2 > size)
			return -1;
		at += 2 + ((size_t)data[at] | (size_t)data[at + 1] << 8);
	}
	for (int field = 8; field <= 16; field <<= 1)
		if (flags & field) {
			while (at < size && data[at] != 0)
				++at;
			++at;
		}
	if (flags & 2)
		at += 2;
	if (at + 8 > size)
		return -1;
	Bits bits = {data, size - 8, at, 0, 0};
	Output output = {NULL, 0, 0};
	int last = 0;
	while (!last) {
		uint32_t header;
		if (read_bits(&bits, 3, &header) != 0)
			goto fail;
		last = (int)(header & 1);
		int type = (int)(header >> 1);
		int rc = type == 0 ? stored(&bits, &output) : type == 1 ? fixed(&bits, &output) : type == 2 ? dynamic(&bits, &output) : -1;
		if (rc != 0)
			goto fail;
	}
	const unsigned char *trailer = data + size - 8;
	uint32_t crc = (uint32_t)trailer[0] | (uint32_t)trailer[1] << 8 | (uint32_t)trailer[2] << 16 | (uint32_t)trailer[3] << 24;
	uint32_t length = (uint32_t)trailer[4] | (uint32_t)trailer[5] << 8 | (uint32_t)trailer[6] << 16 | (uint32_t)trailer[7] << 24;
	if (crc != crc32_of(output.data, output.size) || length != (uint32_t)output.size)
		goto fail;
	*out = output.data;
	*out_size = output.size;
	return 0;
fail:
	vh_free(output.data);
	return -1;
}
