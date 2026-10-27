#include "dns_message.h"

/* A DNS query: a 12-byte header, at least a one-letter name, and the type and class */
#define DNS_MESSAGE_MIN 17u
#define DNS_HEADER_SIZE 12u
#define DNS_CLASS_INTERNET 1u
/* Each rewritten answer: a pointer to the question's name, type, class, TTL and the address */
#define DNS_ANSWER_SIZE 16u

static unsigned read16(const unsigned char *at)
{
    return (unsigned)at[0] << 8 | at[1];
}

static uint32_t read32(const unsigned char *at)
{
    return (uint32_t)at[0] << 24 | (uint32_t)at[1] << 16 | (uint32_t)at[2] << 8 | at[3];
}

static unsigned char lower(unsigned char c)
{
    return c >= 'A' && c <= 'Z' ? (unsigned char)(c | 0x20u) : c;
}

int vitals_dns_query_header(const unsigned char *header)
{
    return (header[2] & 0x80u) == 0 && ((header[2] >> 3) & 0x0fu) == 0 && header[4] == 0 && header[5] == 1 &&
           (header[6] | header[7] | header[8] | header[9]) == 0 && header[10] == 0 && header[11] <= 1;
}

/* A standard answer (QR set, opcode 0) to query id */
static int dns_answer_header(const unsigned char *message, size_t length, uint16_t id)
{
    return length >= DNS_HEADER_SIZE && read16(message) == id && (message[2] & 0x80u) != 0 &&
           ((message[2] >> 3) & 0x0fu) == 0;
}

/* The offset just past the name at message[at] (labels, ending in a zero or a pointer), or 0 */
static size_t skip_name(const unsigned char *message, size_t length, size_t at)
{
    /* A name is at most 255 bytes, so it holds no more than 128 labels */
    for (unsigned labels = 0; labels < 128 && at < length; ++labels)
    {
        unsigned label = message[at];
        if (label == 0)
            return at + 1;
        if ((label & 0xc0u) == 0xc0u)
            return length - at >= 2 ? at + 2 : 0;
        if (label > 63)
            return 0;
        at += 1u + label;
    }
    return 0;
}

/* 1 when the uncompressed name at message[at] is name (dotted), compared without case; *end
 * receives the offset just past it */
static int name_matches(const unsigned char *message, size_t length, size_t at, const char *name, size_t *end)
{
    size_t n = 0;

    for (;;)
    {
        if (at >= length)
            return 0;
        size_t label = message[at++];
        if (label == 0)
            break;
        if (label > 63 || label > length - at)
            return 0;
        if (n != 0 && name[n++] != '.')
            return 0;
        for (size_t i = 0; i < label; ++i, ++n)
            if (name[n] == '\0' || message[at + i] == '.' || lower(message[at + i]) != lower((unsigned char)name[n]))
                return 0;
        at += label;
    }
    *end = at;
    return n != 0 && name[n] == '\0';
}

int vitals_dns_query_name(const unsigned char *message, size_t length, char *name, size_t size, unsigned *type)
{
    size_t at = DNS_HEADER_SIZE, out = 0;

    if (message == NULL || name == NULL || type == NULL || size < 2 || length < DNS_MESSAGE_MIN ||
        !vitals_dns_query_header(message))
        return -1;
    for (;;)
    {
        if (at >= length)
            return -1;
        size_t label = message[at++];
        if (label == 0)
            break;
        /* Questions never use compression; a longer label or one past the end is malformed */
        if (label > 63 || label > length - at)
            return -1;
        if (out != 0)
        {
            if (out + 1 >= size)
                return -1;
            name[out++] = '.';
        }
        if (label >= size - out)
            return -1;
        for (size_t i = 0; i < label; ++i)
        {
            unsigned char c = message[at + i];
            name[out++] = c > 0x20 && c < 0x7f ? (char)c : '?';
        }
        at += label;
    }
    /* The question ends the message, unless the one additional record follows it */
    if (out == 0 || length - at < 4 || (message[11] == 0 ? length - at != 4 : length - at < 4 + 11))
        return -1;
    name[out] = '\0';
    *type = read16(message + at);
    return 0;
}

/* Writes name (dotted, length characters) as labels ending in a zero; returns the bytes written,
 * or 0 when it is not a valid host name or does not fit */
static size_t write_name(unsigned char *output, size_t capacity, const char *name, size_t length)
{
    size_t at = 0, start = 0;

    if (name == NULL || length == 0 || length > VITALS_DNS_HOST_MAX - 1 || capacity < length + 2)
        return 0;
    for (size_t i = 0; i <= length; ++i)
    {
        if (i < length && name[i] != '.')
            continue;
        size_t label = i - start;
        if (label == 0 || label > 63)
            return 0;
        output[at++] = (unsigned char)label;
        for (size_t c = start; c < i; ++c)
            output[at++] = (unsigned char)name[c];
        start = i + 1;
    }
    output[at++] = 0;
    return at;
}

static size_t text_length(const char *text)
{
    size_t length = 0;
    while (length < VITALS_DNS_HOST_MAX && text[length] != '\0')
        ++length;
    return length;
}

size_t vitals_dns_rename_query(const unsigned char *query, size_t length, const char *name, size_t name_length,
                               unsigned char *output, size_t capacity)
{
    char asked[VITALS_DNS_HOST_MAX];
    unsigned type;

    if (output == NULL || capacity < DNS_HEADER_SIZE ||
        vitals_dns_query_name(query, length, asked, sizeof(asked), &type) != 0)
        return 0;
    size_t end = skip_name(query, length, DNS_HEADER_SIZE);
    size_t written = write_name(output + DNS_HEADER_SIZE, capacity - DNS_HEADER_SIZE, name, name_length);
    if (end == 0 || written == 0 || length - end > capacity - DNS_HEADER_SIZE - written)
        return 0;
    for (size_t i = 0; i < DNS_HEADER_SIZE; ++i)
        output[i] = query[i];
    /* The type, the class and any additional record follow as they were */
    unsigned char *rest = output + DNS_HEADER_SIZE + written;
    for (size_t i = end; i < length; ++i)
        *rest++ = query[i];
    return DNS_HEADER_SIZE + written + (length - end);
}

int vitals_dns_answer_addresses(const unsigned char *message, size_t length, uint16_t id,
                                VitalsDnsAddress *addresses, unsigned capacity, uint32_t *ttl)
{
    if (message == NULL || addresses == NULL || ttl == NULL || !dns_answer_header(message, length, id))
        return -1;
    size_t at = DNS_HEADER_SIZE;
    for (unsigned questions = read16(message + 4); questions > 0; --questions)
    {
        at = skip_name(message, length, at);
        if (at == 0 || length - at < 4)
            return -1;
        at += 4;
    }
    /* A name error or a server failure has no addresses */
    if ((message[3] & 0x0fu) != 0)
        return 0;
    unsigned count = 0;
    uint32_t lowest = UINT32_MAX;
    for (unsigned answers = read16(message + 6); answers > 0; --answers)
    {
        at = skip_name(message, length, at);
        if (at == 0 || length - at < 10)
            return -1;
        unsigned type = read16(message + at), record_class = read16(message + at + 2);
        uint32_t record_ttl = read32(message + at + 4);
        size_t data = read16(message + at + 8);
        at += 10;
        if (data > length - at)
            return -1;
        if (type == VITALS_DNS_TYPE_A && record_class == DNS_CLASS_INTERNET && data == 4)
        {
            if (count < capacity)
            {
                for (size_t i = 0; i < 4; ++i)
                    addresses[count].octets[i] = message[at + i];
                ++count;
            }
            if (record_ttl < lowest)
                lowest = record_ttl;
        }
        at += data;
    }
    *ttl = count != 0 ? lowest : 0;
    return (int)count;
}

size_t vitals_dns_rewrite_answer(const unsigned char *response, size_t length, uint16_t id, const char *asked,
                                 const char *name, const VitalsDnsAddress *addresses, unsigned count, uint32_t ttl,
                                 unsigned char *output, size_t capacity)
{
    size_t end;

    if (response == NULL || asked == NULL || name == NULL || output == NULL || (count != 0 && addresses == NULL) ||
        count > VITALS_DNS_ADDRESSES_MAX || capacity < DNS_HEADER_SIZE || !dns_answer_header(response, length, id) ||
        read16(response + 4) != 1 || !name_matches(response, length, DNS_HEADER_SIZE, asked, &end) ||
        length - end < 4 || read16(response + end) != VITALS_DNS_TYPE_A ||
        read16(response + end + 2) != DNS_CLASS_INTERNET)
        return 0;
    size_t written = write_name(output + DNS_HEADER_SIZE, capacity - DNS_HEADER_SIZE, name, text_length(name));
    size_t question = DNS_HEADER_SIZE + written + 4;
    if (written == 0 || question + DNS_ANSWER_SIZE * count > capacity)
        return 0;
    /* A plain answer to the same query: recursion as asked and available, the server's error only
     * when there are no addresses, and nothing but the addresses */
    output[0] = response[0];
    output[1] = response[1];
    output[2] = (unsigned char)(0x80u | (response[2] & 0x01u));
    output[3] = (unsigned char)(0x80u | (count == 0 ? response[3] & 0x0fu : 0));
    output[4] = 0;
    output[5] = 1;
    output[6] = 0;
    output[7] = (unsigned char)count;
    for (size_t i = 8; i < DNS_HEADER_SIZE; ++i)
        output[i] = 0;
    unsigned char *at = output + DNS_HEADER_SIZE + written;
    const unsigned char tail[4] = {0, VITALS_DNS_TYPE_A, 0, DNS_CLASS_INTERNET};
    for (size_t i = 0; i < 4; ++i)
        *at++ = tail[i];
    for (unsigned a = 0; a < count; ++a, at += DNS_ANSWER_SIZE)
    {
        const unsigned char record[DNS_ANSWER_SIZE] = {
            0xc0, DNS_HEADER_SIZE, 0, VITALS_DNS_TYPE_A, 0, DNS_CLASS_INTERNET,
            (unsigned char)(ttl >> 24), (unsigned char)(ttl >> 16), (unsigned char)(ttl >> 8), (unsigned char)ttl,
            0, 4, addresses[a].octets[0], addresses[a].octets[1], addresses[a].octets[2], addresses[a].octets[3]};
        for (size_t i = 0; i < DNS_ANSWER_SIZE; ++i)
            at[i] = record[i];
    }
    return question + DNS_ANSWER_SIZE * count;
}

int vitals_dns_parse_address(const char *name, size_t length, VitalsDnsAddress *address)
{
    size_t at = 0;

    if (name == NULL || address == NULL)
        return 0;
    for (size_t part = 0; part < 4; ++part)
    {
        unsigned value = 0, digits = 0;
        while (at < length && name[at] >= '0' && name[at] <= '9' && digits < 3)
        {
            value = value * 10u + (unsigned)(name[at++] - '0');
            ++digits;
        }
        if (digits == 0 || value > 255 || (part < 3 ? at >= length || name[at++] != '.' : at != length))
            return 0;
        address->octets[part] = (unsigned char)value;
    }
    return 1;
}
