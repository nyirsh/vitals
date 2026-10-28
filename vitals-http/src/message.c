#include "vh.h"

#include "diagnostics.h"

#include <stdio.h>
#include <string.h>

static char lower(char c)
{
    return c >= 'A' && c <= 'Z' ? (char)(c - 'A' + 'a') : c;
}

int vh_equal_nocase(const char *a, const char *b, size_t length)
{
    for (size_t i = 0; i < length; ++i)
        if (lower(a[i]) != lower(b[i]))
            return 0;
    return 1;
}

static int has_header(const VhHeaders *headers, const char *name)
{
    size_t length = strlen(name);
    for (unsigned int i = 0; i < headers->count; ++i)
        if (strlen(headers->items[i].name) == length && vh_equal_nocase(headers->items[i].name, name, length))
            return 1;
    return 0;
}

/* Appends to a growing request text; *failed once memory runs out */
typedef struct Text {
    char *data;
    size_t size, capacity;
    int failed;
} Text;

static void add(Text *text, const char *data, size_t length)
{
    if (text->failed)
        return;
    if (text->size + length + 1 > text->capacity) {
        size_t capacity = (text->size + length + 1) * 2;
        char *grown = vh_alloc(capacity);
        if (grown == NULL) {
            text->failed = 1;
            return;
        }
        if (text->data != NULL)
            memcpy(grown, text->data, text->size);
        vh_free(text->data);
        text->data = grown;
        text->capacity = capacity;
    }
    memcpy(text->data + text->size, data, length);
    text->size += length;
    text->data[text->size] = '\0';
}

static void add_string(Text *text, const char *data)
{
    add(text, data, strlen(data));
}

static void add_header(Text *text, const char *name, const char *value)
{
    add_string(text, name);
    add(text, ": ", 2);
    add_string(text, value);
    add(text, "\r\n", 2);
}

/* Sony's sends a Content-Length for POST, PUT, DELETE and the methods it has no name for */
static int has_length(const char *method)
{
    static const char *const without[] = {"GET", "HEAD", "OPTIONS", "TRACE", "CONNECT"};
    for (size_t i = 0; i < sizeof(without) / sizeof(without[0]); ++i)
        if (strcmp(method, without[i]) == 0)
            return 0;
    return 1;
}

int vh_build_request(const VhObject *request, const VhObject *connection, const VhObject *template_,
                     unsigned long long body_size, int has_body, const char *cookie, char **out, size_t *size)
{
    const VhRequest *r = &request->as.request;
    const VhConnection *c = &connection->as.connection;
    const VhHeaders *headers = &request->settings.headers;
    char number[32];
    Text text = {0};

    add_string(&text, r->method);
    add(&text, " ", 1);
    add_string(&text, r->path[0] != '\0' ? r->path : "/");
    add_string(&text, template_ != NULL && template_->as.template_.http_version == SCE_HTTP_VERSION_1_0
                          ? " HTTP/1.0\r\n"
                          : " HTTP/1.1\r\n");
    /* In Sony's order: its header list from the front (the cookies, added last, first; the Host
     * the request got when it was made among them), then the connection, the body's length for
     * the methods that have one, and gzip */
    (void)has_body;
    if (cookie != NULL && !has_header(headers, "Cookie"))
        add_header(&text, "Cookie", cookie);
    for (unsigned int i = 0; i < headers->count; ++i)
        add_header(&text, headers->items[i].name, headers->items[i].value);
    if (!has_header(headers, "Connection"))
        add_header(&text, "Connection", c->keep_alive ? "Keep-Alive" : "close");
    if (has_length(r->method) && !has_header(headers, "Content-Length")) {
        snprintf(number, sizeof(number), "%llu",
                 r->content_length >= 0 ? (unsigned long long)r->content_length : body_size);
        add_header(&text, "Content-Length", number);
    }
    if (request->settings.accept_gzip == SCE_HTTP_ENABLE && !has_header(headers, "Accept-Encoding"))
        add_header(&text, "Accept-Encoding", "gzip");
    add(&text, "\r\n", 2);
    if (text.failed) {
        vh_free(text.data);
        return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
    }
    *out = text.data;
    *size = text.size;
    return 0;
}

unsigned int vh_list_request_headers(const VhObject *request, const VhObject *connection,
                                     SceHttpHeaderPair *pairs, char *length, unsigned int *length_size)
{
    const VhRequest *r = &request->as.request;
    const VhHeaders *headers = &request->settings.headers;
    unsigned int count = 0;
#define PAIR(header_name, header_value)                                                            \
    do {                                                                                           \
        if (pairs != NULL)                                                                         \
            pairs[count] = (SceHttpHeaderPair){(header_name), (header_value)};                     \
        ++count;                                                                                   \
    } while (0)
    /* Sony's adds the cookies to the front of the list when it sends */
    if (r->sent_cookie != NULL && !has_header(headers, "Cookie"))
        PAIR("Cookie", r->sent_cookie);
    for (unsigned int i = 0; i < headers->count; ++i)
        PAIR(headers->items[i].name, headers->items[i].value);
    if (!has_header(headers, "Connection"))
        PAIR("Connection", connection != NULL && connection->as.connection.keep_alive ? "Keep-Alive" : "close");
    if (has_length(r->method) && !has_header(headers, "Content-Length")) {
        /* As Sony's: the value goes in the app's buffer; without one, the size it needs */
        if (length != NULL && length_size != NULL)
            snprintf(length, *length_size, "%lld", r->content_length >= 0 ? r->content_length : 0);
        else if (length_size != NULL)
            *length_size = 21;
        PAIR("Content-Length", length);
    }
    if (request->settings.accept_gzip == SCE_HTTP_ENABLE && !has_header(headers, "Accept-Encoding"))
        /* Sony's name, with the colon and space its header text has after it */
        PAIR("Accept-Encoding: ", "gzip");
#undef PAIR
    return count;
}

int vh_parse_chunk_size(const unsigned char *data, size_t length, unsigned long long *size, size_t *used)
{
    unsigned long long value = 0;
    size_t at = 0, digits = 0;

    while (at < length) {
        unsigned char c = data[at];
        int digit = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10
                                                   : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
        if (digit < 0)
            break;
        if (++digits > 15)
            return -1;
        value = value * 16u + (unsigned long long)digit;
        ++at;
    }
    if (at == length)
        return 0;
    if (digits == 0)
        return -1;
    /* Chunk extensions and spaces are skipped up to the line's end */
    while (at < length && data[at] != '\n')
        ++at;
    if (at == length)
        return at > 256 ? -1 : 0;
    *size = value;
    *used = at + 1;
    return 1;
}

/* A field as Sony's libhttp finds one: its name at a line's start, then ':'; the value starts
 * after the spaces and tabs that follow, and runs over folded lines up to the line end, without
 * its CR. Returns the offset of the value's end, which is positive, or NOT_FOUND */
static int find_field(const char *header, size_t length, const char *name, size_t *start, size_t *finish)
{
    size_t name_length = strlen(name);
    int line_start = 1;

    for (size_t at = 0; at < length; ++at) {
        char c = header[at];
        if (line_start && c != ' ' && c != '\t' && name_length < length - at &&
            header[at + name_length] == ':' && vh_equal_nocase(header + at, name, name_length)) {
            size_t from = at + name_length + 1;
            while (from < length && (header[from] == ' ' || header[from] == '\t'))
                ++from;
            size_t to = from;
            while (to < length) {
                if (header[to] == '\n' &&
                    !(to + 1 < length && (header[to + 1] == ' ' || header[to + 1] == '\t')))
                    break;
                ++to;
            }
            if (to < length && to > from && header[to - 1] == '\r')
                --to;
            *start = from;
            *finish = to;
            return (int)to;
        }
        line_start = c == '\n';
    }
    return (int)SCE_HTTP_ERROR_PARSE_HTTP_NOT_FOUND;
}

int vh_find_header(const char *header, size_t length, const char *name, const char **value,
                   unsigned int *value_length)
{
    size_t start, finish;
    int result = find_field(header, length, name, &start, &finish);
    if (result < 0)
        return result;
    /* This library's own reads don't want the spaces Sony's leaves at the end */
    while (finish > start && (header[finish - 1] == ' ' || header[finish - 1] == '\t'))
        --finish;
    *value = header + start;
    *value_length = (unsigned int)(finish - start);
    return 0;
}

/* Returns, as Sony's does, the offset of the value's end: callers walk repeated fields with it */
int sceHttpParseResponseHeader(const char *header, unsigned int headerLen, const char *fieldStr,
                               const char **fieldValue, unsigned int *valueLen)
{
    VH_TRACE();
    size_t start, finish;
    if (header == NULL)
        return (int)SCE_HTTP_ERROR_PARSE_HTTP_INVALID_RESPONSE;
    if (fieldStr == NULL || fieldStr[0] == '\0' || fieldValue == NULL || valueLen == NULL)
        return (int)SCE_HTTP_ERROR_PARSE_HTTP_INVALID_VALUE;
    int result = find_field(header, headerLen, fieldStr, &start, &finish);
    if (result < 0) {
        VITALS_LOG("header %s not found", fieldStr);
        return result;
    }
    *fieldValue = header + start;
    *valueLen = (unsigned int)(finish - start);
    VITALS_VERBOSE("header %s found rc=%d length=%u", fieldStr, result, *valueLen);
    return result;
}

static int read_number(const char *text, size_t length, size_t *at, int *value, size_t max_digits)
{
    size_t digits = 0;
    int number = 0;
    while (*at < length && text[*at] >= '0' && text[*at] <= '9' && digits < max_digits) {
        number = number * 10 + (text[*at] - '0');
        ++*at;
        ++digits;
    }
    *value = number;
    return digits != 0;
}

int sceHttpParseStatusLine(const char *statusLine, unsigned int lineLen, int *httpMajorVer, int *httpMinorVer,
                           int *responseCode, const char **reasonPhrase, unsigned int *phraseLen)
{
    VH_TRACE();
    size_t at = 5;
    int major, minor, code;

    if (statusLine == NULL || httpMajorVer == NULL || httpMinorVer == NULL || responseCode == NULL ||
        reasonPhrase == NULL || phraseLen == NULL)
        return (int)SCE_HTTP_ERROR_PARSE_HTTP_INVALID_VALUE;
    /* "HTTP/" major "." minor SP code [SP reason] */
    if (lineLen < 12 || memcmp(statusLine, "HTTP/", 5) != 0 ||
        !read_number(statusLine, lineLen, &at, &major, 3) || at >= lineLen || statusLine[at++] != '.' ||
        !read_number(statusLine, lineLen, &at, &minor, 3) || at >= lineLen || statusLine[at++] != ' ')
        return (int)SCE_HTTP_ERROR_PARSE_HTTP_INVALID_RESPONSE;
    size_t code_start = at;
    if (!read_number(statusLine, lineLen, &at, &code, 3) || at - code_start != 3)
        return (int)SCE_HTTP_ERROR_PARSE_HTTP_INVALID_RESPONSE;
    size_t end = at;
    while (end < lineLen && statusLine[end] != '\r' && statusLine[end] != '\n')
        ++end;
    if (at < end && statusLine[at] == ' ')
        ++at;
    *httpMajorVer = major;
    *httpMinorVer = minor;
    *responseCode = code;
    *reasonPhrase = statusLine + at;
    *phraseLen = (unsigned int)(end - at);
    return 0;
}
