#include "release_version.h"

#include <string.h>

/* One part of a release number: 0 to 99, without a leading zero; returns the characters read */
static size_t read_part(const char *text, unsigned *value) {
    if (text[0] < '0' || text[0] > '9')
        return 0;
    if (text[1] < '0' || text[1] > '9') {
        *value = (unsigned)(text[0] - '0');
        return 1;
    }
    if (text[0] == '0' || (text[2] >= '0' && text[2] <= '9'))
        return 0;
    *value = (unsigned)(text[0] - '0') * 10u + (unsigned)(text[1] - '0');
    return 2;
}

int vitals_release_parse(const char *text, unsigned *major, unsigned *minor) {
    size_t first, second;
    if (text == NULL || (first = read_part(text, major)) == 0 || text[first] != '.' ||
        (second = read_part(text + first + 1, minor)) == 0 || text[first + 1 + second] != '\0')
        return -1;
    return 0;
}

static int is_space(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

int vitals_release_tag(const char *json, size_t length, char *tag, size_t size) {
    static const char key[] = "\"tag_name\"";
    unsigned major, minor;
    size_t i = 0;

    if (json == NULL || tag == NULL || size == 0)
        return -1;
    /* A key inside another string would have its quotes escaped, so the first real one is found */
    for (; i + sizeof(key) - 1 <= length; ++i) {
        if (memcmp(json + i, key, sizeof(key) - 1) == 0)
            break;
    }
    if (i + sizeof(key) - 1 > length)
        return -1;
    i += sizeof(key) - 1;
    while (i < length && is_space(json[i]))
        ++i;
    if (i >= length || json[i++] != ':')
        return -1;
    while (i < length && is_space(json[i]))
        ++i;
    if (i >= length || json[i++] != '"')
        return -1;
    size_t start = i;
    while (i < length && json[i] != '"' && json[i] != '\\' && i - start < size - 1)
        ++i;
    if (i >= length || json[i] != '"')
        return -1;
    memcpy(tag, json + start, i - start);
    tag[i - start] = '\0';
    return vitals_release_parse(tag, &major, &minor) == 0 ? 0 : -1;
}

int vitals_release_newer(const char *candidate, const char *current) {
    unsigned candidate_major, candidate_minor, current_major, current_minor;
    if (vitals_release_parse(candidate, &candidate_major, &candidate_minor) != 0 ||
        vitals_release_parse(current, &current_major, &current_minor) != 0)
        return -1;
    return candidate_major > current_major ||
           (candidate_major == current_major && candidate_minor > current_minor);
}
