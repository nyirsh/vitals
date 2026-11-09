#include "vitals/path.h"

#include <stdint.h>

static size_t bounded_length(const char *string, size_t maximum) {
    size_t length = 0;

    if (string == NULL) {
        return SIZE_MAX;
    }
    while (length < maximum && string[length] != '\0') {
        ++length;
    }
    return length == maximum ? SIZE_MAX : length;
}

static int bytes_equal(const char *left, const char *right, size_t length) {
    size_t index;

    for (index = 0; index < length; ++index) {
        if (left[index] != right[index]) {
            return 0;
        }
    }
    return 1;
}

int vitals_path_equals(const char *path, const char *expected, size_t maximum) {
    size_t path_length = bounded_length(path, maximum);
    size_t expected_length = bounded_length(expected, maximum);

    if (path_length == SIZE_MAX || expected_length == SIZE_MAX ||
        path_length != expected_length) {
        return 0;
    }
    return bytes_equal(path, expected, path_length);
}

int vitals_path_has_suffix(const char *path, const char *suffix, size_t maximum) {
    size_t path_length = bounded_length(path, maximum);
    size_t suffix_length = bounded_length(suffix, maximum);

    if (path_length == SIZE_MAX || suffix_length == SIZE_MAX ||
        suffix_length > path_length) {
        return 0;
    }
    return bytes_equal(path + path_length - suffix_length, suffix, suffix_length);
}

int vitals_browser_engine_request(const char *request) {
    static const char suffix[] = "webcore/ScePsp2Compat.suprx";
    const size_t suffix_size = sizeof(suffix) - 1;
    size_t length = bounded_length(request, 1024);
    size_t prefix;
    size_t colon;

    if (length == SIZE_MAX || length < suffix_size ||
        !bytes_equal(request + length - suffix_size, suffix, suffix_size)) return 0;
    prefix = length - suffix_size;
    if (prefix == 0 || (request[prefix - 1] != '/' && request[prefix - 1] != ':')) return 0;
    for (colon = 0; colon < prefix && request[colon] != ':'; ++colon) {}
    return colon != 0 && colon != prefix;
}
