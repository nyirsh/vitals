#include "vitals/browser_abi.h"
#include "vitals/sony_abi.h"
#include "../provider/diagnostics.h"

#include <string.h>

static int legacy_configuration(size_t offset, int32_t value) {
    VITALS_LOG("browser legacy option: offset=%u value=0x%08X",
        (unsigned int)offset, (unsigned int)value);
    (void)offset;
    (void)value;
    return VITALS_BROWSER_CONFIG_LEGACY;
}

static size_t bounded_length(const char *value, size_t capacity) {
    size_t size;
    if (value == NULL) return 0;
    for (size = 0; size < capacity; ++size) {
        if (value[size] == '\0') return size;
    }
    return SIZE_MAX;
}

static int cipher_mask(const char *ciphers, const char *browser_default, uint32_t *mask) {
    static const struct {
        const char *name;
        uint32_t bit;
    } names[] = {
        {"ECDHE-RSA-AES128-GCM-SHA256", VITALS_BROWSER_RSA_GCM128},
        {"ECDHE-RSA-AES256-GCM-SHA384", VITALS_BROWSER_RSA_GCM256},
        {"ECDHE-ECDSA-AES128-GCM-SHA256", VITALS_BROWSER_ECDSA_GCM128},
        {"ECDHE-ECDSA-AES256-GCM-SHA384", VITALS_BROWSER_ECDSA_GCM256}
    };
    size_t length = bounded_length(ciphers, 1024);
    const char *cursor;
    uint32_t found = 0;

    if (length == SIZE_MAX) return VITALS_BROWSER_CONFIG_INVALID;
    if (ciphers == NULL || strcmp(ciphers, "DEFAULT") == 0 ||
        strcmp(ciphers, "ALL:!EXPORT:!LOW:!aNULL:!eNULL:!SSLv2") == 0) {
        *mask = 15;
        return 0;
    }
    if (browser_default != NULL && strcmp(ciphers, browser_default) == 0) {
        *mask = VITALS_BROWSER_RSA_GCM128 | VITALS_BROWSER_ECDSA_GCM128;
        return 0;
    }
    cursor = ciphers;
    while (*cursor != '\0') {
        const char *separator = strchr(cursor, ':');
        size_t token_length = separator == NULL ? strlen(cursor) : (size_t)(separator - cursor);
        size_t i;
        for (i = 0; i < sizeof(names)/sizeof(names[0]); ++i) {
            if (strlen(names[i].name) == token_length &&
                memcmp(cursor, names[i].name, token_length) == 0) {
                found |= names[i].bit;
                break;
            }
        }
        if (i == sizeof(names)/sizeof(names[0])) return VITALS_BROWSER_CONFIG_LEGACY;
        if (separator == NULL) break;
        cursor = separator + 1;
        if (*cursor == '\0') return VITALS_BROWSER_CONFIG_LEGACY;
    }
    if (found == 0) return VITALS_BROWSER_CONFIG_LEGACY;
    *mask = found;
    return 0;
}

const char *vitals_browser_unverified_host(const void *connection) {
    const uint8_t *easy;
    const char *hostname;
    size_t length;

    if (connection == NULL) return NULL;
    easy = (const uint8_t *)(uintptr_t)vitals_read_u32(connection, VITALS_CURL_EASY_OFFSET);
    if (easy == NULL) return NULL;
    if (easy[VITALS_CURL_VERIFY_PEER_OFFSET] != 0 && easy[VITALS_CURL_VERIFY_HOST_OFFSET] != 0) return NULL;
    hostname = (const char *)(uintptr_t)vitals_read_u32(connection, VITALS_CURL_HOST_OFFSET);
    length = bounded_length(hostname, 1024);
    return length == 0 || length == SIZE_MAX ? NULL : hostname;
}

int vitals_browser_read_options(const void *connection, unsigned int socket_index,
    const char *browser_default_ciphers,
    VitalsBrowserContextCallbackValidator callback_validator,
    VitalsBrowserOptions *options) {
    static const size_t unsupported_material[] = {816, 820, 824, 828, 896, 920, 924};
    const uint8_t *easy;
    const char *ciphers;
    const char *ca_file;
    const void *ctx_callback;
    const void *ctx_userdata;
    uint8_t verify_peer;
    uint8_t verify_host;
    int version;
    size_t i;

    if (connection == NULL || options == NULL || socket_index > 1) {
        return VITALS_BROWSER_CONFIG_INVALID;
    }
    memset(options, 0, sizeof(*options));
    easy = (const uint8_t *)(uintptr_t)vitals_read_u32(connection, VITALS_CURL_EASY_OFFSET);
    if (easy == NULL) return VITALS_BROWSER_CONFIG_INVALID;
    version = vitals_read_i32(easy, VITALS_CURL_VERSION_OFFSET);
    if (version != 0 && version != 1) return legacy_configuration(VITALS_CURL_VERSION_OFFSET, version);
    verify_peer = easy[VITALS_CURL_VERIFY_PEER_OFFSET] != 0;
    verify_host = easy[VITALS_CURL_VERIFY_HOST_OFFSET] != 0;
    ca_file = (const char *)(uintptr_t)vitals_read_u32(easy, VITALS_CURL_CAFILE_OFFSET);
    ctx_callback = (const void *)(uintptr_t)vitals_read_u32(easy, VITALS_CURL_CTX_CALLBACK_OFFSET);
    ctx_userdata = (const void *)(uintptr_t)vitals_read_u32(easy, VITALS_CURL_CTX_CALLBACK_DATA_OFFSET);
    if (ctx_callback != NULL) {
        uint32_t policy = (ctx_userdata == NULL ? 1u : 0u) |
            (callback_validator == NULL ? 2u : 0u) | (!verify_peer ? 4u : 0u) |
            (!verify_host ? 8u : 0u) | (ca_file != NULL ? 16u : 0u);
        /* Which of the callback's conditions failed, to tell a retry with verification off apart */
        VITALS_LOG("browser ctx callback: policy=0x%X peer=%u host=%u cafile=%u",
            (unsigned int)policy, verify_peer, verify_host, ca_file != NULL ? 1u : 0u);
        if (policy != 0 || !callback_validator(ctx_callback, ctx_userdata)) {
            return legacy_configuration(VITALS_CURL_CTX_CALLBACK_OFFSET, 1);
        }
    } else if (ctx_userdata != NULL) {
        return legacy_configuration(VITALS_CURL_CTX_CALLBACK_DATA_OFFSET, 1);
    }
    for (i = 0; i < sizeof(unsupported_material)/sizeof(unsupported_material[0]); ++i) {
        if (vitals_read_u32(easy, unsupported_material[i]) != 0) {
            return legacy_configuration(unsupported_material[i], 1);
        }
    }
    if (easy[VITALS_CURL_CERTINFO_OFFSET] != 0) return legacy_configuration(VITALS_CURL_CERTINFO_OFFSET, 1);
    options->easy = (void *)easy;
    options->socket = vitals_read_i32(connection, VITALS_CURL_SOCKET_OFFSET + 4 * socket_index);
    options->hostname = (const char *)(uintptr_t)vitals_read_u32(connection, VITALS_CURL_HOST_OFFSET);
    options->ca_file = ca_file;
    options->verify_peer = verify_peer;
    options->verify_host = verify_host;
    if (options->socket < 0 || options->hostname == NULL ||
        bounded_length(options->hostname, 1024) == 0 ||
        bounded_length(options->hostname, 1024) == SIZE_MAX ||
        bounded_length(options->ca_file, 1024) == SIZE_MAX) {
        return VITALS_BROWSER_CONFIG_INVALID;
    }
    ciphers = (const char *)(uintptr_t)vitals_read_u32(easy, VITALS_CURL_CIPHERS_OFFSET);
    int result = cipher_mask(ciphers, browser_default_ciphers, &options->tls12_suites);
    return result == VITALS_BROWSER_CONFIG_LEGACY
        ? legacy_configuration(VITALS_CURL_CIPHERS_OFFSET, 1) : result;
}
