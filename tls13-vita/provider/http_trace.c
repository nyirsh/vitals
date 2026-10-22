#include "http_trace.h"

#include "diagnostics.h"

#include <psp2/types.h>
#include <taihen.h>

#include <stdint.h>

#define VITALS_SCE_HTTP_LIBRARY_NID UINT32_C(0xE8F15CDE)

enum {
    TRACE_CREATE_CONNECTION_WITH_URL,
    TRACE_CREATE_REQUEST_WITH_URL,
    TRACE_SEND_REQUEST,
    TRACE_HTTPS_ENABLE_OPTION,
    TRACE_HTTPS_DISABLE_OPTION,
    TRACE_HTTPS_SET_SSL_CALLBACK,
    TRACE_COUNT
};

static int g_trace_hook_ids[TRACE_COUNT] = {-1, -1, -1, -1, -1, -1};
static tai_hook_ref_t g_trace_hook_refs[TRACE_COUNT];

static void *next_hook_function(tai_hook_ref_t reference) {
    struct _tai_hook_user *current = (struct _tai_hook_user *)reference;
    struct _tai_hook_user *next = (struct _tai_hook_user *)current->next;

    return next == NULL ? current->old : next->func;
}
#define TRACE_NEXT(index, type) ((type)next_hook_function(g_trace_hook_refs[index]))

static int trace_create_connection_with_url(int template_id, const char *url, int keep_alive) {
    int result = TRACE_NEXT(TRACE_CREATE_CONNECTION_WITH_URL, int (*)(int, const char *, int))(
        template_id, url, keep_alive);
    VITALS_LOG("http connection url=%s keepalive=%d rc=%08X", url != NULL ? url : "?", keep_alive,
        (unsigned int)result);
    return result;
}

static int trace_create_request_with_url(int connection_id, int method, const char *url, SceULong64 length) {
    int result = TRACE_NEXT(TRACE_CREATE_REQUEST_WITH_URL, int (*)(int, int, const char *, SceULong64))(
        connection_id, method, url, length);
    VITALS_LOG("http request conn=%08X method=%d url=%s rc=%08X", (unsigned int)connection_id, method,
        url != NULL ? url : "?", (unsigned int)result);
    return result;
}

static int trace_send_request(int request_id, const void *data, unsigned int size) {
    VITALS_LOG("http send enter req=%08X size=%u", (unsigned int)request_id, size);
    int result = TRACE_NEXT(TRACE_SEND_REQUEST, int (*)(int, const void *, unsigned int))(request_id, data, size);
    VITALS_LOG("http send req=%08X rc=%08X", (unsigned int)request_id, (unsigned int)result);
    return result;
}

static int trace_https_enable_option(unsigned int flags) {
    int result = TRACE_NEXT(TRACE_HTTPS_ENABLE_OPTION, int (*)(unsigned int))(flags);
    VITALS_LOG("https enable option flags=%08X rc=%08X", flags, (unsigned int)result);
    return result;
}

static int trace_https_disable_option(unsigned int flags) {
    int result = TRACE_NEXT(TRACE_HTTPS_DISABLE_OPTION, int (*)(unsigned int))(flags);
    VITALS_LOG("https disable option flags=%08X rc=%08X", flags, (unsigned int)result);
    return result;
}

static int trace_https_set_ssl_callback(int id, void *callback, void *argument) {
    int result = TRACE_NEXT(TRACE_HTTPS_SET_SSL_CALLBACK, int (*)(int, void *, void *))(id, callback, argument);
    VITALS_LOG("https set callback id=%08X callback=%d rc=%08X", (unsigned int)id, callback != NULL,
        (unsigned int)result);
    return result;
}

static const struct {
    uint32_t nid;
    const void *function;
} g_trace_hooks[TRACE_COUNT] = {
    [TRACE_CREATE_CONNECTION_WITH_URL] = {UINT32_C(0xC616C200), trace_create_connection_with_url},
    [TRACE_CREATE_REQUEST_WITH_URL] = {UINT32_C(0xBD5DA1D0), trace_create_request_with_url},
    [TRACE_SEND_REQUEST] = {UINT32_C(0x9CA58B99), trace_send_request},
    [TRACE_HTTPS_ENABLE_OPTION] = {UINT32_C(0x9FBE2869), trace_https_enable_option},
    [TRACE_HTTPS_DISABLE_OPTION] = {UINT32_C(0xC6D60403), trace_https_disable_option},
    [TRACE_HTTPS_SET_SSL_CALLBACK] = {UINT32_C(0xA0926037), trace_https_set_ssl_callback},
};

/* Best effort: a missing trace hook never affects the provider */
void vitals_http_trace_install(void) {
    for (int i = 0; i < TRACE_COUNT; ++i) {
        g_trace_hook_ids[i] = taiHookFunctionExport(&g_trace_hook_refs[i], "SceLibHttp",
            VITALS_SCE_HTTP_LIBRARY_NID, g_trace_hooks[i].nid, g_trace_hooks[i].function);
        if (g_trace_hook_ids[i] < 0)
            VITALS_LOG("trace hook nid=%08X rc=%08X", g_trace_hooks[i].nid, (unsigned int)g_trace_hook_ids[i]);
    }
}

void vitals_http_trace_release(void) {
    for (int i = TRACE_COUNT - 1; i >= 0; --i) {
        if (g_trace_hook_ids[i] >= 0) {
            taiHookRelease(g_trace_hook_ids[i], g_trace_hook_refs[i]);
            g_trace_hook_ids[i] = -1;
        }
    }
}
