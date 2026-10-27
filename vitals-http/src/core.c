#include "vh.h"

#include "diagnostics.h"

#include <string.h>

/* The library's state: initialized or not, the memory pool's accounting, and the objects */
static int g_initialized;
static unsigned int g_pool_size, g_pool_used, g_pool_peak;
static VhObject *g_objects[VH_OBJECT_MAX];
static int g_next_id = 1;
static unsigned int g_https_options = SCE_HTTPS_FLAG_SERVER_VERIFY | SCE_HTTPS_FLAG_CN_CHECK |
                                      SCE_HTTPS_FLAG_NOT_AFTER_CHECK | SCE_HTTPS_FLAG_NOT_BEFORE_CHECK |
                                      SCE_HTTPS_FLAG_KNOWN_CA_CHECK;
static int g_default_accept_gzip = SCE_HTTP_DISABLE;

/* Each allocation is preceded by its size, so the pool's use can be counted */
typedef union VhBlock {
    size_t size;
    long long align;
} VhBlock;

void vh_lock(void) { vh_platform_lock(); }
void vh_unlock(void) { vh_platform_unlock(); }

int vh_initialized(void)
{
    return g_initialized ? 0 : (int)SCE_HTTP_ERROR_BEFORE_INIT;
}

/* The lock is recursive, so these work with it held or not (the URI functions don't take it) */
void *vh_alloc(size_t size)
{
    vh_lock();
    if (!g_initialized || size > (size_t)g_pool_size || g_pool_used + sizeof(VhBlock) + size > g_pool_size) {
        vh_unlock();
        return NULL;
    }
    VhBlock *block = vh_platform_alloc(sizeof(VhBlock) + size);
    if (block != NULL) {
        block->size = size;
        g_pool_used += (unsigned int)(sizeof(VhBlock) + size);
        if (g_pool_used > g_pool_peak)
            g_pool_peak = g_pool_used;
    }
    vh_unlock();
    return block == NULL ? NULL : block + 1;
}

void vh_free(void *pointer)
{
    if (pointer == NULL)
        return;
    VhBlock *block = (VhBlock *)pointer - 1;
    vh_lock();
    g_pool_used -= (unsigned int)(sizeof(VhBlock) + block->size);
    vh_platform_free(block);
    vh_unlock();
}

char *vh_strdup(const char *text, size_t length)
{
    char *copy = vh_alloc(length + 1);
    if (copy != NULL) {
        memcpy(copy, text, length);
        copy[length] = '\0';
    }
    return copy;
}

unsigned int vh_https_options(void)
{
    return g_https_options;
}

unsigned int vh_https_options_of(const VhSettings *settings)
{
    return (g_https_options | settings->https_enabled) & ~settings->https_disabled;
}

static void default_settings(VhSettings *settings)
{
    memset(settings, 0, sizeof(*settings));
    settings->resolve_timeout_us = SCE_HTTP_DEFAULT_RESOLVER_TIMEOUT;
    settings->resolve_retry = (int)SCE_HTTP_DEFAULT_RESOLVER_RETRY;
    settings->connect_timeout_us = SCE_HTTP_DEFAULT_CONNECT_TIMEOUT;
    settings->send_timeout_us = SCE_HTTP_DEFAULT_SEND_TIMEOUT;
    settings->recv_timeout_us = SCE_HTTP_DEFAULT_RECV_TIMEOUT;
    settings->auto_redirect = SCE_HTTP_ENABLE;
    settings->auth_enabled = SCE_HTTP_ENABLE;
    settings->cookie_enabled = SCE_HTTP_ENABLE;
    settings->response_header_max = SCE_HTTP_DEFAULT_RESPONSE_HEADER_MAX;
    settings->accept_gzip = g_default_accept_gzip;
    settings->inflate_gzip = SCE_HTTP_ENABLE;
}

static void free_headers(VhHeaders *headers)
{
    for (unsigned int i = 0; i < headers->count; ++i) {
        vh_free(headers->items[i].name);
        vh_free(headers->items[i].value);
    }
    headers->count = 0;
}

void vh_settings_free(VhSettings *settings)
{
    free_headers(&settings->headers);
}

/* Copies everything; the headers are duplicated, and dropped where memory runs out */
void vh_settings_copy(VhSettings *destination, const VhSettings *source)
{
    *destination = *source;
    destination->headers.count = 0;
    for (unsigned int i = 0; i < source->headers.count; ++i) {
        const VhHeader *header = &source->headers.items[i];
        char *name = vh_strdup(header->name, strlen(header->name));
        char *value = vh_strdup(header->value, strlen(header->value));
        if (name == NULL || value == NULL) {
            vh_free(name);
            vh_free(value);
            continue;
        }
        destination->headers.items[destination->headers.count++] = (VhHeader){name, value};
    }
}

/* Deleted objects too, which their IDs and their busy requests still need */
static VhObject *find_any(int id)
{
    if (id <= 0)
        return NULL;
    for (unsigned int i = 0; i < VH_OBJECT_MAX; ++i)
        if (g_objects[i] != NULL && g_objects[i]->id == id)
            return g_objects[i];
    return NULL;
}

VhObject *vh_find(int id, VhKind kind)
{
    VhObject *object = find_any(id);
    if (object == NULL || object->doomed || (kind != VH_FREE && object->kind != kind))
        return NULL;
    return object;
}

VhObject *vh_object_at(unsigned int slot)
{
    return slot < VH_OBJECT_MAX ? g_objects[slot] : NULL;
}

VhObject *vh_parent(VhObject *object)
{
    return object == NULL ? NULL : find_any(object->parent);
}

unsigned int vh_children(int id, VhObject **children, unsigned int max)
{
    unsigned int count = 0;
    for (unsigned int i = 0; i < VH_OBJECT_MAX; ++i)
        if (g_objects[i] != NULL && g_objects[i]->parent == id) {
            if (count < max)
                children[count] = g_objects[i];
            ++count;
        }
    return count;
}

VhObject *vh_create(VhKind kind, VhObject *parent)
{
    unsigned int slot = VH_OBJECT_MAX;
    for (unsigned int i = 0; i < VH_OBJECT_MAX && slot == VH_OBJECT_MAX; ++i)
        if (g_objects[i] == NULL)
            slot = i;
    if (slot == VH_OBJECT_MAX)
        return NULL;
    VhObject *object = vh_alloc(sizeof(*object));
    if (object == NULL)
        return NULL;
    memset(object, 0, sizeof(*object));
    /* IDs grow and skip the ones in use, so a stale ID rarely names a new object */
    do {
        object->id = g_next_id;
        g_next_id = g_next_id == 0x7fffffff ? 1 : g_next_id + 1;
    } while (find_any(object->id) != NULL);
    object->kind = kind;
    if (parent != NULL) {
        object->parent = parent->id;
        vh_settings_copy(&object->settings, &parent->settings);
    } else
        default_settings(&object->settings);
    g_objects[slot] = object;
    return object;
}

void vh_destroy(VhObject *object)
{
    for (unsigned int i = 0; i < VH_OBJECT_MAX; ++i)
        if (g_objects[i] == object)
            g_objects[i] = NULL;
    vh_settings_free(&object->settings);
    if (object->kind == VH_CONNECTION && object->as.connection.transport != NULL)
        vh_transport_close(object->as.connection.transport);
    if (object->kind == VH_REQUEST) {
        vh_request_free(&object->as.request);
        VhObject *connection = vh_parent(object);
        if (connection != NULL && connection->kind == VH_CONNECTION && connection->as.connection.requests > 0)
            --connection->as.connection.requests;
    }
    vh_free(object);
}

/* ---- initialization ---- */

int sceHttpInit(unsigned int poolSize)
{
    VH_TRACE();
    if (poolSize == 0)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    vh_lock();
    if (g_initialized) {
        vh_unlock();
        return (int)SCE_HTTP_ERROR_ALREADY_INITED;
    }
    int result = vh_platform_init(poolSize);
    if (result >= 0) {
        g_pool_size = poolSize;
        g_pool_used = g_pool_peak = 0;
        g_initialized = 1;
        result = 0;
    }
    vh_unlock();
    return result;
}

int sceHttpTerm(void)
{
    VH_TRACE();
    vh_lock();
    if (!g_initialized) {
        vh_unlock();
        return (int)SCE_HTTP_ERROR_BEFORE_INIT;
    }
    /* A request in a blocking call still uses its objects */
    for (unsigned int i = 0; i < VH_OBJECT_MAX; ++i)
        if (g_objects[i] != NULL && g_objects[i]->kind == VH_REQUEST && g_objects[i]->as.request.busy) {
            vh_unlock();
            return (int)SCE_HTTP_ERROR_BUSY;
        }
    /* Requests first, then connections, then templates */
    for (int kind = VH_REQUEST; kind >= VH_TEMPLATE; --kind)
        for (unsigned int i = 0; i < VH_OBJECT_MAX; ++i)
            if (g_objects[i] != NULL && g_objects[i]->kind == (VhKind)kind)
                vh_destroy(g_objects[i]);
    vh_cookie_clear();
    vh_redirect_clear();
    vh_epoll_clear();
    vh_tls_unload_certs();
    g_initialized = 0;
    vh_platform_term();
    vh_unlock();
    return 0;
}

int sceHttpGetMemoryPoolStats(SceHttpMemoryPoolStats *currentStat)
{
    /* Apps poll this, often each frame: only changes are logged */
#if VITALS_DEBUG >= 2
    static unsigned int reported_used = UINT32_MAX, reported_peak;
#endif
    if (currentStat == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    vh_lock();
    int result = vh_initialized();
    if (result == 0) {
        currentStat->poolSize = g_pool_size;
        currentStat->maxInuseSize = g_pool_peak;
        currentStat->currentInuseSize = g_pool_used;
        currentStat->reserved = 0;
#if VITALS_DEBUG >= 2
        if (g_pool_used != reported_used || g_pool_peak != reported_peak)
            VITALS_VERBOSE("pool stats size=%u used=%u peak=%u", g_pool_size, g_pool_used, g_pool_peak);
        reported_used = g_pool_used;
        reported_peak = g_pool_peak;
#endif
    }
    vh_unlock();
    return result;
}

/* ---- settings, on a template, connection or request ---- */

/* The settings of the object with that ID, with the lock held; NULL and *result set otherwise */
static VhSettings *settings_of(int id, int *result)
{
    *result = vh_initialized();
    if (*result != 0)
        return NULL;
    VhObject *object = vh_find(id, VH_FREE);
    if (object == NULL) {
        *result = (int)SCE_HTTP_ERROR_INVALID_ID;
        return NULL;
    }
    return &object->settings;
}

#define VH_SET(id, statement)                                                                      \
    do {                                                                                           \
        int result_;                                                                               \
        vh_lock();                                                                                 \
        VhSettings *settings = settings_of((id), &result_);                                        \
        if (settings != NULL) {                                                                    \
            statement;                                                                             \
        }                                                                                          \
        vh_unlock();                                                                               \
        return result_;                                                                            \
    } while (0)

static int is_switch(int value)
{
    return value == SCE_HTTP_ENABLE || value == SCE_HTTP_DISABLE;
}

int sceHttpSetAuthInfoCallback(int id, SceHttpAuthInfoCallback cbfunc, void *userArg)
{
    VH_TRACE();
    VH_SET(id, settings->auth_callback = cbfunc; settings->auth_argument = userArg);
}

int sceHttpSetAuthEnabled(int id, int enable)
{
    VH_TRACE();
    if (!is_switch(enable))
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    VH_SET(id, settings->auth_enabled = enable);
}

int sceHttpGetAuthEnabled(int id, int *enable)
{
    VH_TRACE();
    if (enable == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    VH_SET(id, *enable = settings->auth_enabled);
}

int sceHttpSetRedirectCallback(int id, SceHttpRedirectCallback cbfunc, void *userArg)
{
    VH_TRACE();
    VH_SET(id, settings->redirect_callback = cbfunc; settings->redirect_argument = userArg);
}

int sceHttpSetAutoRedirect(int id, int enable)
{
    VH_TRACE();
    if (!is_switch(enable))
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    VH_SET(id, settings->auto_redirect = enable);
}

int sceHttpGetAutoRedirect(int id, int *enable)
{
    VH_TRACE();
    if (enable == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    VH_SET(id, *enable = settings->auto_redirect);
}

int sceHttpSetResolveTimeOut(int id, unsigned int usec)
{
    VH_TRACE();
    VH_SET(id, settings->resolve_timeout_us = usec);
}

int sceHttpSetResolveRetry(int id, int retry)
{
    VH_TRACE();
    if (retry < 0)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    VH_SET(id, settings->resolve_retry = retry);
}

int sceHttpSetConnectTimeOut(int id, unsigned int usec)
{
    VH_TRACE();
    VH_SET(id, settings->connect_timeout_us = usec);
}

int sceHttpSetSendTimeOut(int id, unsigned int usec)
{
    VH_TRACE();
    VH_SET(id, settings->send_timeout_us = usec);
}

int sceHttpSetRecvTimeOut(int id, unsigned int usec)
{
    VH_TRACE();
    VH_SET(id, settings->recv_timeout_us = usec);
}

int sceHttpSetResponseHeaderMaxSize(int id, unsigned int headerSize)
{
    VH_TRACE();
    if (headerSize == 0)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    VH_SET(id, settings->response_header_max = headerSize);
}

int sceHttpSetCookieEnabled(int id, int enable)
{
    VH_TRACE();
    if (!is_switch(enable))
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    VH_SET(id, settings->cookie_enabled = enable);
}

int sceHttpGetCookieEnabled(int id, int *enable)
{
    VH_TRACE();
    if (enable == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    VH_SET(id, *enable = settings->cookie_enabled);
}

int sceHttpSetCookieRecvCallback(int id, SceHttpCookieRecvCallback cbfunc, void *userArg)
{
    VH_TRACE();
    VH_SET(id, settings->cookie_recv_callback = cbfunc; settings->cookie_recv_argument = userArg);
}

int sceHttpSetCookieSendCallback(int id, SceHttpCookieSendCallback cbfunc, void *userArg)
{
    VH_TRACE();
    VH_SET(id, settings->cookie_send_callback = cbfunc; settings->cookie_send_argument = userArg);
}

int sceHttpsSetSslCallback(int id, SceHttpsCallback cbfunc, void *userArg)
{
    VH_TRACE();
    VITALS_LOG("https ssl callback id=%d set=%d", id, cbfunc != NULL);
    VH_SET(id, settings->ssl_callback = cbfunc; settings->ssl_argument = userArg);
}

int sceHttpSetAcceptEncodingGZIPEnabled(int id, int enable)
{
    VH_TRACE();
    if (!is_switch(enable))
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    VH_SET(id, settings->accept_gzip = enable);
}

int sceHttpGetAcceptEncodingGZIPEnabled(int id, int *enable)
{
    VH_TRACE();
    if (enable == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    VH_SET(id, *enable = settings->accept_gzip);
}

int sceHttpSetInflateGZIPEnabled(int id, int enable)
{
    VH_TRACE();
    if (!is_switch(enable))
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    VH_SET(id, settings->inflate_gzip = enable);
}

/* For the templates created after it */
int sceHttpSetDefaultAcceptEncodingGZIPEnabled(int enable)
{
    VH_TRACE();
    if (!is_switch(enable))
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    vh_lock();
    g_default_accept_gzip = enable;
    vh_unlock();
    return 0;
}

int sceHttpSetNonblock(int id, int enable)
{
    VH_TRACE();
    if (!is_switch(enable))
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    VH_SET(id, settings->nonblock = enable);
}

int sceHttpGetNonblock(int id, int *enable)
{
    VH_TRACE();
    if (enable == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    VH_SET(id, *enable = settings->nonblock);
}

/* The ICM (network-condition) option has no effect here; it reads back as off */
int sceHttpSetIcmOption(int id, int value)
{
    VH_TRACE();
    (void)value;
    VH_SET(id, (void)settings);
}

int sceHttpGetIcmOption(int id, int *value)
{
    VH_TRACE();
    if (value == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    VH_SET(id, *value = 0);
}

/* ---- request headers, on any level ---- */

static int valid_header_text(const char *text, size_t maximum, int name)
{
    size_t length = strlen(text);
    if (length == 0 ? name : length > maximum)
        return 0;
    for (size_t i = 0; i < length; ++i)
        if (text[i] == '\r' || text[i] == '\n' || (name && (text[i] == ':' || text[i] == ' ')))
            return 0;
    return 1;
}

int sceHttpAddRequestHeader(int id, const char *name, const char *value, unsigned int mode)
{
    VH_TRACE();
    if (name == NULL || value == NULL || (mode != SCE_HTTP_HEADER_OVERWRITE && mode != SCE_HTTP_HEADER_ADD) ||
        !valid_header_text(name, VH_HEADER_NAME_MAX, 1) || !valid_header_text(value, VH_HEADER_VALUE_MAX, 0)) {
        VITALS_LOG("add header %s mode=%u rejected", name != NULL ? name : "(null)", mode);
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    }
    int result;
    vh_lock();
    VhSettings *settings = settings_of(id, &result);
    if (settings != NULL)
        result = vh_add_header(settings, name, value, mode);
    vh_unlock();
    return result;
}

/* As Sony's: a header goes in front of the list, which is sent from the front, so the last one
 * added goes first; overwriting removes the ones of that name before */
int vh_add_header(VhSettings *settings, const char *name, const char *value, unsigned int mode)
{
    VhHeaders *headers = &settings->headers;
    size_t length = strlen(name);
    char *name_copy = vh_strdup(name, length);
    char *value_copy = vh_strdup(value, strlen(value));
    if (name_copy == NULL || value_copy == NULL) {
        vh_free(name_copy);
        vh_free(value_copy);
        return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
    }
    if (mode == SCE_HTTP_HEADER_OVERWRITE) {
        unsigned int kept = 0;
        for (unsigned int i = 0; i < headers->count; ++i) {
            VhHeader *header = &headers->items[i];
            if (strlen(header->name) == length && vh_equal_nocase(header->name, name, length)) {
                vh_free(header->name);
                vh_free(header->value);
            } else
                headers->items[kept++] = *header;
        }
        headers->count = kept;
    }
    if (headers->count == VH_HEADERS_MAX) {
        vh_free(name_copy);
        vh_free(value_copy);
        return (int)SCE_HTTP_ERROR_OUT_OF_SIZE;
    }
    memmove(&headers->items[1], &headers->items[0], headers->count * sizeof(headers->items[0]));
    headers->items[0] = (VhHeader){name_copy, value_copy};
    ++headers->count;
    return 0;
}

/* The same, without the checks on what the header holds */
int sceHttpAddRequestHeaderRaw(int id, const char *name, const char *value, unsigned int mode)
{
    VH_TRACE();
    return sceHttpAddRequestHeader(id, name, value, mode);
}

int sceHttpRemoveRequestHeader(int id, const char *name)
{
    VH_TRACE();
    if (name == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    int result;
    vh_lock();
    VhSettings *settings = settings_of(id, &result);
    if (settings != NULL) {
        /* Every header of that name */
        unsigned int kept = 0;
        size_t length = strlen(name);
        for (unsigned int i = 0; i < settings->headers.count; ++i) {
            VhHeader *header = &settings->headers.items[i];
            if (strlen(header->name) == length && vh_equal_nocase(header->name, name, length)) {
                vh_free(header->name);
                vh_free(header->value);
            } else
                settings->headers.items[kept++] = *header;
        }
        if (kept == settings->headers.count)
            result = (int)SCE_HTTP_ERROR_NOT_FOUND;
        settings->headers.count = kept;
    }
    vh_unlock();
    return result;
}

/* ---- HTTPS options, for the whole library ---- */

int sceHttpsEnableOption(unsigned int sslFlags)
{
    VH_TRACE();
    VITALS_LOG("https enable option flags=%08X", sslFlags);
    vh_lock();
    int result = vh_initialized();
    if (result == 0)
        g_https_options |= sslFlags;
    vh_unlock();
    return result;
}

int sceHttpsDisableOption(unsigned int sslFlags)
{
    VH_TRACE();
    VITALS_LOG("https disable option flags=%08X", sslFlags);
    vh_lock();
    int result = vh_initialized();
    if (result == 0)
        g_https_options &= ~sslFlags;
    vh_unlock();
    return result;
}

/* ---- HTTPS options, for one template, connection or request ---- */

int sceHttpsEnableOption2(int id, unsigned int sslFlags)
{
    VH_TRACE();
    VITALS_LOG("https enable option2 id=%d flags=%08X", id, sslFlags);
    VH_SET(id, settings->https_enabled |= sslFlags; settings->https_disabled &= ~sslFlags);
}

int sceHttpsDisableOption2(int id, unsigned int sslFlags)
{
    VH_TRACE();
    VITALS_LOG("https disable option2 id=%d flags=%08X", id, sslFlags);
    VH_SET(id, settings->https_disabled |= sslFlags; settings->https_enabled &= ~sslFlags);
}

int sceHttpsEnableOptionPrivate(int id, unsigned int sslFlags)
{
    VH_TRACE();
    VITALS_LOG("https enable option private id=%d flags=%08X", id, sslFlags);
    return sceHttpsEnableOption2(id, sslFlags);
}

int sceHttpsDisableOptionPrivate(int id, unsigned int sslFlags)
{
    VH_TRACE();
    VITALS_LOG("https disable option private id=%d flags=%08X", id, sslFlags);
    return sceHttpsDisableOption2(id, sslFlags);
}

int sceHttpsLoadCert(int caCertNum, const SceHttpsData **caList, const SceHttpsData *cert, const SceHttpsData *privKey)
{
    VH_TRACE();
    if (caCertNum < 0 || (caCertNum > 0 && caList == NULL))
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    vh_lock();
    int result = vh_initialized();
    if (result == 0)
        result = vh_tls_load_certs(caCertNum, caList, cert, privKey);
    vh_unlock();
    return result;
}

int sceHttpsUnloadCert(void)
{
    VH_TRACE();
    vh_lock();
    int result = vh_initialized();
    if (result == 0)
        vh_tls_unload_certs();
    vh_unlock();
    return result;
}

/* The system's CA list isn't reachable from here; an empty one is handed out */
int sceHttpsGetCaList(SceHttpsCaList *caList)
{
    VH_TRACE();
    if (caList == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    caList->caCerts = NULL;
    caList->caNum = 0;
    return vh_initialized();
}

int sceHttpsFreeCaList(SceHttpsCaList *caList)
{
    VH_TRACE();
    if (caList == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    return vh_initialized();
}

int sceHttpSslIsCtxCreated(int *isCreated)
{
    VH_TRACE();
    if (isCreated == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    *isCreated = 1;
    return vh_initialized();
}

int sceHttpAuthCacheFlush(void)
{
    VH_TRACE();
    return vh_initialized();
}

int sceHttpRedirectCacheFlush(void)
{
    VH_TRACE();
    return vh_initialized();
}
