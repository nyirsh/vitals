#include "vh.h"

#include "diagnostics.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* Exports of Sony's libhttp that no header or NID database names, as its code does them */

static void log_line(const char *format, ...) __attribute__((format(printf, 1, 2)));
static void log_line(const char *format, ...)
{
#if VITALS_DEBUG >= 1
    char line[192];
    va_list arguments;
    va_start(arguments, format);
    vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    VITALS_LOG("%s", line);
#else
    (void)format;
#endif
}

static const char *scheme(int https)
{
    return https ? "https " : "http  ";
}

/* The socket a connection has now (its open one, or one a request of its has), and that request */
static int connection_socket(const VhObject *connection, int *leased)
{
    *leased = 0;
    if (connection->as.connection.transport != NULL)
        return vh_transport_socket(connection->as.connection.transport);
    for (unsigned int slot = 0; slot < VH_OBJECT_MAX; ++slot)
    {
        VhObject *object = vh_object_at(slot);
        if (object != NULL && object->kind == VH_REQUEST && object->parent == connection->id &&
            object->as.request.transport != NULL)
        {
            *leased = object->id;
            return vh_transport_socket(object->as.request.transport);
        }
    }
    return -1;
}

static unsigned int count_of(VhKind kind)
{
    unsigned int count = 0;
    for (unsigned int slot = 0; slot < VH_OBJECT_MAX; ++slot)
    {
        VhObject *object = vh_object_at(slot);
        count += object != NULL && object->kind == kind && !object->doomed;
    }
    return count;
}

/* Every request: its ID, HTTP status, connection, then scheme, host and path */
static void dump_requests(void)
{
    log_line("num. of current request = %d", (int)count_of(VH_REQUEST));
    log_line("id       status connId   ");
    for (unsigned int slot = 0; slot < VH_OBJECT_MAX; ++slot)
    {
        VhObject *object = vh_object_at(slot);
        if (object == NULL || object->kind != VH_REQUEST || object->doomed)
            continue;
        const VhRequest *request = &object->as.request;
        log_line("%8x   %4d  %8x%s%s %s", (unsigned int)object->id, request->status_code, (unsigned int)object->parent,
                 scheme(request->https), request->host, request->path[0] != '\0' ? request->path : "/");
    }
}

/* Every connection: its ID, socket, port, the request using its socket, keep-alive, then scheme and
 * host; Sony's prints the server's address in the parentheses, which isn't kept here */
static void dump_connections(void)
{
    log_line("num. of active connection = %d", (int)count_of(VH_CONNECTION));
    log_line("id        sock  port leased4  stat ");
    for (unsigned int slot = 0; slot < VH_OBJECT_MAX; ++slot)
    {
        VhObject *object = vh_object_at(slot);
        if (object == NULL || object->kind != VH_CONNECTION || object->doomed)
            continue;
        const VhConnection *connection = &object->as.connection;
        int leased;
        int socket = connection_socket(object, &leased);
        log_line("%8x %5d %3d  %8x %4d %s%s(-)", (unsigned int)object->id, socket, connection->port,
                 (unsigned int)leased, connection->keep_alive, scheme(connection->https), connection->host);
    }
    log_line("---------------------");
}

static void dump_pool(void)
{
    SceHttpMemoryPoolStats stats;
    memset(&stats, 0, sizeof(stats));
    (void)sceHttpGetMemoryPoolStats(&stats);
    log_line(" current      max");
    log_line("%8x %8x", stats.currentInuseSize, stats.maxInuseSize);
}

/* Sony's does nothing here either */
/* NID 0x5B6A0ACE */
int sceHttpPrivateDebugNothing(void)
{
    VH_TRACE();
    return 0;
}

/* NID 0xFE60380A */
void sceHttpPrivateDumpRequests(void)
{
    VH_TRACE();
    vh_lock();
    dump_requests();
    vh_unlock();
}

/* NID 0xB0E41827 */
void sceHttpPrivateDumpConnections(void)
{
    VH_TRACE();
    vh_lock();
    dump_connections();
    vh_unlock();
}

/* NID 0x88116DB8 */
void sceHttpPrivateDumpMemoryPool(void)
{
    VH_TRACE();
    dump_pool();
}

/* NID 0x0B0D8E7A */
void sceHttpPrivateDumpDebugInfo(void)
{
    VH_TRACE();
    vh_lock();
    log_line("**** libhttp debug information ****");
    log_line("MEMORY POOL");
    dump_pool();
    log_line("CONNECTION");
    dump_connections();
    log_line("REQUEST");
    dump_requests();
    vh_unlock();
}

/* ---- statistics of one object ---- */

/* A connection's socket: alive while it is open (shut_down stays 0: sockets aren't shut down here,
 * only closed); first_socket is the same, as Sony's sets both when it opens one */
/* NID 0x54847CFE */
int sceHttpPrivateGetConnectionStats(int connId, SceHttpPrivateConnectionStats *stats)
{
    VH_TRACE();
    if (stats == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    vh_lock();
    int result = vh_initialized();
    VhObject *connection = result == 0 ? vh_find(connId, VH_CONNECTION) : NULL;
    if (result == 0 && connection == NULL)
        result = (int)SCE_HTTP_ERROR_INVALID_ID;
    if (connection != NULL)
    {
        int leased;
        int socket = connection_socket(connection, &leased);
        stats->alive = socket >= 0;
        stats->shut_down = 0;
        stats->socket = socket;
        stats->first_socket = socket;
    }
    vh_unlock();
    return result;
}

/* A request's: its connection's socket, and Sony's own per-request one, which there isn't here */
/* NID 0x80E6013D */
int sceHttpPrivateGetRequestStats(int reqId, SceHttpPrivateRequestStats *stats)
{
    VH_TRACE();
    if (stats == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    vh_lock();
    int result = vh_initialized();
    VhObject *request = result == 0 ? vh_find(reqId, VH_REQUEST) : NULL;
    if (result == 0 && request == NULL)
        result = (int)SCE_HTTP_ERROR_INVALID_ID;
    if (request != NULL)
    {
        int socket = request->as.request.transport != NULL ? vh_transport_socket(request->as.request.transport) : -1;
        if (socket < 0)
        {
            int leased;
            VhObject *connection = vh_parent(request);
            socket = connection != NULL ? connection_socket(connection, &leased) : -1;
        }
        stats->socket = socket;
        stats->own_socket = -1;
        stats->first_socket = socket;
    }
    vh_unlock();
    return result;
}

/* ---- settings no header names, on a template, connection or request, inherited as the others ---- */

/* The object's settings, with the lock held: NULL, with the error, before init or for a bad ID */
static VhSettings *settings_of(int id, int *result)
{
    *result = vh_initialized();
    if (*result != 0)
        return NULL;
    VhObject *object = vh_find(id, VH_FREE);
    if (object == NULL)
        *result = (int)SCE_HTTP_ERROR_INVALID_ID;
    return object != NULL ? &object->settings : NULL;
}

/* Option 19 */
/* NID 0x43A7CC70 */
int sceHttpPrivateSetOption19(int id, int value)
{
    VH_TRACE();
    int result;
    vh_lock();
    VhSettings *settings = settings_of(id, &result);
    if (settings != NULL)
        settings->option19 = value;
    vh_unlock();
    VITALS_LOG("private option 19 id=%d value=%d rc=%08X", id, value, (unsigned int)result);
    return result;
}

/* A mode, 2 or 3, of a template or connection only */
/* NID 0x175685B8 */
int sceHttpPrivateSetMode(int id, int mode)
{
    VH_TRACE();
    if (mode != 2 && mode != 3)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    vh_lock();
    int result = vh_initialized();
    VhObject *object = result == 0 ? vh_find(id, VH_FREE) : NULL;
    if (result == 0 && (object == NULL || object->kind == VH_REQUEST))
        result = (int)SCE_HTTP_ERROR_INVALID_ID;
    else if (object != NULL)
        object->settings.mode = mode;
    vh_unlock();
    VITALS_LOG("private mode id=%d mode=%d rc=%08X", id, mode, (unsigned int)result);
    return result;
}

/* Option 14: from then on, the object's connections set socket option 0x40000, to 0 when bit 0 is
 * set and to 8 otherwise, as Sony's does on all of them */
/* NID 0xF30073EC */
int sceHttpPrivateSetSocketOption(int id, unsigned char value)
{
    VH_TRACE();
    int result;
    vh_lock();
    VhSettings *settings = settings_of(id, &result);
    if (settings != NULL)
    {
        settings->option14 = value;
        settings->option14_set = 1;
    }
    vh_unlock();
    VITALS_LOG("private option 14 id=%d value=%u rc=%08X", id, value, (unsigned int)result);
    return result;
}

/* Option 14 back: Sony's asks for it 4 bytes long where it is 1, so it always refuses, as here */
/* NID 0x30F5D11F */
int sceHttpPrivateGetSocketOption(int id, int *value)
{
    VH_TRACE();
    (void)value;
    int result;
    vh_lock();
    VhSettings *settings = settings_of(id, &result);
    if (settings != NULL)
        result = (int)SCE_HTTP_ERROR_INVALID_VALUE;
    vh_unlock();
    return result;
}

/* A proxy (options 17 and 18): kept, and passed on, but connections are always made directly */
/* NID 0x53B722F2 */
int sceHttpPrivateSetProxy(int id, int mode, int version, const char *host, unsigned short port)
{
    VH_TRACE();
    if (host == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    int result;
    vh_lock();
    VhSettings *settings = settings_of(id, &result);
    if (settings != NULL)
    {
        char *copy = vh_strdup(host, strlen(host));
        if (copy == NULL)
            result = (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
        else
        {
            vh_free(settings->proxy_host);
            settings->proxy_host = copy;
            settings->proxy_mode = mode;
            settings->proxy_version = version;
            settings->proxy_port = port;
        }
    }
    vh_unlock();
    VITALS_LOG("private proxy id=%d mode=%d port=%u rc=%08X: not used, connections are direct", id, mode, port,
               (unsigned int)result);
    return result;
}

/* Option 21, on or off: only 1 turns it on */
/* NID 0xC498765A */
int sceHttpPrivateSetOption21(int id, int value)
{
    VH_TRACE();
    int result;
    vh_lock();
    VhSettings *settings = settings_of(id, &result);
    if (settings != NULL)
        settings->option21 = value == 1;
    vh_unlock();
    VITALS_LOG("private option 21 id=%d value=%d rc=%08X", id, value, (unsigned int)result);
    return result;
}

/* Sony's library-wide option 22, which it hands to the TLS contexts libssl makes for it; this
 * library's TLS isn't libssl's, so it is only kept */
static int g_option22;

/* NID 0x855D5254 */
int sceHttpPrivateSetSslContextOption(int value)
{
    VH_TRACE();
    vh_lock();
    int result = vh_initialized();
    if (result == 0)
        g_option22 = value;
    vh_unlock();
    VITALS_LOG("private option 22 value=%d rc=%08X", value, (unsigned int)result);
    return result;
}

/* ---- the store of loaded certificates: the CA certificates, the client certificate and its key,
 * the same ones sceHttpsLoadCert sets, here one at a time ---- */

/* Sony's sets up the store with the caller's allocator; this one uses its own memory */
/* NID 0xE0825488 */
int sceHttpPrivateLoadedCertInit(SceHttpPrivateAlloc allocate, SceHttpPrivateFree release)
{
    VH_TRACE();
    (void)allocate, (void)release;
    return 0;
}

/* Forgets the client certificate and key */
/* NID 0x42108FBE */
int sceHttpPrivateLoadedCertClearClient(void)
{
    VH_TRACE();
    vh_lock();
    vh_tls_clear_client();
    vh_unlock();
    return 0;
}

/* Forgets the CA certificates */
/* NID 0x0CC59EF6 */
int sceHttpPrivateLoadedCertClearCa(void)
{
    VH_TRACE();
    vh_lock();
    vh_tls_clear_cas();
    vh_unlock();
    return 0;
}

/* Ends the store: everything in it is forgotten */
/* NID 0x11C9BCE8 */
int sceHttpPrivateLoadedCertTerm(void)
{
    VH_TRACE();
    vh_lock();
    vh_tls_unload_certs();
    vh_unlock();
    return 0;
}

/* Adds a CA certificate, PEM or DER */
/* NID 0xF8885CFD */
int sceHttpPrivateLoadedCertAddCa(const void *data, unsigned int size)
{
    VH_TRACE();
    vh_lock();
    int result = vh_tls_add_ca(data, size);
    vh_unlock();
    VITALS_LOG("private add CA certificate %u bytes rc=%08X", size, (unsigned int)result);
    return result;
}

/* Sets the client certificate */
/* NID 0x031EBD2A */
int sceHttpPrivateLoadedCertSetClientCert(const void *data, unsigned int size)
{
    VH_TRACE();
    vh_lock();
    int result = vh_tls_set_client_certificate(data, size);
    vh_unlock();
    VITALS_LOG("private client certificate %u bytes rc=%08X", size, (unsigned int)result);
    return result;
}

/* Sets the client key */
/* NID 0x802E3C30 */
int sceHttpPrivateLoadedCertSetClientKey(const void *data, unsigned int size)
{
    VH_TRACE();
    vh_lock();
    int result = vh_tls_set_client_key(data, size);
    vh_unlock();
    VITALS_LOG("private client key %u bytes rc=%08X", size, (unsigned int)result);
    return result;
}

/* ---- the rest ---- */

/* Sony's installs libhttp's certificate check on a libssl context its caller made (the NetCheck
 * dialog's own TLS, on Sony's libssl): (context, argument), 0x80435801 when one is missing. That
 * check is libhttp's code on libssl's certificates, which this library has neither of, so the
 * context is left as libssl made it; failing would end the game's PSN sign-in */
/* NID 0xA9A39BA1 */
int sceHttpPrivateSslContextAddCertCheck(unsigned int context, unsigned int argument)
{
    VH_TRACE();
    VITALS_LOG("private export A9A39BA1 context=%08X argument=%08X: libssl's own checks only", context, argument);
    return context == 0 || argument == 0 ? (int)0x80435801 : 0;
}

/* Sony's does nothing but succeed */
/* NID 0xA4CF892E */
int sceHttpPrivateCertCheckNothing(void)
{
    VH_TRACE();
    return 0;
}
