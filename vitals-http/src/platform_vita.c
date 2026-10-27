#include "vh.h"

#include "diagnostics.h"
#include "user_runtime.h"
#include "vitals/redirects.h"
#include "vitals/useragent.h"

#include <string.h>

#include <psp2/kernel/clib.h>
#include <psp2/kernel/error.h>
#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/sysmem.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/net/net.h>
#include <psp2/rtc.h>

/* The engine on the Vita: a memory block with an mspace for the app's pool, a lightweight mutex,
 * and SceNet. TLS's memory, and the C library this module is linked without, are tls13-vita's
 * runtime (user_runtime.c) */

#define VH_LW_MUTEX_RECURSIVE 0x02u
/* The mspace's own bookkeeping, on top of the pool the app asks for */
#define VH_POOL_SLACK(size) ((size) / 8u + 0x10000u)
/* How often a connect that is waited for checks whether it was aborted, in microseconds */
#define VH_CONNECT_SLICE 100000u
/* A non-blocking request's worker: Mbed TLS's handshake runs on it */
#define VH_WORKER_STACK 0x10000
#define VH_WORKER_PRIORITY 0x10000100
/* Seconds from 0001-01-01, where the RTC counts from, to 1970-01-01 */
#define VH_RTC_EPOCH 62135596800ll

#ifndef VITALS_HTTP_CA_PATH
#define VITALS_HTTP_CA_PATH "vs0:/data/external/cert/CA_LIST.cer"
#endif

/* VitaSDK has the stub but not the prototype; on 3.60 the options are 16 reserved bytes and the
 * output at most 0x124 bytes */
int _sceAppMgrConvertVs0UserDrivePath(const char *path, char *converted_path, SceSize capacity,
                                      const void *options);

static SceKernelLwMutexWork g_mutex;
static SceUID g_pool_block = -1;
static SceClibMspace g_pool;
/* vh_platform_wait's: its own mutex, since the condition can't wait on the recursive lock */
static SceKernelLwMutexWork g_wait_mutex;
static SceKernelLwCondWork g_wait_condition;
static volatile unsigned int g_generation;
static int g_heap_ready;

int module_start(SceSize args, void *argp)
{
    (void)args, (void)argp;
    if (sceKernelCreateLwMutex(&g_mutex, "vh_lock", VH_LW_MUTEX_RECURSIVE, 0, NULL) < 0)
        return SCE_KERNEL_START_FAILED;
    if (sceKernelCreateLwMutex(&g_wait_mutex, "vh_wait", 0, 0, NULL) < 0 ||
        sceKernelCreateLwCond(&g_wait_condition, "vh_wait", 0, &g_wait_mutex, NULL) < 0) {
        sceKernelDeleteLwMutex(&g_mutex);
        return SCE_KERNEL_START_FAILED;
    }
    return SCE_KERNEL_START_SUCCESS;
}

/* Mbed TLS's global state stays in the heap, so it is freed only when nothing is left in it */
int module_stop(SceSize args, void *argp)
{
    (void)args, (void)argp;
    sceHttpTerm();
    if (g_heap_ready)
        vitals_user_runtime_destroy();
    sceKernelDeleteLwCond(&g_wait_condition);
    sceKernelDeleteLwMutex(&g_wait_mutex);
    sceKernelDeleteLwMutex(&g_mutex);
    return SCE_KERNEL_STOP_SUCCESS;
}

int _start(SceSize args, void *argp) __attribute__((weak, alias("module_start")));

void vh_platform_lock(void)
{
    sceKernelLockLwMutex(&g_mutex, 1, NULL);
}

void vh_platform_unlock(void)
{
    sceKernelUnlockLwMutex(&g_mutex, 1);
}

/* ---- memory ---- */

static SceUID new_mspace(const char *name, size_t size, SceClibMspace *mspace)
{
    size = (size + 0xfffu) & ~(size_t)0xfffu;
    SceUID block = sceKernelAllocMemBlock(name, SCE_KERNEL_MEMBLOCK_TYPE_USER_RW, size, NULL);
    void *base;
    if (block < 0)
        return block;
    if (sceKernelGetMemBlockBase(block, &base) < 0 || (*mspace = sceClibMspaceCreate(base, size)) == NULL) {
        sceKernelFreeMemBlock(block);
        return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
    }
    return block;
}

int vh_platform_init(unsigned int pool_size)
{
    SceUID block = new_mspace("vh_pool", (size_t)pool_size + VH_POOL_SLACK(pool_size), &g_pool);
    if (block < 0)
        return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
    g_pool_block = block;
    return 0;
}

void vh_platform_term(void)
{
    if (g_pool_block >= 0) {
        sceClibMspaceDestroy(g_pool);
        sceKernelFreeMemBlock(g_pool_block);
        g_pool_block = -1;
        g_pool = NULL;
    }
}

void *vh_platform_alloc(size_t size)
{
    return g_pool != NULL ? sceClibMspaceMalloc(g_pool, size) : NULL;
}

void vh_platform_free(void *pointer)
{
    if (g_pool != NULL && pointer != NULL)
        sceClibMspaceFree(g_pool, pointer);
}

int vh_platform_ca_path(char *path, size_t capacity)
{
    const uint32_t options[4] = {0};
    if (capacity < 0x124u)
        return -1;
    memset(path, 0, capacity);
    if (_sceAppMgrConvertVs0UserDrivePath(VITALS_HTTP_CA_PATH, path, 0x124u, options) < 0 ||
        memchr(path, '\0', 0x124u) == NULL || path[0] == '\0')
        return -1;
    return 0;
}

/* Every process loads this library, most never use https: the heap waits for the first one */
int vh_platform_tls_init(void)
{
    if (!g_heap_ready && vitals_user_runtime_init() == 0)
        g_heap_ready = 1;
    return g_heap_ready ? 0 : -1;
}

/* Through the kernel plugin: games may not open ux0:data themselves */
int vh_platform_redirects_read(unsigned int offset, void *buffer, unsigned int size)
{
    return vitals_redirects_read(offset, buffer, size);
}

int vh_platform_useragent_read(void *buffer, unsigned int size)
{
    return vitals_useragent_read(buffer, size);
}

unsigned long long vh_platform_clock_us(void)
{
    return sceKernelGetProcessTimeWide();
}

typedef struct VhThreadStart
{
    void (*function)(void *);
    void *argument;
} VhThreadStart;

/* The start copies its arguments onto the thread's stack */
static int thread_entry(SceSize size, void *data)
{
    (void)size;
    const VhThreadStart *start = data;
    start->function(start->argument);
    return sceKernelExitDeleteThread(0);
}

int vh_platform_thread(void (*function)(void *), void *argument)
{
    VhThreadStart start = {function, argument};
    SceUID thread = sceKernelCreateThread("vh_worker", thread_entry, VH_WORKER_PRIORITY, VH_WORKER_STACK, 0, 0, NULL);
    if (thread < 0)
        return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
    int result = sceKernelStartThread(thread, sizeof(start), &start);
    if (result < 0) {
        sceKernelDeleteThread(thread);
        return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
    }
    return 0;
}

unsigned int vh_platform_generation(void)
{
    return __atomic_load_n(&g_generation, __ATOMIC_ACQUIRE);
}

void vh_platform_notify(void)
{
    sceKernelLockLwMutex(&g_wait_mutex, 1, NULL);
    __atomic_add_fetch(&g_generation, 1u, __ATOMIC_RELEASE);
    sceKernelSignalLwCondAll(&g_wait_condition);
    sceKernelUnlockLwMutex(&g_wait_mutex, 1);
}

int vh_platform_wait(unsigned int generation, long long timeout_us)
{
    int result = 0;
    unsigned int left = timeout_us < 0 ? 0 : timeout_us > 0x7fffffff ? 0x7fffffffu : (unsigned int)timeout_us;
    sceKernelLockLwMutex(&g_wait_mutex, 1, NULL);
    while (result == 0 && vh_platform_generation() == generation) {
        /* The timeout left is written back on each wake */
        int waited = sceKernelWaitLwCond(&g_wait_condition, timeout_us < 0 ? NULL : &left);
        if (waited == (int)SCE_KERNEL_ERROR_WAIT_TIMEOUT)
            result = (int)SCE_HTTP_ERROR_TIMEOUT;
        else if (waited < 0)
            result = waited;
    }
    sceKernelUnlockLwMutex(&g_wait_mutex, 1);
    return result;
}

long long vh_platform_time(void)
{
    SceRtcTick tick;
    if (sceRtcGetCurrentTick(&tick) < 0)
        return 0;
    return (long long)(tick.tick / 1000000u) - VH_RTC_EPOCH;
}

/* ---- the network ---- */

struct VhTransport
{
    int socket;
    int resolver;
    volatile int aborted;
    int error_number;
    VhTls *tls;
};

VhTransport *vh_transport_create(void)
{
    VhTransport *transport = vh_alloc(sizeof(*transport));
    if (transport != NULL) {
        memset(transport, 0, sizeof(*transport));
        transport->socket = transport->resolver = -1;
    }
    return transport;
}

/* A SceNet error as libhttp has it; its errno is kept for sceHttpGetLastErrno */
static int network_error(VhTransport *transport, int error)
{
    transport->error_number = error & 0xff;
    if (transport->aborted)
        return (int)SCE_HTTP_ERROR_ABORTED;
    if (error == (int)SCE_NET_ERROR_ETIMEDOUT || error == (int)SCE_NET_ERROR_EAGAIN)
        return (int)SCE_HTTP_ERROR_TIMEOUT;
    return (int)SCE_HTTP_ERROR_NETWORK;
}

static int resolver_error(int error)
{
    switch (error) {
    case (int)SCE_NET_ERROR_RESOLVER_EPACKET:
        return (int)SCE_HTTP_ERROR_RESOLVER_EPACKET;
    case (int)SCE_NET_ERROR_RESOLVER_ENODNS:
        return (int)SCE_HTTP_ERROR_RESOLVER_ENODNS;
    case (int)SCE_NET_ERROR_RESOLVER_ETIMEDOUT:
        return (int)SCE_HTTP_ERROR_RESOLVER_ETIMEDOUT;
    case (int)SCE_NET_ERROR_RESOLVER_ENOSUPPORT:
        return (int)SCE_HTTP_ERROR_RESOLVER_ENOSUPPORT;
    case (int)SCE_NET_ERROR_RESOLVER_EFORMAT:
        return (int)SCE_HTTP_ERROR_RESOLVER_EFORMAT;
    case (int)SCE_NET_ERROR_RESOLVER_ESERVERFAILURE:
        return (int)SCE_HTTP_ERROR_RESOLVER_ESERVERFAILURE;
    case (int)SCE_NET_ERROR_RESOLVER_ENOHOST:
        return (int)SCE_HTTP_ERROR_RESOLVER_ENOHOST;
    case (int)SCE_NET_ERROR_RESOLVER_ENOTIMPLEMENTED:
        return (int)SCE_HTTP_ERROR_RESOLVER_ENOTIMPLEMENTED;
    case (int)SCE_NET_ERROR_RESOLVER_ESERVERREFUSED:
        return (int)SCE_HTTP_ERROR_RESOLVER_ESERVERREFUSED;
    case (int)SCE_NET_ERROR_RESOLVER_ENORECORD:
        return (int)SCE_HTTP_ERROR_RESOLVER_ENORECORD;
    default:
        return (int)SCE_HTTP_ERROR_NETWORK;
    }
}

static int resolve(VhTransport *transport, const VhOpen *open, SceNetInAddr *address)
{
    if (open->host[0] == '[')
        return (int)SCE_HTTP_ERROR_RESOLVER_ENOSUPPORT;
    if (sceNetInetPton(SCE_NET_AF_INET, open->host, address) == 1)
        return 0;
    int resolver = sceNetResolverCreate("vh_resolver", NULL, 0);
    if (resolver < 0)
        return network_error(transport, resolver);
    transport->resolver = resolver;
    int result = transport->aborted ? (int)SCE_HTTP_ERROR_ABORTED
                                    : sceNetResolverStartNtoa(resolver, open->host, address,
                                                              (int)open->resolve_timeout_us, open->resolve_retry, 0);
    transport->resolver = -1;
    sceNetResolverDestroy(resolver);
    if (result < 0)
        return transport->aborted ? (int)SCE_HTTP_ERROR_ABORTED : resolver_error(result);
    return 0;
}

static void set_option(int socket, int level, int name, int value)
{
    sceNetSetsockopt(socket, level, name, &value, sizeof(value));
}

/* Waits for a non-blocking connect, in slices so an abort is seen; 0 or an error */
static int wait_connected(VhTransport *transport, unsigned int timeout_us)
{
    SceNetEpollEvent event;
    int epoll = sceNetEpollCreate("vh_epoll", 0);
    if (epoll < 0)
        return network_error(transport, epoll);
    memset(&event, 0, sizeof(event));
    event.events = SCE_NET_EPOLLOUT | SCE_NET_EPOLLERR | SCE_NET_EPOLLHUP;
    event.data.fd = transport->socket;
    int result = sceNetEpollControl(epoll, SCE_NET_EPOLL_CTL_ADD, transport->socket, &event);
    for (unsigned int waited = 0; result >= 0;) {
        if (transport->aborted) {
            result = (int)SCE_HTTP_ERROR_ABORTED;
            break;
        }
        if (timeout_us != 0 && waited >= timeout_us) {
            result = (int)SCE_HTTP_ERROR_TIMEOUT;
            break;
        }
        int ready = sceNetEpollWait(epoll, &event, 1, (int)VH_CONNECT_SLICE);
        if (ready > 0) {
            result = 0;
            break;
        }
        if (ready < 0 && ready != (int)SCE_NET_ERROR_EINTR)
            result = ready;
        waited += VH_CONNECT_SLICE;
    }
    sceNetEpollDestroy(epoll);
    if (result < 0 && result != (int)SCE_HTTP_ERROR_ABORTED && result != (int)SCE_HTTP_ERROR_TIMEOUT)
        return network_error(transport, result);
    if (result < 0)
        return result;
    int error = 0;
    unsigned int size = sizeof(error);
    if (sceNetGetsockopt(transport->socket, SCE_NET_SOL_SOCKET, SCE_NET_SO_ERROR, &error, &size) < 0 || error != 0) {
        transport->error_number = error;
        return transport->aborted ? (int)SCE_HTTP_ERROR_ABORTED : (int)SCE_HTTP_ERROR_NETWORK;
    }
    return 0;
}

int vh_transport_connect(VhTransport *transport, const VhOpen *open, int *ssl_error, unsigned int *ssl_detail)
{
    SceNetInAddr address;
    SceNetSockaddrIn server;

    *ssl_error = 0;
    *ssl_detail = 0;
    VITALS_VERBOSE("resolve %s", open->host);
    int result = resolve(transport, open, &address);
    VITALS_VERBOSE("resolved %s rc=%08X", open->host, (unsigned int)result);
    if (result < 0)
        return result;
    int socket = sceNetSocket("vh_socket", SCE_NET_AF_INET, SCE_NET_SOCK_STREAM, 0);
    if (socket < 0)
        return network_error(transport, socket);
    transport->socket = socket;
    if (transport->aborted)
        return (int)SCE_HTTP_ERROR_ABORTED;

    set_option(socket, SCE_NET_SOL_SOCKET, SCE_NET_SO_NBIO, 1);
    memset(&server, 0, sizeof(server));
    server.sin_len = sizeof(server);
    server.sin_family = SCE_NET_AF_INET;
    server.sin_port = sceNetHtons(open->port);
    server.sin_addr = address;
    result = sceNetConnect(socket, (const SceNetSockaddr *)&server, sizeof(server));
    if (result == (int)SCE_NET_ERROR_EINPROGRESS)
        result = wait_connected(transport, open->connect_timeout_us);
    else if (result < 0)
        result = network_error(transport, result);
    VITALS_VERBOSE("connected %s:%u rc=%08X", open->host, (unsigned int)open->port, (unsigned int)result);
    if (result < 0)
        return result;
    set_option(socket, SCE_NET_SOL_SOCKET, SCE_NET_SO_NBIO, 0);
    set_option(socket, SCE_NET_SOL_SOCKET, SCE_NET_SO_SNDTIMEO, (int)open->send_timeout_us);
    set_option(socket, SCE_NET_SOL_SOCKET, SCE_NET_SO_RCVTIMEO, (int)open->recv_timeout_us);
    set_option(socket, SCE_NET_IPPROTO_TCP, SCE_NET_TCP_NODELAY, 1);
    if (open->https) {
        VITALS_VERBOSE("tls start %s options=%03X", open->host, (unsigned int)open->https_options);
        return vh_tls_start(&transport->tls, transport, open, ssl_error, ssl_detail);
    }
    return 0;
}

int vh_transport_raw_send(VhTransport *transport, const void *data, size_t size)
{
    for (;;) {
        int sent = sceNetSend(transport->socket, data, size > 0x40000000u ? 0x40000000u : (unsigned int)size, 0);
        if (sent >= 0)
            return transport->aborted ? (int)SCE_HTTP_ERROR_ABORTED : sent;
        if (sent != (int)SCE_NET_ERROR_EINTR || transport->aborted)
            return network_error(transport, sent);
    }
}

int vh_transport_raw_recv(VhTransport *transport, void *data, size_t size)
{
    for (;;) {
        int received = sceNetRecv(transport->socket, data, size > 0x40000000u ? 0x40000000u : (unsigned int)size, 0);
        if (received >= 0)
            return transport->aborted ? (int)SCE_HTTP_ERROR_ABORTED : received;
        if (received != (int)SCE_NET_ERROR_EINTR || transport->aborted)
            return network_error(transport, received);
    }
}

int vh_transport_send(VhTransport *transport, const void *data, size_t size)
{
    if (transport->tls != NULL)
        return vh_tls_send(transport->tls, data, size);
    const unsigned char *at = data;
    while (size > 0) {
        int sent = vh_transport_raw_send(transport, at, size);
        if (sent < 0)
            return sent;
        at += sent;
        size -= (size_t)sent;
    }
    return 0;
}

int vh_transport_recv(VhTransport *transport, void *data, size_t size)
{
    if (transport->tls != NULL)
        return vh_tls_recv(transport->tls, data, size);
    return vh_transport_raw_recv(transport, data, size);
}

void vh_transport_abort(VhTransport *transport)
{
    transport->aborted = 1;
    int resolver = transport->resolver, socket = transport->socket;
    if (resolver >= 0)
        sceNetResolverAbort(resolver, 0);
    if (socket >= 0)
        sceNetSocketAbort(socket, 0);
}

int vh_transport_aborted(VhTransport *transport)
{
    return transport->aborted;
}

int vh_transport_errno(VhTransport *transport)
{
    return transport->error_number;
}

void vh_transport_close(VhTransport *transport)
{
    vh_tls_close(transport->tls);
    if (transport->socket >= 0)
        sceNetSocketClose(transport->socket);
    vh_free(transport);
}
