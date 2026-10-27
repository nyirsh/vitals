#include "vh.h"
#include "user_runtime.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdarg.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* The engine on a desktop, for testing it: malloc, a pthread mutex and BSD sockets; TLS is the real
 * Mbed TLS, over tls13-vita's Vita stand-ins (tests/transport/vita_mock.c) */

#define VH_CONNECT_SLICE_MS 100

/* The CA bundle and the host redirect list, which the test names */
const char *vh_test_ca_path, *vh_test_redirects_path, *vh_test_useragent_path;

int vh_platform_useragent_read(void *buffer, unsigned int size)
{
    FILE *file = vh_test_useragent_path != NULL ? fopen(vh_test_useragent_path, "rb") : NULL;
    if (file == NULL)
        return (int)0x80010002;
    size_t got = fread(buffer, 1, size, file);
    fclose(file);
    return (int)got;
}

int vh_platform_redirects_read(unsigned int offset, void *buffer, unsigned int size)
{
    FILE *file = vh_test_redirects_path != NULL ? fopen(vh_test_redirects_path, "rb") : NULL;
    if (file == NULL)
        return (int)0x80010002;
    size_t got = fseek(file, (long)offset, SEEK_SET) == 0 ? fread(buffer, 1, size, file) : 0;
    fclose(file);
    return (int)got;
}

/* The debug log (VITALS_LOG), shown when VH_TEST_LOG is set */
int sceClibPrintf(const char *format, ...)
{
    va_list arguments;
    int result = 0;
    if (getenv("VH_TEST_LOG") == NULL)
        return 0;
    va_start(arguments, format);
    result = vfprintf(stderr, format, arguments);
    va_end(arguments);
    return result;
}

static pthread_mutex_t g_mutex;
static pthread_once_t g_mutex_once = PTHREAD_ONCE_INIT;

static void make_mutex(void)
{
    pthread_mutexattr_t attributes;
    pthread_mutexattr_init(&attributes);
    pthread_mutexattr_settype(&attributes, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&g_mutex, &attributes);
}

void vh_platform_lock(void)
{
    pthread_once(&g_mutex_once, make_mutex);
    pthread_mutex_lock(&g_mutex);
}

void vh_platform_unlock(void)
{
    pthread_mutex_unlock(&g_mutex);
}

int vh_platform_init(unsigned int pool_size)
{
    (void)pool_size;
    return 0;
}

void vh_platform_term(void)
{
}

void *vh_platform_alloc(size_t size)
{
    return malloc(size);
}

void vh_platform_free(void *pointer)
{
    free(pointer);
}

int vh_platform_ca_path(char *path, size_t capacity)
{
    if (vh_test_ca_path == NULL || strlen(vh_test_ca_path) >= capacity)
        return -1;
    strcpy(path, vh_test_ca_path);
    return 0;
}

int vh_platform_tls_init(void)
{
    return 0;
}

unsigned long long vh_platform_clock_us(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (unsigned long long)now.tv_sec * 1000000u + (unsigned long long)now.tv_nsec / 1000u;
}

typedef struct VhThreadStart
{
    void (*function)(void *);
    void *argument;
} VhThreadStart;

static void *thread_entry(void *data)
{
    VhThreadStart start = *(VhThreadStart *)data;
    free(data);
    start.function(start.argument);
    return NULL;
}

int vh_platform_thread(void (*function)(void *), void *argument)
{
    pthread_t thread;
    VhThreadStart *start = malloc(sizeof(*start));
    if (start == NULL)
        return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
    start->function = function;
    start->argument = argument;
    if (pthread_create(&thread, NULL, thread_entry, start) != 0) {
        free(start);
        return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
    }
    pthread_detach(thread);
    return 0;
}

static pthread_mutex_t g_wait_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_wait_condition = PTHREAD_COND_INITIALIZER;
static unsigned int g_generation;

unsigned int vh_platform_generation(void)
{
    return __atomic_load_n(&g_generation, __ATOMIC_ACQUIRE);
}

void vh_platform_notify(void)
{
    pthread_mutex_lock(&g_wait_mutex);
    __atomic_add_fetch(&g_generation, 1u, __ATOMIC_RELEASE);
    pthread_cond_broadcast(&g_wait_condition);
    pthread_mutex_unlock(&g_wait_mutex);
}

int vh_platform_wait(unsigned int generation, long long timeout_us)
{
    struct timespec until;
    int result = 0;
    clock_gettime(CLOCK_REALTIME, &until);
    if (timeout_us >= 0) {
        long long nanoseconds = until.tv_nsec + (timeout_us % 1000000) * 1000;
        until.tv_sec += (time_t)(timeout_us / 1000000 + nanoseconds / 1000000000);
        until.tv_nsec = (long)(nanoseconds % 1000000000);
    }
    pthread_mutex_lock(&g_wait_mutex);
    while (result == 0 && vh_platform_generation() == generation)
        if ((timeout_us < 0 ? pthread_cond_wait(&g_wait_condition, &g_wait_mutex)
                            : pthread_cond_timedwait(&g_wait_condition, &g_wait_mutex, &until)) == ETIMEDOUT)
            result = (int)SCE_HTTP_ERROR_TIMEOUT;
    pthread_mutex_unlock(&g_wait_mutex);
    return result;
}

long long vh_platform_time(void)
{
    return (long long)time(NULL);
}

struct VhTransport
{
    int socket;
    volatile int aborted;
    int error_number;
    VhTls *tls;
};

VhTransport *vh_transport_create(void)
{
    VhTransport *transport = vh_alloc(sizeof(*transport));
    if (transport != NULL) {
        memset(transport, 0, sizeof(*transport));
        transport->socket = -1;
    }
    return transport;
}

static int network_error(VhTransport *transport, int error)
{
    transport->error_number = error;
    if (transport->aborted)
        return (int)SCE_HTTP_ERROR_ABORTED;
    if (error == EAGAIN || error == EWOULDBLOCK || error == ETIMEDOUT)
        return (int)SCE_HTTP_ERROR_TIMEOUT;
    return (int)SCE_HTTP_ERROR_NETWORK;
}

static void set_timeout(int socket, int option, unsigned int usec)
{
    struct timeval value = {.tv_sec = usec / 1000000u, .tv_usec = (int)(usec % 1000000u)};
    setsockopt(socket, SOL_SOCKET, option, &value, sizeof(value));
}

int vh_transport_connect(VhTransport *transport, const VhOpen *open, int *ssl_error, unsigned int *ssl_detail)
{
    struct addrinfo hints, *found;
    char host[VH_HOST_MAX], port[8];

    *ssl_error = 0;
    *ssl_detail = 0;
    size_t length = strlen(open->host);
    if (length >= 2 && open->host[0] == '[') {
        memcpy(host, open->host + 1, length - 2);
        host[length - 2] = '\0';
    } else
        strcpy(host, open->host);
    snprintf(port, sizeof(port), "%u", (unsigned int)open->port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &found) != 0)
        return (int)SCE_HTTP_ERROR_RESOLVER_ENOHOST;
    int socket_ = socket(found->ai_family, found->ai_socktype, found->ai_protocol);
    if (socket_ < 0) {
        freeaddrinfo(found);
        return network_error(transport, errno);
    }
    transport->socket = socket_;
    fcntl(socket_, F_SETFL, fcntl(socket_, F_GETFL) | O_NONBLOCK);
    int result = connect(socket_, found->ai_addr, found->ai_addrlen);
    freeaddrinfo(found);
    if (result < 0 && errno != EINPROGRESS)
        return network_error(transport, errno);
    if (result < 0) {
        int waited = 0;
        for (;;) {
            struct pollfd poller = {.fd = socket_, .events = POLLOUT};
            if (transport->aborted)
                return (int)SCE_HTTP_ERROR_ABORTED;
            if (open->connect_timeout_us != 0 && (unsigned int)waited * 1000u >= open->connect_timeout_us)
                return (int)SCE_HTTP_ERROR_TIMEOUT;
            if (poll(&poller, 1, VH_CONNECT_SLICE_MS) > 0)
                break;
            waited += VH_CONNECT_SLICE_MS;
        }
        int error = 0;
        socklen_t size = sizeof(error);
        getsockopt(socket_, SOL_SOCKET, SO_ERROR, &error, &size);
        if (error != 0)
            return network_error(transport, error);
    }
    fcntl(socket_, F_SETFL, fcntl(socket_, F_GETFL) & ~O_NONBLOCK);
    set_timeout(socket_, SO_SNDTIMEO, open->send_timeout_us);
    set_timeout(socket_, SO_RCVTIMEO, open->recv_timeout_us);
    int on = 1;
    setsockopt(socket_, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
    setsockopt(socket_, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
    if (open->https)
        return vh_tls_start(&transport->tls, transport, open, ssl_error, ssl_detail);
    return 0;
}

int vh_transport_raw_send(VhTransport *transport, const void *data, size_t size)
{
    for (;;) {
        ssize_t sent = send(transport->socket, data, size, 0);
        if (sent >= 0)
            return transport->aborted ? (int)SCE_HTTP_ERROR_ABORTED : (int)sent;
        if (errno != EINTR || transport->aborted)
            return network_error(transport, errno);
    }
}

int vh_transport_raw_recv(VhTransport *transport, void *data, size_t size)
{
    for (;;) {
        ssize_t received = recv(transport->socket, data, size, 0);
        if (received >= 0)
            return transport->aborted ? (int)SCE_HTTP_ERROR_ABORTED : (int)received;
        if (errno != EINTR || transport->aborted)
            return network_error(transport, errno);
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
    if (transport->socket >= 0)
        shutdown(transport->socket, SHUT_RDWR);
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
        close(transport->socket);
    vh_free(transport);
}

/* The Vita's TLS heap report; the host's heap is the system's */
void vitals_user_runtime_report(const char *tag, int force)
{
    (void)tag;
    (void)force;
}
