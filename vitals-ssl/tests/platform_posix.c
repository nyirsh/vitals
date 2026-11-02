#include "vs.h"

#include <arpa/inet.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* vitals-ssl's platform on a host, for the tests: the pool only counts (Mbed TLS uses the system's
 * allocator here), sockets are the system's, the handshake runs on the caller's thread */

static pthread_mutex_t g_mutex;
static pthread_once_t g_once = PTHREAD_ONCE_INIT;
static unsigned int g_capacity;
/* Where the CA bundle is: set by the tests */
char vs_test_ca_path[512];
/* A pool size the tests want refused, with the error a kernel gives */
unsigned int vs_test_refused_pool;

static void make_mutex(void)
{
    pthread_mutexattr_t attributes;
    pthread_mutexattr_init(&attributes);
    pthread_mutexattr_settype(&attributes, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&g_mutex, &attributes);
    pthread_mutexattr_destroy(&attributes);
}

/* The debug log, on stderr when VS_TEST_LOG is set */
int sceClibPrintf(const char *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    int result = getenv("VS_TEST_LOG") != NULL ? vfprintf(stderr, format, arguments) : 0;
    va_end(arguments);
    return result;
}

void vs_lock(void)
{
    pthread_once(&g_once, make_mutex);
    pthread_mutex_lock(&g_mutex);
}

void vs_unlock(void)
{
    pthread_mutex_unlock(&g_mutex);
}

int vs_platform_heap_create(unsigned int size)
{
    if (size == vs_test_refused_pool)
        return (int)0x80020000u + 0x2001; /* any kernel error */
    g_capacity = size;
    return 0;
}

void vs_platform_heap_destroy(void)
{
    g_capacity = 0;
}

void vs_platform_heap_stats(unsigned int *capacity, unsigned int *peak, unsigned int *used)
{
    *capacity = g_capacity;
    *peak = 0;
    *used = 0;
}

unsigned int vs_platform_thread_id(void)
{
    return (unsigned int)(uintptr_t)pthread_self();
}

void vs_platform_clear_net_errno(void)
{
}

int vs_platform_socket_close(int fd)
{
    return close(fd);
}

int vs_platform_parse_ipv4(const char *host, unsigned char address[4])
{
    return inet_pton(AF_INET, host, address) == 1;
}

void vs_platform_run_on_large_stack(void (*function)(void *), void *argument)
{
    function(argument);
}

int vs_platform_ca_path(char *path, size_t size)
{
    if (vs_test_ca_path[0] == '\0' || strlen(vs_test_ca_path) >= size)
        return -1;
    strcpy(path, vs_test_ca_path);
    return 0;
}
