#include "vh.h"

#include "diagnostics.h"
#include "vs.h"

/* The host tests build vitals-ssl into vitals-http, as a host can't import the libssl module:
 * its platform is the tests' vitals-http platform. Its lock is vitals-http's (recursive), its pool
 * only counted (the system's allocator serves), its handshake thread one of vitals-http's, and
 * its connections run over vitals-http's transport (vitalsSslBioNew) or the tests' sockets */

void vs_lock(void)
{
    vh_lock();
}

void vs_unlock(void)
{
    vh_unlock();
}

int vs_platform_heap_create(unsigned int size)
{
    (void)size;
    return 0;
}

void vs_platform_heap_destroy(void)
{
}

void vs_platform_heap_stats(unsigned int *capacity, unsigned int *peak, unsigned int *used)
{
    *capacity = *peak = *used = 0;
}

void vs_platform_clear_net_errno(void)
{
}

int vs_platform_socket_close(int fd)
{
    (void)fd;
    return 0;
}

/* Four decimal numbers up to 255, dot-separated, nothing else, as sceNetInetPton takes them */
int vs_platform_parse_ipv4(const char *host, unsigned char address[4])
{
    for (int part = 0; part < 4; ++part) {
        unsigned int value = 0, digits = 0;
        while (*host >= '0' && *host <= '9' && digits < 4) {
            value = value * 10u + (unsigned int)(*host++ - '0');
            ++digits;
        }
        if (digits == 0 || digits > 3 || value > 255)
            return 0;
        address[part] = (unsigned char)value;
        if (part < 3 && *host++ != '.')
            return 0;
    }
    return *host == '\0';
}

typedef struct VhSslRun {
    void (*function)(void *);
    void *argument;
    int done;
} VhSslRun;

static void run_thread(void *context)
{
    VhSslRun *run = context;
    run->function(run->argument);
    /* The caller's frame holds run: once done is seen, it may be gone */
    vh_lock();
    run->done = 1;
    vh_platform_notify();
    vh_unlock();
}

/* As vitals-http's handshakes ran: on a thread of its own, with a known stack, as an app may call
 * from a thread whose stack is too small for one */
void vs_platform_run_on_large_stack(void (*function)(void *), void *argument)
{
    VhSslRun run = {function, argument, 0};
    if (vh_platform_thread(run_thread, &run) < 0) {
        VITALS_LOG("handshake thread not started: on the caller's");
        function(argument);
        return;
    }
    for (;;) {
        unsigned int generation = vh_platform_generation();
        vh_lock();
        int done = run.done;
        vh_unlock();
        if (done)
            return;
        vh_platform_wait(generation, -1);
    }
}

int vs_platform_ca_path(char *path, size_t size)
{
    return vh_platform_ca_path(path, size);
}

/* Only the CA store's lookups by name use it (Sony's libhttp's verify callback), which vitals-http
 * doesn't make */
unsigned int vs_platform_thread_id(void)
{
    return 0;
}
