#include "vs.h"

#include "diagnostics.h"
#include "user_runtime.h"

#include <string.h>

#include <psp2/kernel/clib.h>
#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/net/net.h>

/* The console's side of vitals-ssl: module start and stop, the lock, the pool, SceNet and the
 * handshake's thread */

#define VS_LW_MUTEX_RECURSIVE 0x02u
/* A TLS 1.3 handshake with elliptic curves takes more stack than some apps' network threads
 * have, as with vitals-http */
#define VS_HANDSHAKE_STACK 0x10000
#define VS_HANDSHAKE_PRIORITY 0x10000100

/* vitals-ssl's paths, as the app sees them (vs0: through _sceAppMgrConvertVs0UserDrivePath) */
int _sceAppMgrConvertVs0UserDrivePath(const char *path, char *converted_path, SceSize capacity,
                                      const void *options);

static SceKernelLwMutexWork g_mutex;

/* As Sony's libssl, which says it was built with SDK 3.73; vita-elf-create exports this symbol as
 * the module's SDK version */
const unsigned int module_sdk_version __attribute__((used)) = 0x03730011;

int module_start(SceSize args, void *argp)
{
    (void)args, (void)argp;
    if (sceKernelCreateLwMutex(&g_mutex, "vs_lock", VS_LW_MUTEX_RECURSIVE, 0, NULL) < 0)
        return SCE_KERNEL_START_FAILED;
    return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize args, void *argp)
{
    (void)args, (void)argp;
    if (vs_initialized())
        (void)sceSslTerm();
    sceKernelDeleteLwMutex(&g_mutex);
    return SCE_KERNEL_STOP_SUCCESS;
}

int _start(SceSize args, void *argp) __attribute__((weak, alias("module_start")));

void vs_lock(void)
{
    sceKernelLockLwMutex(&g_mutex, 1, NULL);
}

void vs_unlock(void)
{
    sceKernelUnlockLwMutex(&g_mutex, 1);
}

/* As Sony's, under the name Sony's gives it: the kernel's error when the block can't be had (a
 * size that isn't a multiple of 4 KiB, or more than the process has left) */
int vs_platform_heap_create(unsigned int size)
{
    int result = vitals_user_runtime_init_size("SceLibsslGlobalHeap", size);
    return result == -1 ? (int)VS_ERROR_OUT_OF_MEMORY : result;
}

void vs_platform_heap_destroy(void)
{
    int result = vitals_user_runtime_destroy();
    if (result != 0)
        VITALS_LOG("pool not freed rc=%08X: something still uses it", (unsigned int)result);
}

void vs_platform_heap_stats(unsigned int *capacity, unsigned int *peak, unsigned int *used)
{
    VitalsRuntimeStats stats = {0};
    (void)vitals_user_runtime_stats(&stats);
    *capacity = stats.capacity;
    *peak = stats.peak;
    *used = stats.used;
}

void vs_platform_clear_net_errno(void)
{
    *sceNetErrnoLoc() = 0;
}

int vs_platform_socket_close(int fd)
{
    return sceNetSocketClose(fd);
}

int vs_platform_parse_ipv4(const char *host, unsigned char address[4])
{
    return sceNetInetPton(SCE_NET_AF_INET, host, address) > 0;
}

typedef struct VsThreadStart {
    void (*function)(void *);
    void *argument;
} VsThreadStart;

/* The start copies its arguments onto the thread's stack */
static int thread_entry(SceSize size, void *data)
{
    (void)size;
    const VsThreadStart *start = data;
    start->function(start->argument);
    return sceKernelExitThread(0);
}

void vs_platform_run_on_large_stack(void (*function)(void *), void *argument)
{
    VsThreadStart start = {function, argument};
    SceUID thread = sceKernelCreateThread("vs_handshake", thread_entry, VS_HANDSHAKE_PRIORITY,
                                          VS_HANDSHAKE_STACK, 0, 0, NULL);
    if (thread >= 0 && sceKernelStartThread(thread, sizeof(start), &start) >= 0) {
        sceKernelWaitThreadEnd(thread, NULL, NULL);
        sceKernelDeleteThread(thread);
        return;
    }
    if (thread >= 0)
        sceKernelDeleteThread(thread);
    VITALS_LOG("handshake thread not started: on the caller's");
    function(argument);
}

unsigned int vs_platform_thread_id(void)
{
    return (unsigned int)sceKernelGetThreadId();
}

int vs_platform_ca_path(char *path, size_t size)
{
    const uint32_t options[4] = {0};
    if (size < 0x124u)
        return -1;
    memset(path, 0, size);
    if (_sceAppMgrConvertVs0UserDrivePath(VITALS_SSL_CA_PATH, path, 0x124u, options) < 0 ||
        memchr(path, '\0', 0x124u) == NULL || path[0] == '\0')
        return -1;
    return 0;
}
