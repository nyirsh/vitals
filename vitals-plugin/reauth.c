#include "reauth.h"

#include <psp2kern/io/stat.h>
#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/sysroot.h>
#include <psp2kern/kernel/threadmgr/misc.h>
#include <psp2kern/kernel/threadmgr/mutex.h>
#include <stdint.h>
#include <taihen.h>

#define VITALS_REAUTH_PATH "vs0:/data/external/vitals/native/vitals-reauth.suprx"
#define VITALS_REAUTH_NAME "vitals_reauth"
#define VITALS_REAUTH_PATH_LIMIT 0x400u
#define TAI_MODULE_NOT_FOUND ((int)UINT32_C(0x90010002))

static int g_ready;
static SceUID g_mutex = -1;

int vitals_reauth_init(void)
{
    SceIoStat status;
    if (g_mutex >= 0)
        return g_ready;
    if (ksceIoGetstat(VITALS_REAUTH_PATH, &status) < 0)
        return 0;
    g_mutex = ksceKernelCreateMutex("vitals reauth", 0, 0, NULL);
    g_ready = g_mutex >= 0;
    return g_ready;
}

void vitals_reauth_destroy(void)
{
    g_ready = 0;
    if (g_mutex >= 0)
        (void)ksceKernelDeleteMutex(g_mutex);
    g_mutex = -1;
}

/* The Store library's file name contains "commerce2"; the injected module itself checks that
 * SceNpCommerce2 really is loaded, so a loose match never hooks anything else */
static int is_store_library(const char *path)
{
    static const char needle[] = "commerce2";
    if (strncmp(path, "vs0:", 4) != 0)
        return 0;
    for (size_t i = 0; i < VITALS_REAUTH_PATH_LIMIT && path[i] != '\0'; ++i)
    {
        size_t n = 0;
        while (n < sizeof(needle) - 1 && path[i + n] != '\0' &&
               (path[i + n] | 0x20) == needle[n])
            ++n;
        if (n == sizeof(needle) - 1)
            return 1;
    }
    return 0;
}

int vitals_reauth_wanted(SceUID pid, const char *path, int is_libhttp)
{
    if (!g_ready || pid <= 0 || path == NULL)
        return 0;
    if (is_libhttp)
        return pid == ksceKernelSysrootGetShellPid();
    return is_store_library(path) && pid != ksceKernelSysrootGetShellPid();
}

typedef struct ReauthCall
{
    SceUID pid;
    int result;
} ReauthCall;

static int lookup(SceUID pid, const char *name, tai_module_info_t *info)
{
    memset(info, 0, sizeof(*info));
    info->size = sizeof(*info);
    return taiGetModuleInfoForKernel(pid, name, info);
}

static int inject_on_stack(void *opaque)
{
    ReauthCall *call = opaque;
    tai_module_info_t info;
    int status = 0;

    /* The process must hold the module the redirect hooks */
    const char *target = call->pid == ksceKernelSysrootGetShellPid() ? "SceShell" : "SceNpCommerce2";
    if (lookup(call->pid, target, &info) != 0)
    {
        call->result = 0;
        return 0;
    }
    /* Once per process: hooking the same import twice is never needed */
    int found = lookup(call->pid, VITALS_REAUTH_NAME, &info);
    if (found != TAI_MODULE_NOT_FOUND)
    {
        call->result = found == 0 ? 0 : found;
        return 0;
    }
    SceUID modid = ksceKernelLoadStartModuleForPid(call->pid, VITALS_REAUTH_PATH, 0, NULL, 0, NULL, &status);
    call->result = modid < 0 ? modid : 0;
    ksceDebugPrintf("vitals: reauth pid=0x%X target=%s mod=0x%08X status=%d\n",
                    call->pid, target, modid, status);
    return 0;
}

int vitals_reauth_inject(SceUID pid)
{
    ReauthCall call = {pid, -1};
    if (!g_ready || pid <= 0)
        return -1;
    int result = ksceKernelLockMutex(g_mutex, 1, NULL);
    if (result < 0)
        return result;
    /* Module loading must not run on the nested native loader's kernel stack */
    result = ksceKernelRunWithStack(16384, inject_on_stack, &call);
    (void)ksceKernelUnlockMutex(g_mutex, 1);
    return result < 0 ? result : call.result;
}
