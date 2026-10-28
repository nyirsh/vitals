/*
    Original module-redirection code by SKGleba (iTLS-Enso)
    All Rights Reserved
*/

#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/processmgr.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/types.h>
#include <taihen.h>
#include <vitasdkkern.h>

#include <stddef.h>
#include <stdint.h>

#include "vitals/path.h"
#include "tls13_loader.h"
#include "hook_guard.h"
#include "native_module_api.h"
#include "post_start.h"
#include "dns_watch.h"
#include "diag.h"

#define VITALS_MAX_MODULE_PATH ((size_t)0x400)

enum
{
    MODULE_COMPAT,
    MODULE_LIBHTTP,
    MODULE_LIBSSL,
    MODULE_COUNT
};

/* libhttp's is vitals-http, which does its own TLS (tls13-vita's), in every process */
static const char *const g_replacement_modules[MODULE_COUNT] = {
    "vs0:/data/external/vitals/ScePsp2Compat.suprx",
    "vs0:/data/external/vitals/libhttp.suprx",
    "vs0:/data/external/vitals/libssl.suprx",
};

static uint8_t g_replace[MODULE_COUNT];
static uint8_t g_replace_iap;

static int g_loader_hook_id = -1;
static tai_hook_ref_t g_loader_hook_ref;
static int g_start_hook_id = -1;
static tai_hook_ref_t g_start_hook_ref;

static int add_replace_flags(void)
{
    SceIoStat stat;

    for (size_t i = 0; i < MODULE_COUNT; ++i)
        g_replace[i] = ksceIoGetstat(g_replacement_modules[i], &stat) >= 0;
    g_replace_iap = g_replace[MODULE_LIBHTTP] && g_replace[MODULE_LIBSSL];
    return g_replace[MODULE_COMPAT] || g_replace_iap;
}

static int path_is(const char *path, const char *a, const char *b)
{
    return vitals_path_equals(path, a, VITALS_MAX_MODULE_PATH) ||
           (b != NULL && vitals_path_equals(path, b, VITALS_MAX_MODULE_PATH));
}

// load module for pid (0 for the caller), running in kernel context, path is in kernel
static SceUID load_for_pid_patched(SceUID pid, const char *path, uint32_t flags, int *ptr_to_four)
{
    const SceUID target_pid = pid == 0 ? ksceKernelGetProcessId() : pid;
    char browser_path[VITALS_PENDING_BROWSER_PATH_SIZE];
    char browser_provider[VITALS_PENDING_BROWSER_PATH_SIZE];
    int module = -1;
    const char *requested = path;

    if (g_replace_iap && (path_is(path, "vs0:sys/external/libhttp.suprx", "vs0:/sys/external/libhttp.suprx") ||
                          path_is(path, "ur0:data/reAuth/libhttp.suprx", NULL)))
    {
        ksceDebugPrintf("vitals: libhttp load pid=0x%X flags=0x%08X path=%s\n", target_pid, flags, path);
        module = MODULE_LIBHTTP;
        path = g_replacement_modules[module];
        /* Temporary diagnostic: Sony's libhttp for the Store, when its files are there */
        const char *diag = vitals_diag_libhttp(target_pid);
        if (diag != NULL)
            path = diag;
    }
    else if (g_replace_iap && path_is(path, "vs0:sys/external/libssl.suprx", "vs0:/sys/external/libssl.suprx"))
    {
        module = MODULE_LIBSSL;
        path = g_replacement_modules[module];
    }
    else if (g_replace[MODULE_COMPAT] &&
             vitals_browser_replacement_path(path, browser_path, sizeof(browser_path)))
    {
        module = MODULE_COMPAT;
        path = browser_path;
    }

    /* vitals-http needs nothing injected, so libhttp keeps the mapping the loader asked for:
     * shared, as Sony's is, in the shell and everywhere else */
    SceUID res = TAI_CONTINUE(SceUID, g_loader_hook_ref, pid, path, flags, ptr_to_four);
    if (res < 0)
        return res;
    vitals_diag_loaded(target_pid, requested, res);

    /* Injection waits until the native start hook reports that linking finished */
    if (module == MODULE_COMPAT && vitals_kernel_browser_loader_ready() &&
             vitals_browser_provider_path(path, browser_provider, sizeof(browser_provider)))
        (void)vitals_post_start_defer(target_pid, res, browser_provider);
    return res;
}

static int start_for_pid_patched(SceUID pid, SceUID module, SceSize size,
                                 const void *data, uint32_t flags, const void *options, int *status)
{
    const SceUID target_pid = pid == 0 ? ksceKernelGetProcessId() : pid;
    int res = TAI_CONTINUE(int, g_start_hook_ref, pid, module, size, data, flags, options, status);
    (void)vitals_post_start_complete(target_pid, module, res);
    vitals_diag_started(target_pid, module, res);
    return res;
}

/* The Vita loader enters through _start; macOS, where only the host tests build, has no aliases */
#if !defined(__APPLE__)
int _start(SceSize argc, const void *args) __attribute__((weak, alias("module_start")));
#endif
int module_start(SceSize argc, const void *args)
{
    (void)argc;
    (void)args;

    ksceDebugPrintf("vitals module loaded\n");
    if (!add_replace_flags())
        return SCE_KERNEL_START_SUCCESS;

#if defined(__arm__)
    /* Resolve once here, never from a loader-hook callback */
    if (vitals_native_module_api_init() < 0)
        return SCE_KERNEL_START_FAILED;
#endif
    /* The browser provider, injected after vitals' browser engine starts */
    if (g_replace[MODULE_COMPAT])
    {
        int init = vitals_kernel_loader_init();
        ksceDebugPrintf("vitals: loader init=%d browser=%d\n", init, vitals_kernel_browser_loader_ready());
    }

    SceUID modid = ksceKernelSearchModuleByName("SceKernelModulemgr");
    if (modid <= 0 || vitals_validate_loader_hook(modid) < 0 || vitals_post_start_init() < 0)
        goto failed;
    g_start_hook_id = taiHookFunctionOffsetForKernel(KERNEL_PID, &g_start_hook_ref, modid, 0,
                                                     VITALS_MODULEMGR_START_OFFSET, 1, start_for_pid_patched);
    if (g_start_hook_id < 0)
        goto failed;
    g_loader_hook_id = taiHookFunctionOffsetForKernel(KERNEL_PID, &g_loader_hook_ref, modid, 0,
                                                      VITALS_MODULEMGR_LOAD_OFFSET, 1, load_for_pid_patched);
    /* The start hook may already be running on another thread; its code must stay mapped */
    if (g_loader_hook_id < 0)
        ksceDebugPrintf("vitals: loader hook failed: 0x%08X\n", g_loader_hook_id);
    /* The DNS rules (ux0:data/vitals/dns.txt), for every lookup in every process */
    (void)vitals_dns_watch_start();
    return SCE_KERNEL_START_SUCCESS;

failed:
    ksceDebugPrintf("vitals: startup failed before hooking\n");
    (void)vitals_post_start_destroy();
    vitals_kernel_loader_destroy();
    return SCE_KERNEL_START_FAILED;
}

int module_stop(SceSize argc, const void *args)
{
    (void)argc;
    (void)args;

    /* Deferred injections and in-flight hook calls can outlive a release */
    if (g_loader_hook_id >= 0 || g_start_hook_id >= 0)
        return SCE_KERNEL_STOP_FAIL;
    vitals_dns_watch_stop();
    (void)vitals_post_start_destroy();
    vitals_kernel_loader_destroy();
    return SCE_KERNEL_STOP_SUCCESS;
}
