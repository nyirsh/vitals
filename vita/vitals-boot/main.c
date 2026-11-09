/*
    Original module-redirection code by SKGleba (iTLS-Enso)
    All Rights Reserved
*/

#define VITALS_LOG_NAME "vitals-boot"
#define VITALS_LOG_KERNEL
#include "vitals/log.h"
#include "log_file.h"
#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/processmgr.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/sysroot.h>
#include <psp2kern/types.h>
#include <taihen.h>
#include <vitasdkkern.h>

#include <stddef.h>
#include <stdint.h>

#include "vitals/path.h"
#include "vitals/switches.h"
#include "tls13_loader.h"
#include "hook_guard.h"
#include "native_module_api.h"
#include "post_start.h"
#include "dns_watch.h"

#define VITALS_MAX_MODULE_PATH ((size_t)0x400)

enum
{
    MODULE_COMPAT,
    MODULE_LIBHTTP,
    MODULE_LIBSSL,
    MODULE_COUNT
};

/* libhttp's is vitals-http, which does its own TLS (vitals-ssl's), in every process */
static const char *const g_replacement_modules[MODULE_COUNT] = {
    VITALS_COMPAT_PATH,
    VITALS_LIBHTTP_PATH,
    VITALS_LIBSSL_PATH,
};


static int g_loader_hook_id = -1;
static tai_hook_ref_t g_loader_hook_ref;
static int g_start_hook_id = -1;
static tai_hook_ref_t g_start_hook_ref;

static int module_present(unsigned module)
{
    SceIoStat stat;
    return ksceIoGetstat(g_replacement_modules[module], &stat) >= 0;
}

/* An Options switch (vitals/switches.h): 1 while its .off is there */
static int switched_off(const char *flag)
{
    SceIoStat stat;
    return ksceIoGetstat(flag, &stat) >= 0;
}

/* vitals' libhttp and libssl, installed together and looked for at each load rather than once at
 * boot: they're on ux0, which a plugin loaded after this one may still be mapping when it starts (an
 * SD2Vita's), and while they aren't there Sony's load. The switches, looked for at the same time,
 * each keep one of Sony's: tls.off libssl (vitals-http then does its TLS on Sony's, as Sony's libhttp
 * does), http.off libhttp (on vitals-ssl, which has all Sony's libhttp uses) */
static int installed(void)
{
    return module_present(MODULE_LIBHTTP) && module_present(MODULE_LIBSSL);
}

static int replace_libssl(void)
{
    return installed() && !switched_off(VITALS_TLS_OFF);
}

static int replace_libhttp(void)
{
    return installed() && !switched_off(VITALS_HTTP_OFF);
}

static int path_is(const char *path, const char *a, const char *b)
{
    return vitals_path_equals(path, a, VITALS_MAX_MODULE_PATH) ||
           (b != NULL && vitals_path_equals(path, b, VITALS_MAX_MODULE_PATH));
}

/* vitals' engine, when the process's own load of it failed: the browser's process sees its files
 * through a view of its own, without ux0 (0x80010013, no such device), so the kernel loads it with its
 * own call, as it loads the provider into that same process (private, as the browser starts it so on
 * the console; naming the process to the hooked load instead fails the same way). Its module ID, or
 * the error */
static SceUID load_engine_for_process(SceUID target_pid, const char *path, SceUID failed)
{
    VITALS_LOG_ALWAYS("browser engine: the process's load failed (0x%08X)", failed);
    SceUID res = ksceKernelLoadModuleForPid(target_pid, path, 0, NULL);
    VITALS_LOG_ALWAYS("browser engine: kernel load for pid=0x%X: 0x%08X", target_pid, res);
    return res;
}

// load module for pid (0 for the caller), running in kernel context, path is in kernel
static SceUID load_for_pid_patched(SceUID pid, const char *path, uint32_t flags, int *ptr_to_four)
{
    const SceUID target_pid = pid == 0 ? ksceKernelGetProcessId() : pid;
    const char *requested = path;
    int module = -1;

    if ((path_is(path, "vs0:sys/external/libhttp.suprx", "vs0:/sys/external/libhttp.suprx") ||
         path_is(path, "ur0:data/reAuth/libhttp.suprx", NULL)) &&
        replace_libhttp())
    {
        VITALS_LOG_ALWAYS("libhttp load pid=0x%X flags=0x%08X path=%s", target_pid, flags, path);
        module = MODULE_LIBHTTP;
        path = g_replacement_modules[module];
    }
    else if (path_is(path, "vs0:sys/external/libssl.suprx", "vs0:/sys/external/libssl.suprx") && replace_libssl())
    {
        VITALS_LOG_ALWAYS("libssl load pid=0x%X flags=0x%08X", target_pid, flags);
        module = MODULE_LIBSSL;
        path = g_replacement_modules[module];
    }
    /* The browser engine: from ux0:data/vitals/system too, looked for at each load as libhttp is; its
     * TLS is vitals-ssl's, so tls.off keeps Sony's engine and its own TLS */
    else if (vitals_browser_engine_request(path) && module_present(MODULE_COMPAT) && !switched_off(VITALS_TLS_OFF))
    {
        module = MODULE_COMPAT;
        path = g_replacement_modules[module];
    }

    /* vitals-http needs nothing injected, so libhttp keeps the mapping the loader asked for:
     * shared, as Sony's is, in the shell and everywhere else */
    SceUID res = TAI_CONTINUE(SceUID, g_loader_hook_ref, pid, path, flags, ptr_to_four);
    if (res < 0 && module == MODULE_COMPAT)
        res = load_engine_for_process(target_pid, path, res);
    if (res < 0 && module == MODULE_COMPAT)
    {
        /* vitals' engine didn't load for this process: Sony's, so the browser still opens, without
         * vitals' TLS (nothing is injected into it) */
        VITALS_LOG_ALWAYS("browser engine from %s failed (0x%08X), Sony's instead: %s", path, res, requested);
        module = -1;
        res = TAI_CONTINUE(SceUID, g_loader_hook_ref, pid, requested, flags, ptr_to_four);
    }
    if (res < 0)
        return res;

    /* Injection waits until the native start hook reports that linking finished */
    if (module == MODULE_COMPAT && vitals_kernel_browser_loader_ready())
        (void)vitals_post_start_defer(target_pid, res, VITALS_BROWSER_PROVIDER_BOOT_PATH);
    return res;
}

static int start_for_pid_patched(SceUID pid, SceUID module, SceSize size,
                                 const void *data, uint32_t flags, const void *options, int *status)
{
    const SceUID target_pid = pid == 0 ? ksceKernelGetProcessId() : pid;
    int res = TAI_CONTINUE(int, g_start_hook_ref, pid, module, size, data, flags, options, status);
    (void)vitals_post_start_complete(target_pid, module, res);
    return res;
}

/* The flags the system's own loads of libhttp and libssl into an app come with (sceSysmodule's):
 * shared, as Sony's libraries are */
#define VITALS_SYSTEM_MODULE_LOAD_FLAGS UINT32_C(0x08008001)

/* libssl for the browser engine's process, loaded as the system loads it for an app: through the
 * path swap above, and shared, since the shared libhttp there imports from it and a private module
 * can't export to a shared one. Loaded and started through the module manager's own functions,
 * which these hooks already call (ksceKernelStartModuleForPid's import isn't the same on every
 * firmware). Its module ID, or the loader's error; *started and *status are the start's */
SceUID vitals_kernel_load_system_libssl(SceUID pid, int *started, int *status)
{
    int four = 4;
    *started = -1;
    *status = SCE_KERNEL_START_FAILED;
    SceUID modid = load_for_pid_patched(pid, "vs0:sys/external/libssl.suprx", VITALS_SYSTEM_MODULE_LOAD_FLAGS, &four);
    if (modid > 0)
        *started = start_for_pid_patched(pid, modid, 0, NULL, 0, NULL, status);
    return modid;
}

/* The Vita loader enters through _start; macOS, where only the host tests build, has no aliases */
#if !defined(__APPLE__)
int _start(SceSize argc, const void *args) __attribute__((weak, alias("module_start")));
#endif
int module_start(SceSize argc, const void *args)
{
    (void)argc;
    (void)args;

    /* First, as every line from here on goes through it */
    vitals_log_file_start();
    VITALS_LOG_ALWAYS("module loaded");
    /* The hooks go in whatever is there now: vitals' modules are looked for at each load */

#if defined(__arm__)
    /* Resolve once here, never from a loader-hook callback */
    if (vitals_native_module_api_init() < 0)
        return SCE_KERNEL_START_FAILED;
#endif
    /* The browser provider, injected after vitals' browser engine starts; ready once it and the
     * engine are found, now or at an engine load */
    int init = vitals_kernel_loader_init();
    VITALS_LOG_ALWAYS("loader init=%d browser=%d", init, vitals_kernel_browser_loader_ready());

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
        VITALS_LOG_ALWAYS("loader hook failed: 0x%08X", g_loader_hook_id);
    /* The DNS rules (ux0:data/vitals/dns.txt), for every lookup in every process */
    (void)vitals_dns_watch_start();
    return SCE_KERNEL_START_SUCCESS;

failed:
    VITALS_LOG_ALWAYS("startup failed before hooking");
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
    vitals_log_file_stop();
    return SCE_KERNEL_STOP_SUCCESS;
}
