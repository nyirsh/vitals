/*
    Based on reAuth by Reiko Asakura (https://github.com/psv-plugins-archive/reAuth)
*/

#include <psp2/kernel/modulemgr.h>
#include <taihen.h>

#if VITALS_DEBUG >= 1
#include <psp2/kernel/clib.h>
#define REAUTH_LOG(format, ...) sceClibPrintf("vitals_reauth: " format "\n", ##__VA_ARGS__)
#else
#define REAUTH_LOG(format, ...) ((void)0)
#endif

/* PSN sign-in moved to a new host; old firmware still asks for the old one
 * The kernel plugin loads this module into the shell after it loads its HTTP library, and into
 * apps after they load the Store library (SceNpCommerce2)
 * It rewrites that one hostname in that module's sceHttpCreateConnection calls and changes
 * nothing else */
#define OLD_HOST "native.np.ac.playstation.net"
#define NEW_HOST "native-vita.np.ac.playstation.net"

#define SCE_HTTP_LIBRARY_NID 0xE8F15CDE
#define SCE_HTTP_CREATE_CONNECTION_NID 0xAEB3307E

static SceUID g_hook_id = -1;
static tai_hook_ref_t g_hook_ref;

static int is_old_host(const char *name)
{
    static const char old_host[] = OLD_HOST;
    if (name == 0)
        return 0;
    for (unsigned i = 0; i < sizeof(old_host); ++i)
    {
        if (name[i] != old_host[i])
            return 0;
    }
    return 1;
}

static int create_connection_hook(int template_id, const char *server_name, const char *scheme,
                                  unsigned short port, int keep_alive)
{
    if (is_old_host(server_name))
    {
        server_name = NEW_HOST;
        REAUTH_LOG("redirected " OLD_HOST " to " NEW_HOST);
    }
    return TAI_CONTINUE(int, g_hook_ref, template_id, server_name, scheme, port, keep_alive);
}

/* The Vita loader enters through _start; macOS, where only the host tests build, has no aliases */
#if !defined(__APPLE__)
int _start(SceSize argc, const void *args) __attribute__((weak, alias("module_start")));
#endif
int module_start(SceSize argc, const void *args)
{
    (void)argc;
    (void)args;
    /* The shell signs in to PSN; apps reach the Store through SceNpCommerce2 */
    static const char *const targets[] = {"SceShell", "SceNpCommerce2"};
    for (unsigned i = 0; i < sizeof(targets) / sizeof(targets[0]); ++i)
    {
        tai_module_info_t info;
        info.size = sizeof(info);
        if (taiGetModuleInfo(targets[i], &info) < 0)
            continue;
        g_hook_id = taiHookFunctionImport(&g_hook_ref, targets[i], SCE_HTTP_LIBRARY_NID,
                                          SCE_HTTP_CREATE_CONNECTION_NID, create_connection_hook);
        REAUTH_LOG("hook %s rc=0x%08X", targets[i], (unsigned)g_hook_id);
        /* Without its hook the module has nothing to do, so it unloads itself */
        return g_hook_id >= 0 ? SCE_KERNEL_START_SUCCESS : SCE_KERNEL_START_NO_RESIDENT;
    }
    return SCE_KERNEL_START_NO_RESIDENT;
}

int module_stop(SceSize argc, const void *args)
{
    (void)argc;
    (void)args;
    if (g_hook_id >= 0)
        taiHookRelease(g_hook_id, g_hook_ref);
    g_hook_id = -1;
    return SCE_KERNEL_STOP_SUCCESS;
}
