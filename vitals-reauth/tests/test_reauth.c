/* Host test of vitals-reauth: which module it hooks, and that only the old PSN host is rewritten */
#include "../main.c"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define TAI_NOT_FOUND ((int)0x90010002)
#define ORIGINAL_RESULT 0x5150

static int shell_present, store_present, hook_result;
static int hooks, releases, calls;
static char hooked_module[32];
static uint32_t hooked_library, hooked_function;
static const void *hook_function;

/* What Sony's sceHttpCreateConnection received */
static struct {
    int template_id, keep_alive;
    const char *server_name, *scheme;
    unsigned short port;
} seen;

static int original_create_connection(int template_id, const char *server_name, const char *scheme,
                                      unsigned short port, int keep_alive)
{
    ++calls;
    seen.template_id = template_id;
    seen.server_name = server_name;
    seen.scheme = scheme;
    seen.port = port;
    seen.keep_alive = keep_alive;
    return ORIGINAL_RESULT;
}

int taiGetModuleInfo(const char *module, tai_module_info_t *info)
{
    assert(info->size == sizeof(*info));
    if (strcmp(module, "SceShell") == 0)
        return shell_present ? 0 : TAI_NOT_FOUND;
    assert(strcmp(module, "SceNpCommerce2") == 0);
    return store_present ? 0 : TAI_NOT_FOUND;
}

SceUID taiHookFunctionImport(tai_hook_ref_t *reference, const char *module, uint32_t library_nid,
                             uint32_t function_nid, const void *function)
{
    ++hooks;
    snprintf(hooked_module, sizeof(hooked_module), "%s", module);
    hooked_library = library_nid;
    hooked_function = function_nid;
    hook_function = function;
    *reference = (tai_hook_ref_t)original_create_connection;
    return hook_result;
}

int taiHookRelease(SceUID hook_id, tai_hook_ref_t reference)
{
    assert(hook_id == hook_result && hook_id >= 0);
    assert(reference == (tai_hook_ref_t)original_create_connection);
    ++releases;
    return 0;
}

static int start(int shell, int store, int result)
{
    shell_present = shell;
    store_present = store;
    hook_result = result;
    hooks = releases = 0;
    hooked_module[0] = '\0';
    return module_start(0, NULL);
}

/* Calls the installed hook as libhttp's callers would */
static int call_hook(const char *server_name)
{
    typedef int (*CreateConnection)(int, const char *, const char *, unsigned short, int);
    memset(&seen, 0, sizeof(seen));
    calls = 0;
    int result = ((CreateConnection)hook_function)(7, server_name, "https", 443, 1);
    assert(calls == 1 && result == ORIGINAL_RESULT);
    assert(seen.template_id == 7 && strcmp(seen.scheme, "https") == 0 && seen.port == 443 && seen.keep_alive == 1);
    return result;
}

int main(void)
{
    /* Neither module present: nothing is hooked and the module unloads itself */
    assert(start(0, 0, 33) == SCE_KERNEL_START_NO_RESIDENT && hooks == 0);
    assert(module_stop(0, NULL) == SCE_KERNEL_STOP_SUCCESS && releases == 0);

    /* The shell is hooked when present, even if the Store library is loaded too */
    assert(start(1, 1, 33) == SCE_KERNEL_START_SUCCESS && hooks == 1);
    assert(strcmp(hooked_module, "SceShell") == 0);
    assert(hooked_library == 0xE8F15CDE && hooked_function == 0xAEB3307E);
    assert(module_stop(0, NULL) == SCE_KERNEL_STOP_SUCCESS && releases == 1);
    assert(module_stop(0, NULL) == SCE_KERNEL_STOP_SUCCESS && releases == 1);

    /* In an app, the Store library is hooked */
    assert(start(0, 1, 34) == SCE_KERNEL_START_SUCCESS && hooks == 1);
    assert(strcmp(hooked_module, "SceNpCommerce2") == 0);

    /* Only the exact old host goes to the new one; everything else reaches Sony unchanged */
    call_hook("native.np.ac.playstation.net");
    assert(strcmp(seen.server_name, "native-vita.np.ac.playstation.net") == 0);
    const char *unchanged[] = {
        "native-vita.np.ac.playstation.net",
        "native.np.ac.playstation.net.example.com",
        "native.np.ac.playstation.ne",
        "native.np.ac.playstation.net ",
        "NATIVE.np.ac.playstation.net",
        "sound.ture.fish",
        "",
    };
    for (unsigned i = 0; i < sizeof(unchanged) / sizeof(unchanged[0]); ++i)
    {
        call_hook(unchanged[i]);
        assert(seen.server_name == unchanged[i]);
    }
    call_hook(NULL);
    assert(seen.server_name == NULL);
    assert(module_stop(0, NULL) == SCE_KERNEL_STOP_SUCCESS && releases == 1);

    /* A failed hook: the module unloads itself and has nothing to release */
    assert(start(1, 0, -12) == SCE_KERNEL_START_NO_RESIDENT && hooks == 1);
    assert(module_stop(0, NULL) == SCE_KERNEL_STOP_SUCCESS && releases == 0);

    puts("vitals-reauth: shell or Store hook, exact old-host redirect, failed hooks and release PASS");
    return 0;
}
