#include <kernel_mock.h>
#include <taihen.h>
#include <assert.h>
#include <stdio.h>

#define _start vitals_test_kernel_entry
#include "../main.c"
#undef _start

typedef int (*TestStartFunction)(SceUID, SceUID, SceSize, const void *, uint32_t, const void *, int *);
typedef SceUID (*TestLoadFunction)(SceUID, const char *, uint32_t, int *);

static SceUID current_pid, seen_pid, injected_pid;
static SceUID load_result;
static int injections, native_starts;
static uint32_t seen_flags;
static int *seen_options;
static char selected_path[256], provider_path[256];
static int stat_result;
static int loader_initializations, loader_destructions;
static int hook_validation_result, hook_installations;
static int start_install_error, load_install_error;
static int http_process_allowed = 1;
static int mutex_live, mutex_locked;
static int reauth_wanted, reauth_injections, reauth_is_libhttp;
static SceUID reauth_pid;
static char reauth_path[256];
static TestStartFunction installed_start;
static TestLoadFunction installed_load;

SceUID ksceKernelGetProcessId(void) { return current_pid; }
int ksceDebugPrintf(const char *format, ...) { (void)format; return 0; }
int ksceIoGetstat(const char *path, SceIoStat *status) { (void)path; (void)status; return stat_result; }
SceUID ksceKernelSearchModuleByName(const char *name) {
    assert(strcmp(name, "SceKernelModulemgr") == 0);
    return 11;
}
int vitals_validate_loader_hook(SceUID module) {
    assert(module == 11 && hook_installations == 0);
    return hook_validation_result;
}
int vitals_kernel_loader_init(void) { ++loader_initializations; return 0; }
void vitals_kernel_loader_destroy(void) { ++loader_destructions; }
int vitals_kernel_loader_ready(void) { return 1; }
int vitals_kernel_http_process_allowed(SceUID pid) { return pid > 0 && http_process_allowed; }
int vitals_kernel_browser_loader_ready(void) { return 1; }
int vitals_kernel_inject_for_pid(SceUID pid, SceUID module) {
    /* Injection only follows a completed native start */
    assert(module == 88 && native_starts > 0 && !mutex_locked);
    injected_pid = pid;
    ++injections;
    return 0;
}
int vitals_reauth_init(void) { return 1; }
void vitals_reauth_destroy(void) {}
int vitals_reauth_wanted(SceUID pid, const char *path, int is_libhttp) {
    reauth_pid = pid;
    reauth_is_libhttp = is_libhttp;
    strcpy(reauth_path, path);
    return reauth_wanted;
}
int vitals_reauth_inject(SceUID pid) {
    /* Like the providers, the reAuth injection follows a completed native start */
    assert(native_starts > 0 && !mutex_locked && pid == reauth_pid);
    ++reauth_injections;
    return 0;
}
int vitals_kernel_inject_browser_for_pid(SceUID pid, SceUID module, const char *path) {
    strcpy(provider_path, path);
    return vitals_kernel_inject_for_pid(pid, module);
}
SceUID ksceKernelCreateMutex(const char *name, unsigned int attr, int count, const void *options) {
    assert(name != NULL && attr == 0 && count == 0 && options == NULL && !mutex_live);
    assert(hook_installations == 0);
    mutex_live = 1;
    return 41;
}
int ksceKernelDeleteMutex(SceUID id) {
    assert(id == 41 && mutex_live && !mutex_locked);
    mutex_live = 0;
    return 0;
}
int ksceKernelLockMutex(SceUID id, int count, unsigned int *timeout) {
    assert(id == 41 && mutex_live && !mutex_locked && count == 1 && timeout == NULL);
    mutex_locked = 1;
    return 0;
}
int ksceKernelUnlockMutex(SceUID id, int count) {
    assert(id == 41 && mutex_locked && count == 1);
    mutex_locked = 0;
    return 0;
}

static SceUID original_load(SceUID pid, const char *path, uint32_t flags, int *options) {
    seen_pid = pid;
    seen_flags = flags;
    seen_options = options;
    strcpy(selected_path, path);
    return load_result;
}
static int original_start(SceUID pid, SceUID module, SceSize size, const void *data,
    uint32_t flags, const void *options, int *status) {
    assert(size == 3 && data == (void *)(uintptr_t)0x12340000 && flags == 0x8001);
    assert(options == NULL && status != NULL && !mutex_locked);
    (void)pid; (void)module;
    ++native_starts;
    *status = 19;
    return 0;
}
int taiHookFunctionOffsetForKernel(SceUID pid, tai_hook_ref_t *reference, SceUID module,
    int segment, size_t offset, int thumb, const void *function) {
    assert(pid == KERNEL_PID && module == 11 && segment == 0 && thumb == 1);
    ++hook_installations;
    if (offset == VITALS_MODULEMGR_START_OFFSET) {
        /* The start hook must exist before any load can defer an injection */
        assert(hook_installations == 1);
        if (start_install_error) return -71;
        installed_start = (TestStartFunction)function;
        *reference = (tai_hook_ref_t)original_start;
        return 31;
    }
    assert(offset == VITALS_MODULEMGR_LOAD_OFFSET && installed_start != NULL);
    if (load_install_error) return -72;
    installed_load = (TestLoadFunction)function;
    *reference = (tai_hook_ref_t)original_load;
    return 32;
}

static void reset_startup(void) {
    g_loader_hook_id = g_start_hook_id = -1;
    installed_start = NULL;
    installed_load = NULL;
    hook_installations = loader_initializations = loader_destructions = 0;
    hook_validation_result = start_install_error = load_install_error = 0;
    stat_result = 0;
}
static void reset(void) {
    current_pid = 99;
    seen_pid = injected_pid = -1;
    seen_flags = 0;
    injections = native_starts = 0;
    load_result = 88;
    http_process_allowed = 1;
    selected_path[0] = provider_path[0] = '\0';
    reauth_wanted = reauth_injections = reauth_is_libhttp = 0;
    reauth_pid = -1;
    reauth_path[0] = '\0';
}
static int finish_start(SceUID pid) {
    int status = -999;
    int result = installed_start(pid, 88, 3, (void *)(uintptr_t)0x12340000, 0x8001, NULL, &status);
    assert(status == 19);
    return result;
}

static void test_startup_failures(void) {
    reset_startup();
    stat_result = -1;
    assert(module_start(0, NULL) == SCE_KERNEL_START_SUCCESS);
    assert(hook_installations == 0 && loader_initializations == 0 && !mutex_live);

    reset_startup();
    hook_validation_result = -1;
    assert(module_start(0, NULL) == SCE_KERNEL_START_FAILED);
    assert(hook_installations == 0 && loader_destructions == 1 && !mutex_live);

    reset_startup();
    start_install_error = 1;
    assert(module_start(0, NULL) == SCE_KERNEL_START_FAILED);
    assert(hook_installations == 1 && loader_destructions == 1 && !mutex_live);

    /* A live start hook keeps the module resident even if the loader hook fails */
    reset_startup();
    load_install_error = 1;
    assert(module_start(0, NULL) == SCE_KERNEL_START_SUCCESS);
    assert(hook_installations == 2 && loader_destructions == 0 && mutex_live);
    assert(module_stop(0, NULL) == SCE_KERNEL_STOP_FAIL);
    g_start_hook_id = -1;
    assert(module_stop(0, NULL) == SCE_KERNEL_STOP_SUCCESS);
    assert(loader_destructions == 1 && !mutex_live);
    puts("kernel startup: no-replacement, validation, start-hook and load-hook failures PASS");
}

static void test_routes(void) {
    int options = 4;
    const char *libhttp_paths[] = {"vs0:sys/external/libhttp.suprx", "vs0:/sys/external/libhttp.suprx",
        "ur0:data/reAuth/libhttp.suprx"};
    for (size_t i = 0; i < sizeof(libhttp_paths) / sizeof(libhttp_paths[0]); ++i) {
        reset();
        assert(installed_load(0, libhttp_paths[i], 0x1000, &options) == 88);
        assert(strcmp(selected_path, g_replacement_modules[MODULE_LIBHTTP]) == 0);
        assert(seen_pid == 0 && seen_flags == 0x1000 && seen_options == &options);
        assert(injections == 0);
        assert(finish_start(0) == 0);
        assert(injections == 1 && injected_pid == 99);
    }
    reset();
    assert(installed_load(123, libhttp_paths[0], 0, NULL) == 88);
    assert(finish_start(123) == 0 && injections == 1 && injected_pid == 123 && seen_pid == 123);
    reset();
    load_result = -5;
    assert(installed_load(0, libhttp_paths[0], 0, NULL) == -5);
    assert(finish_start(0) == 0 && injections == 0);

    reset();
    assert(installed_load(0, "wb0:/webcore/ScePsp2Compat.suprx", 0x8001, &options) == 88);
    assert(strcmp(selected_path, "wb0:/vitals/ScePsp2Compat.suprx") == 0 && seen_flags == 0x8001);
    assert(injections == 0);
    assert(finish_start(0) == 0);
    assert(injections == 1 && injected_pid == 99);
    assert(strcmp(provider_path, "wb0:/vitals/vitals.suprx") == 0);

    reset();
    assert(installed_load(0, "vs0:sys/external/np_commerce2.suprx", 0, NULL) == 88);
    assert(strcmp(selected_path, "vs0:sys/external/np_commerce2.suprx") == 0);
    reset();
    assert(installed_load(0, "vs0:sys/external/libssl.suprx", 0, NULL) == 88);
    assert(strcmp(selected_path, g_replacement_modules[MODULE_LIBSSL]) == 0);

    reset();
    assert(installed_load(0, "ux0:/unrelated.suprx", 0x8001, NULL) == 88);
    assert(strcmp(selected_path, "ux0:/unrelated.suprx") == 0 && seen_flags == 0x8001);
    assert(finish_start(0) == 0 && injections == 0);
    puts("kernel module route: redirection and post-start injection for current and explicit PIDs PASS");
}

static void test_reauth_routes(void) {
    /* The decision sees the path the process asked for, not the replacement */
    reset();
    current_pid = 50;
    reauth_wanted = 1;
    http_process_allowed = 0;
    assert(installed_load(0, "vs0:sys/external/libhttp.suprx", 0, NULL) == 88);
    assert(reauth_pid == 50 && reauth_is_libhttp == 1);
    assert(strcmp(reauth_path, "vs0:sys/external/libhttp.suprx") == 0);
    assert(strcmp(selected_path, g_replacement_modules[MODULE_LIBHTTP]) == 0);
    assert(reauth_injections == 0);
    assert(finish_start(0) == 0 && reauth_injections == 1);

    reset();
    reauth_wanted = 1;
    assert(installed_load(0, "vs0:sys/external/np_commerce2.suprx", 0, NULL) == 88);
    assert(reauth_pid == 99 && reauth_is_libhttp == 0);
    assert(finish_start(0) == 0 && reauth_injections == 1 && injections == 0);

    reset();
    reauth_wanted = 1;
    load_result = -5;
    assert(installed_load(0, "vs0:sys/external/np_commerce2.suprx", 0, NULL) == -5);
    assert(finish_start(0) == 0 && reauth_injections == 0);

    reset();
    assert(installed_load(0, "vs0:sys/external/np_commerce2.suprx", 0, NULL) == 88);
    assert(finish_start(0) == 0 && reauth_injections == 0);
    puts("PSN redirect route: shell libhttp and Store loads queue the redirect after start PASS");
}

static void test_private_flags(void) {
    const char *paths[] = {"vs0:sys/external/libhttp.suprx", "vs0:sys/external/libssl.suprx"};
    for (unsigned i = 0; i < 2; ++i) {
        /* libssl always stays shared */
        const uint32_t private_flags = i == 1 ? 0x08008001u : 0x8000u;
        reset();
        current_pid = 123;
        assert(installed_load(0, paths[i], 0x08008001, NULL) == 88);
        assert(seen_flags == private_flags);
        reset();
        current_pid = 123;
        http_process_allowed = 0;
        assert(installed_load(0, paths[i], 0x08008001, NULL) == 88);
        assert(seen_flags == 0x08008001);
    }
    reset();
    assert(installed_load(0, "wb0:/webcore/ScePsp2Compat.suprx", 0x08008001, NULL) == 88);
    assert(seen_flags == 0x08008001);
    puts("private loads: only eligible libhttp replacements drop shared mapping flags PASS");
}

int main(void) {
    test_startup_failures();
    reset_startup();
    assert(module_start(0, NULL) == SCE_KERNEL_START_SUCCESS);
    assert(hook_installations == 2 && loader_initializations == 1 && mutex_live);
    assert(g_replace_iap && g_replace[MODULE_COMPAT]);
    test_routes();
    test_reauth_routes();
    test_private_flags();
    assert(module_stop(0, NULL) == SCE_KERNEL_STOP_FAIL);
    return 0;
}
