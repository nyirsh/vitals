#include "backend.h"
#include "module_descriptor.h"
#include "diagnostics.h"
#include "webkit_callback.h"
#include "vitals/path.h"

#include <psp2/kernel/modulemgr.h>
#include <psp2common/kernel/modulemgr.h>
#include <taihen.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

enum { BROWSER_HOOK_CLOSE, BROWSER_HOOK_PENDING, BROWSER_HOOK_CHECK, BROWSER_HOOK_CONNECT, BROWSER_HOOK_COUNT };
static tai_hook_ref_t hook_refs[BROWSER_HOOK_COUNT];
static int hook_ids[BROWSER_HOOK_COUNT];
static uint32_t starting;
static char ca_path[256];

static int reject_identity(const char *check, uint32_t detail) {
    VITALS_LOG("browser module identity rejected: check=%s detail=0x%08X", check, detail);
    (void)check;
    (void)detail;
    return -1;
}

static void *continuation(tai_hook_ref_t reference) {
    struct _tai_hook_user *current = (struct _tai_hook_user *)reference;
    struct _tai_hook_user *next = (struct _tai_hook_user *)current->next;
    return next == NULL ? current->old : next->func;
}

static int hook_connect(void *connection, int index, unsigned char nonblocking, unsigned char *done) {
    typedef int (*Original)(void *, int, unsigned char, unsigned char *);
    int handled;
    int result = vitals_browser_connect(connection, index, nonblocking, done, &handled);
    if (handled) {
        return result;
    }
    result = ((Original)continuation(hook_refs[BROWSER_HOOK_CONNECT]))(connection, index, nonblocking, done);
    return result;
}

static int hook_close(void *connection, int index) {
    typedef int (*Original)(void *, int);
    int handled;
    int result = vitals_browser_close(connection, index, &handled);
    if (!handled) result = ((Original)continuation(hook_refs[BROWSER_HOOK_CLOSE]))(connection, index);
    return result;
}

static int hook_pending(void *connection, int index) {
    typedef int (*Original)(void *, int);
    int handled;
    int result = vitals_browser_pending(connection, index, &handled);
    if (!handled) result = ((Original)continuation(hook_refs[BROWSER_HOOK_PENDING]))(connection, index);
    return result;
}

static int hook_check(void *connection) {
    typedef int (*Original)(void *);
    int handled;
    int result = vitals_browser_check(connection, &handled);
    if (!handled) result = ((Original)continuation(hook_refs[BROWSER_HOOK_CHECK]))(connection);
    return result;
}

static int validate_module(int modid, uintptr_t *text) {
    SceKernelModuleInfo info;
    size_t signature = SIZE_MAX, byte = SIZE_MAX;
    int result;

    memset(&info, 0, sizeof(info));
    info.size = sizeof(info);
    result = sceKernelGetModuleInfo(modid, &info);
    if (result < 0) return reject_identity("module_info", (uint32_t)result);
    if (memcmp(info.module_name, "ScePsp2Compat", sizeof("ScePsp2Compat")) != 0)
        return reject_identity("module_name", 0);
    if (info.segments[0].vaddr == NULL || info.segments[1].vaddr == NULL)
        return reject_identity("segment_address", 0);
    if (info.segments[0].filesz != VITALS_BROWSER_TEXT_FILESZ)
        return reject_identity("text_filesz", info.segments[0].filesz);
    if (info.segments[0].memsz != VITALS_BROWSER_TEXT_MEMSZ)
        return reject_identity("text_memsz", info.segments[0].memsz);
    if (info.segments[1].filesz != VITALS_BROWSER_DATA_FILESZ)
        return reject_identity("data_filesz", info.segments[1].filesz);
    if (info.segments[1].memsz != VITALS_BROWSER_DATA_MEMSZ)
        return reject_identity("data_memsz", info.segments[1].memsz);
    result = vitals_validate_module_text(info.segments[0].vaddr, info.segments[0].filesz,
        &browser_descriptor, &signature, &byte);
    if (result != VITALS_MODULE_GATE_OK) {
        VITALS_LOG("browser module signature rejected: index=%u byte=%u result=%d",
            (unsigned int)signature, (unsigned int)byte, result);
        return result;
    }
    if (memchr(info.path, '\0', sizeof(info.path)) == NULL ||
        !vitals_browser_ca_path(info.path, ca_path, sizeof(ca_path))) {
        VITALS_LOG("browser module path rejected");
        return -1;
    }
    *text = (uintptr_t)info.segments[0].vaddr;
    return 0;
}

int module_start(SceSize size, const void *data) {
    static const struct { size_t offset; const void *function; } hooks[] = {
        {VITALS_BROWSER_CLOSE_OFFSET, hook_close},
        {VITALS_BROWSER_PENDING_OFFSET, hook_pending},
        {VITALS_BROWSER_CHECK_OFFSET, hook_check},
        {VITALS_BROWSER_CONNECT_OFFSET, hook_connect}
    };
    VitalsBrowserStartArgs args;
    VitalsBrowserOps ops = {0};
    uintptr_t text;
    uint32_t expected = 0;
    int result;

    if (!__atomic_compare_exchange_n(&starting, &expected, 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        return SCE_KERNEL_START_FAILED;
    }
    if (data == NULL || size != sizeof(args))
        return SCE_KERNEL_START_FAILED;
    memcpy(&args, data, sizeof(args));
    if (args.magic != VITALS_BROWSER_START_MAGIC)
        return SCE_KERNEL_START_FAILED;
    if (args.version != VITALS_BROWSER_START_VERSION)
        return SCE_KERNEL_START_FAILED;
    if (args.compat_modid < 0)
        return SCE_KERNEL_START_FAILED;
    if (args.reserved != 0)
        return SCE_KERNEL_START_FAILED;
    result = validate_module(args.compat_modid, &text);
    if (result != 0) return SCE_KERNEL_START_FAILED;
    ops.timeleft = (int (*)(void *, void *, int))(text + VITALS_BROWSER_TIMELEFT_OFFSET + 1);
    ops.socket_wait = (int (*)(int, int, int, int))(text + VITALS_BROWSER_WAIT_OFFSET + 1);
    ops.is_default_ctx_callback = vitals_webkit_is_default_ctx_callback;
    ops.default_ciphers = VITALS_BROWSER_DEFAULT_CIPHERS;
    ops.default_ca_path = ca_path;
    result = vitals_browser_init(&ops);
    if (result != 0) {
        VITALS_LOG("browser TLS initialization failed: 0x%08X", result);
        return SCE_KERNEL_START_FAILED;
    }
    for (size_t i = 0; i < BROWSER_HOOK_COUNT; ++i) hook_ids[i] = -1;
    unsigned int published = 0;
    for (size_t i = 0; i < BROWSER_HOOK_COUNT; ++i) {
        hook_ids[i] = taiHookFunctionOffset(&hook_refs[i], args.compat_modid, 0,
            hooks[i].offset, 1, hooks[i].function);
        if (hook_ids[i] < 0) {
            VITALS_LOG("browser TLS inactive: hook=%u error=0x%08X", (unsigned int)i, hook_ids[i]);
            if (published == 0) {
                (void)vitals_browser_destroy();
                return SCE_KERNEL_START_FAILED;
            }
            /* Published continuations may still be executing on another thread */
            VITALS_LOG("browser hooks retained until process exit");
            return SCE_KERNEL_START_SUCCESS;
        }
        ++published;
    }
    vitals_browser_enable(1);
    VITALS_LOG("browser TLS active: compat=0x%08X text=0x%08X", args.compat_modid, (unsigned int)text);
    return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize size, const void *args) {
    (void)size;
    (void)args;
    return SCE_KERNEL_STOP_FAIL;
}

/* The Vita loader enters through _start; macOS, where only the host tests build, has no aliases */
#if !defined(VITALS_HOST_MODULE_TEST) && !defined(__APPLE__)
int _start(SceSize size, const void *args) __attribute__((weak, alias("module_start")));
#endif
