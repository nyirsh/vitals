#include "diag.h"

#include <psp2kern/io/stat.h>
#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysroot.h>

#include "native_module_api.h"
#include "vitals/path.h"

#include <psp2kern/io/fcntl.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/sysmem.h>

#define DIAG_LIBHTTP "ur0:data/vitals-diag/lhttp.suprx"
#define DIAG_MODULE "ur0:data/vitals-diag/vitals-diag.suprx"
#define STORE_TITLE "NPXS10002"

/* Decided once at boot, as libhttp is shared between processes and every process must get the
 * same one: 0 off; 1 Sony's libhttp everywhere (both files there), with the logging module in the
 * shell and the Store; 2 vitals-http as usual (only the logging module there), with the logging
 * module in the Store */
static int g_mode = -1;
/* Modules waiting for their start before the logging module goes in: the shell's libhttp, and the
 * Store's SceNpCommerce2 */
static struct
{
    SceUID pid, module;
} g_waiting[2] = {{-1, -1}, {-1, -1}};

static int mode(void)
{
    if (g_mode < 0) {
        SceIoStat status;
        int module = ksceIoGetstat(DIAG_MODULE, &status) >= 0;
        g_mode = !module ? 0 : ksceIoGetstat(DIAG_LIBHTTP, &status) >= 0 ? 1 : 2;
        ksceDebugPrintf("vitals: diag: %s\n", g_mode == 1 ? "on: Sony's libhttp everywhere"
                                               : g_mode == 2 ? "on: logging the Store, vitals-http as usual" : "off");
    }
    return g_mode;
}

static int has_title(SceUID pid, const char *wanted)
{
    char title[16] = {0};
    if (ksceKernelSysrootGetProcessTitleId(pid, title, sizeof(title)) < 0)
        return 0;
    for (unsigned i = 0; wanted[i] != '\0' || title[i] != '\0'; ++i)
        if (i >= sizeof(title) || title[i] != wanted[i])
            return 0;
    return 1;
}

static int is_store(SceUID pid)
{
    return has_title(pid, STORE_TITLE);
}

/* The shell may load its libhttp before its process is known as the shell's; its title is "main" */
static int is_shell(SceUID pid)
{
    return pid == ksceKernelSysrootGetShellPid() || has_title(pid, "main");
}

const char *vitals_diag_libhttp(SceUID pid)
{
    (void)pid;
    return mode() == 1 ? DIAG_LIBHTTP : NULL;
}

void vitals_diag_loaded(SceUID pid, const char *path, SceUID module)
{
    if (module <= 0 || mode() == 0)
        return;
    /* The shell signs in to PSN through its libhttp; the Store reaches PSN through SceNpCommerce2 */
    if (mode() == 1 && is_shell(pid) &&
        (vitals_path_equals(path, "vs0:sys/external/libhttp.suprx", 0x400) ||
         vitals_path_equals(path, "vs0:/sys/external/libhttp.suprx", 0x400))) {
        g_waiting[0].pid = pid;
        g_waiting[0].module = module;
    } else if ((vitals_path_equals(path, "vs0:sys/external/np_commerce2.suprx", 0x400) ||
                vitals_path_equals(path, "vs0:/sys/external/np_commerce2.suprx", 0x400)) &&
               is_store(pid)) {
        g_waiting[1].pid = pid;
        g_waiting[1].module = module;
    }
}

/* Copies the segments of the Store's modules that matter to ux0:data/vitals-diag-dump/, once per
 * boot, to find in their code where the Store gives up; Sony's code only, no personal data */
#define DUMP_DIR "ux0:data/vitals-diag-dump"
static int g_dumped;
static SceUID g_modules[128];
static SceKernelModuleInfo g_info;
static unsigned char g_chunk[0x1000];

static void dump_modules(SceUID pid)
{
    static const char *const wanted[] = {"SceStoreBrowser", "SceNpCommerce2", "SceNpManager", "SceNpCommon"};
    SceSize count = sizeof(g_modules) / sizeof(g_modules[0]);
    if (g_dumped || ksceKernelGetModuleList(pid, 0xff, 1, g_modules, &count) < 0)
        return;
    g_dumped = 1;
    (void)ksceIoMkdir(DUMP_DIR, 0777);
    for (SceSize m = 0; m < count; ++m) {
        memset(&g_info, 0, sizeof(g_info));
        g_info.size = sizeof(g_info);
        if (ksceKernelGetModuleInfo(pid, g_modules[m], &g_info) < 0)
            continue;
        int match = 0;
        for (unsigned w = 0; w < sizeof(wanted) / sizeof(wanted[0]); ++w)
            match |= strncmp(g_info.module_name, wanted[w], sizeof(g_info.module_name)) == 0;
        if (!match)
            continue;
        for (unsigned seg = 0; seg < 4; ++seg) {
            uintptr_t base = (uintptr_t)g_info.segments[seg].vaddr;
            SceSize size = g_info.segments[seg].memsz;
            if (base == 0 || size == 0)
                continue;
            char path[128];
            snprintf(path, sizeof(path), DUMP_DIR "/%s-seg%u-%08X.bin", g_info.module_name, seg, (unsigned)base);
            SceUID fd = ksceIoOpen(path, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0666);
            if (fd < 0)
                continue;
            SceSize written = 0;
            for (SceSize at = 0; at < size; at += sizeof(g_chunk)) {
                SceSize n = size - at < sizeof(g_chunk) ? size - at : sizeof(g_chunk);
                if (ksceKernelCopyFromUserProc(pid, g_chunk, (const void *)(base + at), n) < 0)
                    break;
                written += (SceSize)ksceIoWrite(fd, g_chunk, n);
            }
            (void)ksceIoClose(fd);
            ksceDebugPrintf("vitals: diag: dumped %s seg%u base=0x%08X size=0x%X written=0x%X\n", g_info.module_name,
                            seg, (unsigned)base, size, written);
        }
    }
}

void vitals_diag_started(SceUID pid, SceUID module, int result)
{
    for (unsigned i = 0; i < 2; ++i) {
        if (g_waiting[i].module < 0 || pid != g_waiting[i].pid || module != g_waiting[i].module)
            continue;
        g_waiting[i].pid = g_waiting[i].module = -1;
        if (i == 1)
            dump_modules(pid);
        int status = 0;
        SceUID loaded = result == 0 ? ksceKernelLoadStartModuleForPid(pid, DIAG_MODULE, 0, NULL, 0, NULL, &status) : -1;
        ksceDebugPrintf("vitals: diag: logging module pid=0x%X rc=0x%08X status=0x%08X\n", pid, loaded, status);
    }
}
