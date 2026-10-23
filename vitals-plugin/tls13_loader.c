#include "tls13_loader.h"
#include "native_module_api.h"

#include <psp2kern/kernel/debug.h>
#include <psp2/io/fcntl.h>
#include <psp2kern/io/fcntl.h>
#include <psp2kern/io/stat.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysroot.h>
#include <psp2kern/kernel/threadmgr/misc.h>
#include <psp2kern/kernel/threadmgr/mutex.h>
#include <psp2kern/kernel/utils.h>

#include <stddef.h>
#include <stdint.h>

#include "vitals/sony_abi.h"
#include "vitals/browser_abi.h"
#include "vitals/path.h"

/* VitaSDK supplies this native stub but omits its declaration from the kernel I/O header */
SceUID ksceIoOpenForPid(SceUID pid, const char *filename, int flags, unsigned int mode);

#include <taihen.h>
#if defined(__arm__)
_Static_assert(sizeof(tai_module_info_t) == 0x38, "taiHEN ARM32 module-info extent");
#endif

#define VITALS_LIBHTTP_PATH "vs0:/data/external/vitals/libhttp.suprx"
#ifndef VITALS_HTTP_PROVIDER_PATH
#define VITALS_HTTP_PROVIDER_PATH "vs0:/data/external/vitals/native/vitals_http.suprx"
#endif
#define VITALS_PROVIDER_PATH VITALS_HTTP_PROVIDER_PATH
#define VITALS_HASH_BUFFER_SIZE UINT32_C(1024)
#define VITALS_HASH_WORKSPACE_SIZE UINT32_C(4096)
#define VITALS_MAX_PROCESS_MODULES UINT32_C(256)
#define VITALS_QUERY_WORKSPACE_SIZE UINT32_C(4096)
#define VITALS_ARGUMENT_WORKSPACE_SIZE UINT32_C(4096)

_Static_assert(sizeof(SceKernelAllocMemBlockKernelOpt) == 0x58, "Native allocation option extent");
_Static_assert(offsetof(SceKernelAllocMemBlockKernelOpt, pid) == 0x24, "Native allocation PID offset");

static const uint8_t g_expected_libhttp_sha256[SCE_SHA256_DIGEST_SIZE] = {
    0x42,
    0xBC,
    0x7E,
    0x34,
    0x07,
    0x79,
    0x64,
    0xAC,
    0x7E,
    0xDC,
    0x43,
    0x65,
    0xAB,
    0xAD,
    0x8A,
    0xF9,
    0xBF,
    0x41,
    0x79,
    0x3A,
    0x34,
    0xD2,
    0xC7,
    0xEF,
    0xD6,
    0x31,
    0x97,
    0x6F,
    0x7D,
    0x27,
    0x39,
    0xC1,
};

static const uint8_t g_expected_browser_sha256[SCE_SHA256_DIGEST_SIZE] = {
    0x73,
    0x88,
    0x62,
    0x13,
    0x38,
    0x19,
    0xfc,
    0x37,
    0xbc,
    0x21,
    0xf7,
    0x14,
    0xda,
    0x7c,
    0xa7,
    0x6c,
    0x72,
    0xd7,
    0x3a,
    0x62,
    0x0a,
    0xfa,
    0xfb,
    0xe6,
    0xa9,
    0x40,
    0xd8,
    0x7d,
    0xd4,
    0xe6,
    0xdc,
    0x58,
};

typedef struct LoaderTarget
{
    const char *module_path;
    const char *provider_path;
    const char *provider_name;
    const uint8_t *hash;
    uint32_t start_magic;
    uint32_t start_version;
} LoaderTarget;

static const LoaderTarget targets[] = {
    {VITALS_LIBHTTP_PATH, VITALS_PROVIDER_PATH, "vitals_http", g_expected_libhttp_sha256,
     VITALS_START_MAGIC, VITALS_START_VERSION},
    {"vs0:/data/external/vitals/ScePsp2Compat.suprx", VITALS_BROWSER_PROVIDER_BOOT_PATH,
     "vitals", g_expected_browser_sha256, VITALS_BROWSER_START_MAGIC, VITALS_BROWSER_START_VERSION}};

static uint8_t ready[2];
static struct
{
    SceUID pid;
    unsigned int target;
} in_flight[64];
static SceUID g_injection_mutex = -1;

typedef struct HashWorkspace
{
    SceSha256Context context;
    uint8_t buffer[VITALS_HASH_BUFFER_SIZE];
} HashWorkspace;

_Static_assert(sizeof(HashWorkspace) <= VITALS_HASH_WORKSPACE_SIZE,
               "hash workspace exceeds its bounded allocation");

static int hash_file_sha256(const char *path, uint8_t digest[SCE_SHA256_DIGEST_SIZE],
                            SceUID namespace_pid)
{
    HashWorkspace *workspace = NULL;
    void *allocation = NULL;
    SceUID descriptor = -1, memory;
    int result = -1;

    /* The nested loader stack must not also hold the file buffer and SHA state */
    memory = ksceKernelAllocMemBlock("vitals hash workspace", SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_RW,
                                     VITALS_HASH_WORKSPACE_SIZE, NULL);
    if (memory < 0)
        return memory;
    int base_result = ksceKernelGetMemBlockBase(memory, &allocation);
    if (base_result >= 0 && allocation != NULL)
        workspace = allocation;
    if (workspace == NULL)
        goto cleanup;

    descriptor = namespace_pid > 0 ? ksceIoOpenForPid(namespace_pid, path, SCE_O_RDONLY, 0)
                                   : ksceIoOpen(path, SCE_O_RDONLY, 0);
    if (descriptor < 0)
    {
        result = descriptor;
        goto cleanup;
    }

    result = ksceSha256BlockInit(&workspace->context);
    if (result < 0)
        goto cleanup;
    while (result >= 0)
    {
        int bytes_read = ksceIoRead(descriptor, workspace->buffer, sizeof(workspace->buffer));
        if (bytes_read < 0)
        {
            result = bytes_read;
            break;
        }
        if (bytes_read == 0)
        {
            result = 0;
            break;
        }
        result = ksceSha256BlockUpdate(&workspace->context, workspace->buffer, (SceSize)bytes_read);
    }
    if (result >= 0)
    {
        result = ksceSha256BlockResult(&workspace->context, digest);
    }

cleanup:
    if (descriptor >= 0)
    {
        int closed = ksceIoClose(descriptor);
        if (closed < 0 && result >= 0)
            result = -1;
    }
    if (workspace != NULL)
        memset(workspace, 0, sizeof(*workspace));
    if (memory >= 0)
    {
        int freed = ksceKernelFreeMemBlock(memory);
        if (freed < 0 && result >= 0)
            result = -1;
    }
    return result;
}

typedef struct QueryWorkspace
{
    SceUID module_ids[VITALS_MAX_PROCESS_MODULES];
    SceKernelModuleInfo info;
    char browser_module_path[256];
    SceKernelAllocMemBlockKernelOpt argument_options;
    VitalsStartArgs argument_echo;
    tai_module_info_t name_info;
    SceUID name_target_uid;
} QueryWorkspace;

_Static_assert(sizeof(QueryWorkspace) <= VITALS_QUERY_WORKSPACE_SIZE,
               "module query workspace exceeds its bounded allocation");

static int named_module_matches(const tai_module_info_t *info, const char *name)
{
    return info->modid > 0 && memchr(info->name, '\0', sizeof(info->name)) != NULL &&
           strcmp(info->name, name) == 0;
}

static int lookup_name(SceUID pid, const char *name, tai_module_info_t *info)
{
    memset(info, 0, sizeof(*info));
    info->size = sizeof(*info);
    return taiGetModuleInfoForKernel(pid, name, info);
}

static int provider_is_loaded_by_name(SceUID pid, const char *target_name,
                                      const char *provider_name, QueryWorkspace *workspace)
{
    tai_module_info_t *info = &workspace->name_info;
    int result = lookup_name(pid, target_name, info);
    if (result != 0 || !named_module_matches(info, target_name))
        return -1;
    workspace->name_target_uid = info->modid;
    result = lookup_name(pid, provider_name, info);
    /* Only taiHEN's explicit not-found result establishes absence */
    if (result == (int32_t)UINT32_C(0x90010002))
        return 0;
    return result == 0 && named_module_matches(info, provider_name) ? 1 : -1;
}

static int target_matches(const LoaderTarget *target, SceUID module_namespace_pid)
{
    uint8_t digest[SCE_SHA256_DIGEST_SIZE];
    SceIoStat status;
    int matches = 0;
    if (ksceIoGetstat(target->provider_path, &status) < 0)
        return 0;
    if (hash_file_sha256(target->module_path, digest, module_namespace_pid) >= 0)
        matches = timingsafe_memcmp(digest, target->hash, sizeof(digest)) == 0;
    memset(digest, 0, sizeof(digest));
    return matches;
}

int vitals_kernel_loader_init(void)
{
    if (g_injection_mutex >= 0)
        return -1;
    memset(ready, 0, sizeof(ready));
    memset(in_flight, 0, sizeof(in_flight));
    for (size_t i = 0; i < sizeof(targets) / sizeof(targets[0]); ++i)
    {
        ready[i] = (uint8_t)target_matches(&targets[i], 0);
    }
    if (!ready[0] && !ready[1])
        return -1;
    g_injection_mutex = ksceKernelCreateMutex("vitals inject", 0, 0, NULL);
    if (g_injection_mutex < 0)
    {
        memset(ready, 0, sizeof(ready));
        return g_injection_mutex;
    }
    return 0;
}

void vitals_kernel_loader_destroy(void)
{
    memset(ready, 0, sizeof(ready));
    if (g_injection_mutex >= 0)
    {
        (void)ksceKernelDeleteMutex(g_injection_mutex);
        g_injection_mutex = -1;
    }
}

int vitals_kernel_loader_ready(void)
{
    return ready[0];
}

int vitals_kernel_browser_loader_ready(void)
{
    return ready[1];
}

static int inject_target(SceUID pid, SceUID module_id, unsigned int target_index, const char *provider_path)
{
    const LoaderTarget *target = &targets[target_index];
    const char *file_path = target_index == 1
                                ? target->provider_path
                                : provider_path;
    /* The provider loads from its global path; only the compat module is hashed in pid's overlay */
    const SceUID module_namespace_pid = target_index == 1 ? pid : 0;
    QueryWorkspace *workspace = NULL;
    void *allocation = NULL;
    SceUID query_memory = -1;
    SceUID argument_memory = -1;
    void *user_arguments = NULL;
    VitalsStartArgs arguments;
    SceKernelModuleInfo *target_info;
    int start_status = SCE_KERNEL_START_FAILED;
    int loaded;
    SceUID provider_modid;
    int result;
    size_t slot = sizeof(in_flight) / sizeof(in_flight[0]);

    if (!ready[target_index] || g_injection_mutex < 0 || pid <= 0 || module_id < 0 || provider_path == NULL)
    {
        return -1;
    }
    result = ksceKernelLockMutex(g_injection_mutex, 1, NULL);
    if (result < 0)
    {
        return result;
    }

    for (size_t i = 0; i < sizeof(in_flight) / sizeof(in_flight[0]); ++i)
    {
        if (in_flight[i].pid == pid && in_flight[i].target == target_index)
        {
            (void)ksceKernelUnlockMutex(g_injection_mutex, 1);
            return 1;
        }
        if (in_flight[i].pid == 0 && slot == sizeof(in_flight) / sizeof(in_flight[0]))
            slot = i;
    }
    if (slot == sizeof(in_flight) / sizeof(in_flight[0]))
    {
        (void)ksceKernelUnlockMutex(g_injection_mutex, 1);
        return -1;
    }
    in_flight[slot].pid = pid;
    in_flight[slot].target = target_index;
    (void)ksceKernelUnlockMutex(g_injection_mutex, 1);

    result = -1;
    /* Query buffers must not consume the nested native loader's kernel stack */
    query_memory = ksceKernelAllocMemBlock("vitals query workspace", SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_RW,
                                           VITALS_QUERY_WORKSPACE_SIZE, NULL);
    if (query_memory < 0)
        goto cleanup;
    int base_result = ksceKernelGetMemBlockBase(query_memory, &allocation);
    if (base_result >= 0 && allocation != NULL)
        workspace = allocation;
    if (workspace == NULL)
        goto cleanup;
    loaded = provider_is_loaded_by_name(pid, target_index == 1 ? "ScePsp2Compat" : "SceLibHttp",
                                        target->provider_name, workspace);
    if (loaded < 0)
    {
        result = loaded;
        goto cleanup;
    }
    if (loaded != 0)
    {
        /* The provider never unloads, so a libhttp loaded again in the same process (after the
         * app unloaded the first) is left to Sony's TLS */
        ksceDebugPrintf("vitals: provider already resident pid=0x%X; it stays with its first libhttp\n", pid);
        result = 0;
        goto cleanup;
    }
    /* The HTTP provider now owns its sceClib mspace; host SceLibc is not a prerequisite */

    result = -1;
    LoaderTarget verification_target = *target;
    if (target_index == 1)
    {
        if (!vitals_browser_module_path(provider_path, workspace->browser_module_path,
                                           sizeof(workspace->browser_module_path)))
            goto cleanup;
        verification_target.provider_path = file_path;
        verification_target.module_path = workspace->browser_module_path;
    }
    if (!target_matches(&verification_target, module_namespace_pid))
    {
        result = -1;
        goto cleanup;
    }
    target_info = &workspace->info;
    memset(target_info, 0, sizeof(*target_info));
    target_info->size = sizeof(*target_info);
    result = ksceKernelGetModuleInfo(pid, module_id, target_info);
    if (result < 0 || target_info->modid <= 0 ||
        strcmp(target_info->module_name, target_index == 1 ? "ScePsp2Compat" : "SceLibHttp") != 0)
    {
        result = -1;
        goto cleanup;
    }
    if (target_info->modid != workspace->name_target_uid)
    {
        result = -1;
        goto cleanup;
    }
    /* The HTTP provider checks its libhttp mapping is private itself, through the user Sysmem
     * API, before setting up its heap or hooks */
    if (target_index == 0 && target_info->segments[0].vaddr == NULL)
    {
        result = -1;
        goto cleanup;
    }
    arguments.magic = target->start_magic;
    arguments.version = target->start_version;
    arguments.libhttp_modid = target_info->modid;
    arguments.reserved = 0;

    /* The native entry-thread path copies from the current process's user address space */
    if (ksceKernelGetProcessId() != pid)
    {
        result = -1;
        goto cleanup;
    }
    memset(&workspace->argument_options, 0, sizeof(workspace->argument_options));
    workspace->argument_options.size = sizeof(workspace->argument_options);
    workspace->argument_options.attr = SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_HAS_PID;
    workspace->argument_options.pid = pid;
    argument_memory = ksceKernelAllocMemBlock("vitals start arguments", SCE_KERNEL_MEMBLOCK_TYPE_USER_RW,
                                              VITALS_ARGUMENT_WORKSPACE_SIZE, &workspace->argument_options);
    if (argument_memory < 0)
    {
        result = -1;
        goto cleanup;
    }
    result = ksceKernelGetMemBlockBase(argument_memory, &user_arguments);
    if (result < 0 || user_arguments == NULL)
    {
        result = -1;
        goto cleanup;
    }
    result = ksceKernelCopyToUserProc(pid, user_arguments, &arguments, sizeof(arguments));
    if (result != 0)
    {
        result = -1;
        goto cleanup;
    }
    result = ksceKernelCopyFromUserProc(pid, &workspace->argument_echo, user_arguments, sizeof(arguments));
    if (result == 0 && memcmp(&workspace->argument_echo, &arguments, sizeof(arguments)) != 0)
        result = -1;
    if (result != 0)
    {
        result = -1;
        goto cleanup;
    }

    provider_modid = ksceKernelLoadStartModuleForPid(
        pid,
        file_path,
        sizeof(arguments),
        user_arguments,
        0,
        NULL,
        &start_status);
    memset(&arguments, 0, sizeof(arguments));

    if (provider_modid <= 0)
    {
        result = provider_modid < 0 ? provider_modid : -1;
        goto cleanup;
    }
    if (start_status != SCE_KERNEL_START_SUCCESS)
    {
        (void)ksceKernelUnloadModuleForPid(pid, provider_modid, 0, NULL);
        result = -1;
        goto cleanup;
    }
    result = 0;

cleanup:
    if (argument_memory >= 0)
    {
        int freed = ksceKernelFreeMemBlock(argument_memory);
        if (freed < 0 && result >= 0)
            result = -1;
    }
    if (workspace != NULL)
        memset(workspace, 0, sizeof(*workspace));
    if (query_memory >= 0)
    {
        int freed = ksceKernelFreeMemBlock(query_memory);
        if (freed < 0 && result >= 0)
            result = -1;
    }
    if (ksceKernelLockMutex(g_injection_mutex, 1, NULL) >= 0)
    {
        in_flight[slot].pid = 0;
        in_flight[slot].target = 0;
        (void)ksceKernelUnlockMutex(g_injection_mutex, 1);
    }
    return result;
}

typedef struct PreparationCall
{
    SceUID pid;
    SceUID module_id;
    unsigned int target_index;
    const char *provider_path;
    int result;
    int called;
} PreparationCall;

static int prepare_on_native_stack(void *opaque)
{
    PreparationCall *call = opaque;
    call->called = 1;
    call->result = inject_target(call->pid, call->module_id, call->target_index, call->provider_path);
    ksceDebugPrintf("vitals: inject target=%u pid=0x%X rc=0x%08X\n",
                    call->target_index, call->pid, call->result);
    return 0;
}

static int dispatch_preparation(SceUID pid, SceUID module_id, unsigned int target_index, const char *provider_path)
{
    PreparationCall call = {pid, module_id, target_index, provider_path, -1, 0};
    int result = ksceKernelRunWithStack(16384, prepare_on_native_stack, &call);
    if (result < 0)
        return result;
    return call.called ? call.result : -1;
}

int vitals_kernel_http_process_allowed(SceUID pid)
{
    if (pid <= 0)
        return 0;
    /* SceShell shares its HTTP library with other Sony code, and a private copy can't serve
     * that code (the loader fails with 0x8002D018)
     * So the shell keeps Sony's library and TLS */
    if (pid == ksceKernelSysrootGetShellPid())
        return 0;
    char title_id[16] = {0};
    int result = ksceKernelSysrootGetProcessTitleId(pid, title_id, sizeof(title_id));
    if (result < 0)
        return result;
    /* Exclude the browser controller and its WebKit helper; they use the browser provider */
    if (memcmp(title_id, "NPXS10003", sizeof("NPXS10003")) == 0 ||
        memcmp(title_id, "NPXS10083", sizeof("NPXS10083")) == 0)
        return 0;
    VitalsNativeHttpConsumer consumer;
    int shared = vitals_native_http_shared_consumer(pid, &consumer);
    if (shared != 0)
        return shared < 0 ? shared : 0;
    return 1;
}

int vitals_kernel_inject_for_pid(SceUID pid, SceUID libhttp_modid)
{
    if (!ready[0] || g_injection_mutex < 0 || pid <= 0 || libhttp_modid < 0)
        return -1;
    int allowed = vitals_kernel_http_process_allowed(pid);
    ksceDebugPrintf("vitals: http policy pid=0x%X allowed=%d\n", pid, allowed);
    if (allowed <= 0)
        return allowed;
    return dispatch_preparation(pid, libhttp_modid, 0, targets[0].provider_path);
}

int vitals_kernel_inject_browser_for_pid(SceUID pid, SceUID compat_modid, const char *provider_path)
{
    return dispatch_preparation(pid, compat_modid, 1, provider_path);
}
