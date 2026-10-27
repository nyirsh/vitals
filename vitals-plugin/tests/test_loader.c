#include "tls13_loader.h"
#include "native_module_api.h"
#include "vitals/browser_abi.h"
#include "vitals/sony_abi.h"
#include <kernel_mock.h>
#include "vitals/path.h"
#include <assert.h>
#include <stdio.h>

#include <taihen.h>

static const uint8_t compat_hash[32] = {
    0x73,0x88,0x62,0x13,0x38,0x19,0xfc,0x37,0xbc,0x21,0xf7,0x14,0xda,0x7c,0xa7,0x6c,
    0x72,0xd7,0x3a,0x62,0x0a,0xfa,0xfb,0xe6,0xa9,0x40,0xd8,0x7d,0xd4,0xe6,0xdc,0x58};
static int browser_file = 1, corrupt_browser;
static int read_once[2], locked, mutex_live, loads, unloads;
static int load_error, start_error, reenter, close_error;
static int target_info_error, target_user_id = 188;
static int target_wrong_name;
static unsigned int target_queries;
static const char *expected_path;
static const char *expected_module_path;
static int runtime_namespace_required, namespace_provider_error, namespace_hash_error;
static int namespace_stat_error, namespace_close_error;
static unsigned int namespace_provider_opens, namespace_hash_opens;
static unsigned int global_provider_stats;
static unsigned int stream_blocks = 1;
static int open_descriptors;
static _Alignas(16) unsigned char hash_memory[4096];
static int workspace_live, alloc_fail, base_fail, null_base, free_fail;
static unsigned int allocations, frees;
static _Alignas(16) unsigned char query_memory[4096];
static int query_live, query_alloc_fail, query_base_fail, query_null_base, query_free_fail;
static unsigned int query_allocations, query_frees;
static unsigned int stack_calls;
static int stack_error, stack_skip, stack_error_after;
static _Alignas(16) unsigned char argument_memory[4096];
static int argument_live, argument_alloc_fail, argument_base_fail, argument_null_base;
static int argument_copy_fail, argument_readback_fail, argument_corrupt, argument_free_fail;
static unsigned int argument_allocations, argument_frees, argument_copies;
static SceUID argument_current_pid = 99;

static void expect_hash_stage(const char *stage) { (void)stage; }

static void require_workspace(const void *data, size_t size) {
    uintptr_t address = (uintptr_t)data, base = (uintptr_t)hash_memory;
    assert(workspace_live && address >= base && size <= sizeof(hash_memory));
    assert(address - base <= sizeof(hash_memory) - size);
}

static void require_query_workspace(const void *data, size_t size) {
    uintptr_t address = (uintptr_t)data, base = (uintptr_t)query_memory;
    assert(query_live && address >= base && size <= sizeof(query_memory));
    assert(address - base <= sizeof(query_memory) - size);
}

int ksceDebugPrintf(const char *format, ...) { (void)format; return 0; }
int ksceKernelRunWithStack(SceSize size, int (*callback)(void *), void *argument) {
    assert(size == 16384 && !locked);
    assert(callback != NULL && argument != NULL);
    ++stack_calls;
    if (stack_error) return -141;
    if (stack_skip) return 0;
    assert(callback(argument) == 0);
    return stack_error_after ? -142 : 0;
}

SceUID ksceKernelAllocMemBlock(const char *name, int type, SceSize size, const void *options) {
    assert(!locked);
    if (strcmp(name, "vitals start arguments") == 0) {
        const SceKernelAllocMemBlockKernelOpt *opt = options;
        SceKernelAllocMemBlockKernelOpt expected = {.size = sizeof(expected),
            .attr = SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_HAS_PID, .pid = 99};
        assert(type == SCE_KERNEL_MEMBLOCK_TYPE_USER_RW && size == sizeof(argument_memory));
        assert(opt != NULL && memcmp(opt, &expected, sizeof(expected)) == 0);
        assert(!argument_live && query_live);
        expect_hash_stage("args.alloc.enter");
        if (argument_alloc_fail) return -161;
        memset(argument_memory, 0, sizeof(argument_memory));
        argument_live = 1;
        ++argument_allocations;
        return 44;
    }
    if (strcmp(name, "vitals query workspace") == 0) {
        assert(type == SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_RW);
        assert(size == sizeof(query_memory) && options == NULL && !query_live);
        expect_hash_stage("query.alloc.enter");
        if (query_alloc_fail) return -133;
        ++query_allocations;
        query_live = 1;
        memset(query_memory, 0xa5, sizeof(query_memory));
        return 43;
    }
    assert(strcmp(name, "vitals hash workspace") == 0 && type == SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_RW);
    assert(size == sizeof(hash_memory) && options == NULL && !workspace_live);
    expect_hash_stage("hash.alloc.enter");
    if (alloc_fail) return -123;
    ++allocations;
    workspace_live = 1;
    memset(hash_memory, 0xa5, sizeof(hash_memory));
    return 42;
}

int ksceKernelGetMemBlockBase(SceUID uid, void **base) {
    assert(!locked);
    if (uid == 44) {
        assert(argument_live && base != NULL);
        expect_hash_stage("args.base.enter");
        if (argument_base_fail) return -162;
        *base = argument_null_base ? NULL : argument_memory;
        return 0;
    }
    if (uid == 43) {
        assert(query_live && base != NULL);
        expect_hash_stage("query.base.enter");
        if (query_base_fail) return -134;
        *base = query_null_base ? NULL : query_memory;
        return 0;
    }
    assert(uid == 42 && workspace_live && base != NULL);
    expect_hash_stage("hash.base.enter");
    if (base_fail) return -124;
    *base = null_base ? NULL : hash_memory;
    return 0;
}

int ksceKernelFreeMemBlock(SceUID uid) {
    assert(!locked);
    if (uid == 44) {
        assert(argument_live);
        expect_hash_stage("args.free.enter");
        ++argument_frees;
        argument_live = 0;
        return argument_free_fail ? -165 : 0;
    }
    if (uid == 43) {
        assert(query_live);
        expect_hash_stage("query.free.enter");
        ++query_frees;
        query_live = 0;
        return query_free_fail ? -135 : 0;
    }
    assert(uid == 42 && workspace_live);
    expect_hash_stage("hash.free.enter");
    ++frees;
    workspace_live = 0;
    return free_fail ? -125 : 0;
}

int ksceIoGetstat(const char *path, SceIoStat *status) {
    (void)status;
    expect_hash_stage("hash.stat.enter");
    if (strcmp(path, VITALS_BROWSER_PROVIDER_BOOT_PATH) == 0) {
        if (query_live) ++global_provider_stats;
        return namespace_provider_error || !browser_file ? -151 : 0;
    }
    if (runtime_namespace_required && query_live && strstr(path, "/" VITALS_BROWSER_PROVIDER_FILENAME))
        return (int32_t)UINT32_C(0x80010002);
    return browser_file ? 0 : -1;
}
int ksceIoOpen(const char *path, int flags, int mode) {
    int index = strstr(path, "ScePsp2Compat") != NULL;
    (void)flags; (void)mode;
    expect_hash_stage("hash.open.enter");
    if (runtime_namespace_required && query_live && index)
        return (int32_t)UINT32_C(0x80010002);
    read_once[index] = 0;
    ++open_descriptors;
    return index + 10;
}
SceUID ksceIoOpenForPid(SceUID pid, const char *path, int flags, unsigned int mode) {
    assert(pid == 99 && flags == SCE_O_RDONLY && mode == 0 && query_live && !locked);
    if (strcmp(path, VITALS_BROWSER_PROVIDER_BOOT_PATH) == 0)
        return (int32_t)UINT32_C(0x80010013);
    if (strcmp(path, expected_path) == 0) {
        expect_hash_stage("hash.stat.enter");
        ++namespace_provider_opens;
        if (namespace_provider_error || !browser_file) return -151;
        ++open_descriptors;
        return 12;
    }
    assert(strcmp(path, expected_module_path) == 0);
    expect_hash_stage("hash.open.enter");
    ++namespace_hash_opens;
    if (namespace_hash_error) return -152;
    read_once[1] = 0;
    ++open_descriptors;
    return 11;
}
int ksceIoGetstatByFd(SceUID fd, SceIoStat *status) {
    assert(fd == 12 && open_descriptors > 0 && status != NULL && !locked);
    expect_hash_stage("hash.stat.enter");
    return namespace_stat_error ? -153 : 0;
}
int ksceIoRead(int fd, void *data, unsigned int size) {
    assert(fd >= 10 && fd <= 11 && size >= 1);
    require_workspace(data, size);
    if (read_once[fd-10] == 0) expect_hash_stage("hash.read.enter");
    if ((unsigned int)read_once[fd-10]++ >= stream_blocks) return 0;
    *(uint8_t *)data = (uint8_t)(fd - 10);
    return 1;
}
int ksceIoClose(int fd) {
    assert(fd >= 10 && fd <= 12 && open_descriptors > 0);
    if (fd == 12) {
        expect_hash_stage("hash.stat.enter");
        --open_descriptors;
        return namespace_close_error ? -154 : 0;
    }
    expect_hash_stage("hash.close.enter");
    --open_descriptors;
    return close_error ? -1 : 0;
}
int ksceSha256BlockInit(SceSha256Context *context) {
    expect_hash_stage("hash.init.enter");
    require_workspace(context, sizeof(*context));
    context->kind = 0;
    return 0;
}
int ksceSha256BlockUpdate(SceSha256Context *context, const void *data, SceSize size) {
    assert(size == 1);
    require_workspace(context, sizeof(*context));
    require_workspace(data, size);
    if (read_once[*(const uint8_t *)data] == 1) expect_hash_stage("hash.update.enter");
    context->kind = *(const uint8_t *)data;
    return 0;
}
int ksceSha256BlockResult(SceSha256Context *context, uint8_t *digest) {
    expect_hash_stage("hash.finish.enter");
    require_workspace(context, sizeof(*context));
    /* Only vitals' ScePsp2Compat is hashed (stream byte 1) */
    assert(context->kind == 1);
    memcpy(digest, compat_hash, 32);
    if (corrupt_browser) digest[0] ^= 1;
    return 0;
}
int timingsafe_memcmp(const void *left, const void *right, size_t size) {
    expect_hash_stage("hash.compare.enter");
    return memcmp(left, right, size);
}
SceUID ksceKernelGetProcessId(void) { return argument_current_pid; }
int ksceKernelCopyToUserProc(SceUID pid, void *destination, const void *source, SceSize size) {
    assert(pid == 99 && argument_live && destination == argument_memory && source != destination);
    assert(size == sizeof(VitalsStartArgs) && !locked && query_live);
    expect_hash_stage("args.copy.enter");
    ++argument_copies;
    memcpy(destination, source, size);
    return argument_copy_fail ? -163 : 0;
}
int ksceKernelCopyFromUserProc(SceUID pid, void *destination, const void *source, SceSize size) {
    assert(pid == 99 && argument_live && source == argument_memory);
    assert(size == sizeof(VitalsStartArgs) && !locked);
    require_query_workspace(destination, size);
    expect_hash_stage("args.verify.enter");
    memcpy(destination, source, size);
    if (argument_corrupt) *(unsigned char *)destination ^= 1;
    return argument_readback_fail ? -164 : 0;
}
SceUID ksceKernelCreateMutex(const char *name, unsigned int attr, int count, const void *options) {
    (void)name; (void)attr; (void)options;
    assert(!mutex_live && count == 0);
    mutex_live = 1;
    return 1;
}
int ksceKernelDeleteMutex(SceUID id) { assert(id == 1 && mutex_live && !locked); mutex_live = 0; return 0; }
int ksceKernelLockMutex(SceUID id, int count, unsigned int *timeout) {
    assert(id == 1 && count == 1 && timeout == NULL && mutex_live && !locked);
    locked = 1;
    return 0;
}
int ksceKernelUnlockMutex(SceUID id, int count) { assert(id == 1 && count == 1 && locked); locked = 0; return 0; }
int ksceKernelGetModuleInfo(SceUID pid, SceUID id, SceKernelModuleInfo *info) {
    /* The loader only queries the target module it was handed */
    assert(pid == 99 && id == 88 && info->size == sizeof(*info));
    require_query_workspace(info, sizeof(*info));
    assert(info->module_name[sizeof(info->module_name) - 1] == 0);
    ++target_queries;
    if (target_info_error) return -1;
    info->modid = target_user_id;
    info->segments[0].vaddr = (void *)(uintptr_t)0x81000000;
    strcpy(info->module_name, target_wrong_name ? "unexpected" : "ScePsp2Compat");
    return 0;
}
SceUID ksceKernelLoadStartModuleForPid(SceUID pid, const char *path, SceSize size, const void *data,
    int flags, const void *options, int *status) {
    const VitalsBrowserStartArgs *args = data;
    assert(pid == 99 && size == sizeof(*args) && options == NULL && !locked);
    assert(argument_live && data == argument_memory);
    assert(flags == 0);
    assert(args->compat_modid == 188 && args->reserved == 0);
    assert(args->version == 1 && strcmp(path, VITALS_BROWSER_PROVIDER_BOOT_PATH) == 0);
    assert(args->magic == VITALS_BROWSER_START_MAGIC);
    ++loads;
    if (reenter) {
        assert(vitals_kernel_inject_browser_for_pid(pid, 88, expected_path) == 1);
    }
    if (load_error) return load_error == 2 ? 0 : -456;
    *status = start_error ? SCE_KERNEL_START_FAILED : SCE_KERNEL_START_SUCCESS;
    return 777;
}
int ksceKernelUnloadModuleForPid(SceUID pid, SceUID id, int flags, const void *options) {
    assert(pid == 99 && id == 777 && flags == 0 && options == NULL && !locked);
    ++unloads;
    return 0;
}

static void reset(void) {
    vitals_kernel_loader_destroy();
    assert(!argument_live && argument_allocations == argument_frees);
    assert(open_descriptors == 0 && !workspace_live && allocations == frees);
    assert(!query_live && query_allocations == query_frees);
    stream_blocks = 1;
    loads = unloads = 0;
    load_error = start_error = reenter = corrupt_browser = close_error = 0;
    target_info_error = 0;
    target_wrong_name = 0;
    target_user_id = 188;
    browser_file = 1;
    expected_path = "wb0:/vitals/" VITALS_BROWSER_PROVIDER_FILENAME;
    expected_module_path = "wb0:/vitals/ScePsp2Compat.suprx";
    runtime_namespace_required = namespace_provider_error = namespace_hash_error = 0;
    namespace_stat_error = namespace_close_error = 0;
    namespace_provider_opens = namespace_hash_opens = global_provider_stats = 0;
}

static void test_workspace_failures(void) {
    int *const failures[] = {&alloc_fail, &base_fail, &null_base, &free_fail};
    reset();
    assert(vitals_kernel_loader_init() == 0);
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        *failures[i] = 1;
        unsigned int before = (unsigned int)loads;
        assert(vitals_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
        assert(!workspace_live && allocations == frees && open_descriptors == 0 && (unsigned int)loads == before);
        *failures[i] = 0;
        assert(vitals_kernel_inject_browser_for_pid(99, 88, expected_path) == 0);
    }
    reset();
}

static void test_query_workspace_failures(void) {
    int *const failures[] = {&query_alloc_fail, &query_base_fail, &query_null_base, &query_free_fail};
    reset();
    assert(vitals_kernel_loader_init() == 0);
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        *failures[i] = 1;
        unsigned int before = (unsigned int)loads;
        assert(vitals_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
        assert(!query_live && query_allocations == query_frees);
        assert(!workspace_live && allocations == frees && open_descriptors == 0 && !locked);
        if (i < 3) assert((unsigned int)loads == before);
        *failures[i] = 0;
        assert(vitals_kernel_inject_browser_for_pid(99, 88, expected_path) == 0);
    }
    reset();
}

static void test_extended_stack_contract(void) {
    int *const failures[] = {&stack_error, &stack_skip, &stack_error_after};
    reset();
    assert(vitals_kernel_loader_init() == 0);
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        unsigned int before = stack_calls, before_alloc = query_allocations;
        int before_loads = loads, before_unloads = unloads;
        *failures[i] = 1;
        assert(vitals_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
        /* An error reported after the native-stack call ran comes after the provider loaded */
        assert(stack_calls == before + 1 && loads == before_loads + (i == 2) && unloads == before_unloads);
        assert(!query_live && query_allocations == query_frees);
        assert(!workspace_live && allocations == frees && !locked);
        if (i < 2) assert(query_allocations == before_alloc);
        *failures[i] = 0;
        assert(vitals_kernel_inject_browser_for_pid(99, 88, expected_path) == 0);
    }
    reset();
}

/* Failure paths the loader must survive, run by the production test */
static void test_loader_failure_paths(void) {
    reset();
    assert(vitals_kernel_loader_init() == 0);
    assert(vitals_kernel_browser_loader_ready());
    reenter = 1;
    assert(vitals_kernel_inject_browser_for_pid(99, 88, expected_path) == 0 && loads == 1);
    reenter = 0;
    corrupt_browser = 1;
    assert(vitals_kernel_inject_browser_for_pid(99, 88, expected_path) < 0 && loads == 1);
    corrupt_browser = 0;
    assert(vitals_kernel_inject_browser_for_pid(99, 88, expected_path) == 0 && loads == 2);
    start_error = 1;
    assert(vitals_kernel_inject_browser_for_pid(99, 88, expected_path) < 0 && loads == 3 && unloads == 1);
    start_error = 0; load_error = 1;
    assert(vitals_kernel_inject_browser_for_pid(99, 88, expected_path) == -456 && loads == 4);
    reset();
    assert(!mutex_live && !locked);
}
