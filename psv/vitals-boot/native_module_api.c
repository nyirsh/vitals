#include "native_module_api.h"
#include "vitals/firmware_profiles.h"
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/threadmgr/misc.h>
#include <taihen.h>

/* Exported by taihenModuleUtils, although omitted from the public header */
int module_get_export_func(SceUID pid, const char *module, uint32_t library,
    uint32_t function, uintptr_t *address);

static int (*get_info)(SceUID, SceUID, SceKernelModuleInfo *);
static int (*get_list)(SceUID, int, int, SceUID *, SceSize *);
static int (*unload_module)(SceUID, SceUID, int, const void *);
static int (*is_shared)(SceUID, void *);
static SceUID (*load_module)(SceUID, const char *, int, void *);
static int ready;

int vitals_native_module_api_init(void) {
    tai_module_info_t identity;
    const VitalsKernelProfile *profile = NULL;
    /* SceModulemgrForKernel as each firmware family exports it: get info, get list, unload and
     * is-shared */
    static const uint32_t libraries[VITALS_KERNEL_FAMILY_COUNT] = {
        [VITALS_KERNEL_FAMILY_360] = UINT32_C(0xc445fa63),
        [VITALS_KERNEL_FAMILY_365] = UINT32_C(0x92c9ffc2),
    };
    static const uint32_t nids[VITALS_KERNEL_FAMILY_COUNT][4] = {
        [VITALS_KERNEL_FAMILY_360] = {0xd269f915, 0x97cf7b4e, 0x5972e2cc, 0x99890202},
        [VITALS_KERNEL_FAMILY_365] = {0xdaa90093, 0xb72c75a4, 0xfca9fdb1, 0xf1de6949},
    };
    uintptr_t addresses[4] = {0};
    __atomic_store_n(&ready, 0, __ATOMIC_RELEASE);
    memset(&identity, 0, sizeof(identity));
    identity.size = sizeof(identity);
    if (taiGetModuleInfoForKernel(KERNEL_PID, "SceKernelModulemgr", &identity) < 0 ||
        memcmp(identity.name, "SceKernelModulemgr", sizeof("SceKernelModulemgr")) != 0) return -1;
    for (size_t i = 0; i < sizeof(vitals_kernel_profiles) / sizeof(vitals_kernel_profiles[0]); ++i) {
        if (identity.module_nid == vitals_kernel_profiles[i].module_nid) {
            profile = &vitals_kernel_profiles[i];
            break;
        }
    }
    if (profile == NULL) return -1;
    for (size_t i = 0; i < 4; ++i) {
        if (module_get_export_func(KERNEL_PID, "SceKernelModulemgr", libraries[profile->family],
                nids[profile->family][i], &addresses[i]) < 0 ||
            addresses[i] == 0) return -1;
    }
    get_info = (int (*)(SceUID, SceUID, SceKernelModuleInfo *))addresses[0];
    get_list = (int (*)(SceUID, int, int, SceUID *, SceSize *))addresses[1];
    unload_module = (int (*)(SceUID, SceUID, int, const void *))addresses[2];
    is_shared = (int (*)(SceUID, void *))addresses[3];
    /* ksceKernelLoadModuleForPid, which isn't needed to start: without it, only the browser engine's
     * load from ux0 goes without its last try (vitals-headers' db/360 and db/363) */
    static const uint32_t load_nids[VITALS_KERNEL_FAMILY_COUNT] = {
        [VITALS_KERNEL_FAMILY_360] = UINT32_C(0xfa21d8cb),
        [VITALS_KERNEL_FAMILY_365] = UINT32_C(0x4e85022d),
    };
    uintptr_t load_address = 0;
    load_module = NULL;
    if (module_get_export_func(KERNEL_PID, "SceKernelModulemgr", libraries[profile->family],
            load_nids[profile->family], &load_address) >= 0 && load_address != 0)
        load_module = (SceUID (*)(SceUID, const char *, int, void *))load_address;
    __atomic_store_n(&ready, 1, __ATOMIC_RELEASE);
    return 0;
}

int vitals_native_module_info(SceUID pid, SceUID module, SceKernelModuleInfo *info) {
    return __atomic_load_n(&ready, __ATOMIC_ACQUIRE) ? get_info(pid, module, info) : -1;
}
int vitals_native_module_list(SceUID pid, int flags1, int flags2, SceUID *modules, SceSize *count) {
    return __atomic_load_n(&ready, __ATOMIC_ACQUIRE) ? get_list(pid, flags1, flags2, modules, count) : -1;
}
int vitals_native_module_unload(SceUID pid, SceUID module, int flags, const void *options) {
    return __atomic_load_n(&ready, __ATOMIC_ACQUIRE) ? unload_module(pid, module, flags, options) : -1;
}
int vitals_native_module_shared(SceUID pid, void *address) {
    return __atomic_load_n(&ready, __ATOMIC_ACQUIRE) ? is_shared(pid, address) : -1;
}
SceUID vitals_native_module_load(SceUID pid, const char *path, int flags, void *options) {
    return __atomic_load_n(&ready, __ATOMIC_ACQUIRE) && load_module != NULL ? load_module(pid, path, flags, options) : -1;
}
