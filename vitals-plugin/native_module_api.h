#ifndef VITALS_NATIVE_MODULE_API_H
#define VITALS_NATIVE_MODULE_API_H

#include <psp2kern/kernel/modulemgr.h>

int vitals_native_module_api_init(void);
int vitals_native_module_info(SceUID pid, SceUID module, SceKernelModuleInfo *info);
int vitals_native_module_list(SceUID pid, int flags1, int flags2, SceUID *modules, SceSize *count);
int vitals_native_module_unload(SceUID pid, SceUID module, int flags, const void *options);
int vitals_native_module_shared(SceUID pid, void *address);
typedef struct VitalsNativeHttpConsumer {
    SceUID module;
    uint32_t library;
    uint16_t attributes;
    char name[28];
    uint32_t step;
    int32_t native_result;
} VitalsNativeHttpConsumer;
/* 0: private exports are compatible; 1: a shared HTTP/SSL consumer; <0: unknown */
int vitals_native_http_shared_consumer(SceUID pid, VitalsNativeHttpConsumer *consumer);

/* Host fixtures retain their native-service mocks
 * ARM uses resolved exports */
#if defined(__arm__)
#define ksceKernelGetModuleInfo vitals_native_module_info
#define ksceKernelGetModuleList vitals_native_module_list
#define ksceKernelUnloadModuleForPid vitals_native_module_unload
#define ksceKernelGetModuleIsSharedByAddr vitals_native_module_shared
#endif

#endif
