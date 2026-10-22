#ifndef VITALS_KERNEL_LOADER_H
#define VITALS_KERNEL_LOADER_H

#include <psp2kern/types.h>

#ifdef __cplusplus
extern "C" {
#endif

int vitals_kernel_loader_init(void);
void vitals_kernel_loader_destroy(void);
int vitals_kernel_loader_ready(void);
int vitals_kernel_http_process_allowed(SceUID pid);
int vitals_kernel_inject_for_pid(SceUID pid, SceUID libhttp_modid);
int vitals_kernel_browser_loader_ready(void);
int vitals_kernel_inject_browser_for_pid(SceUID pid, SceUID compat_modid, const char *provider_path);

#ifdef __cplusplus
}
#endif

#endif
