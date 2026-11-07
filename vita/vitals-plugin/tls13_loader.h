#ifndef VITALS_KERNEL_LOADER_H
#define VITALS_KERNEL_LOADER_H

#include <psp2kern/types.h>

#ifdef __cplusplus
extern "C" {
#endif

int vitals_kernel_loader_init(void);
void vitals_kernel_loader_destroy(void);
int vitals_kernel_browser_loader_ready(void);
/* The provider into pid, whose vitals' browser engine is compat_modid; ca_path is the certificate
 * store as that process names it, which the provider is given */
int vitals_kernel_inject_browser_for_pid(SceUID pid, SceUID compat_modid, const char *ca_path);
/* main.c: libssl loaded into pid and started as the system loads it for an app (shared, with
 * vitals' in place of Sony's): its module ID, or the loader's error; *started and *status are the
 * start's */
SceUID vitals_kernel_load_system_libssl(SceUID pid, int *started, int *status);

#ifdef __cplusplus
}
#endif

#endif
