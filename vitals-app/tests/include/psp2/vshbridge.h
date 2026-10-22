#ifndef VITALS_APP_TEST_VSHBRIDGE_H
#define VITALS_APP_TEST_VSHBRIDGE_H
#include <psp2/types.h>

int vshIoUmount(int id, int force, int unk2, int unk3);
int _vshIoMount(int id, const char *path, int permission, void *buffer);
int _vshSblGetSystemSwVersion(SceKernelFwInfo *info);

#endif
