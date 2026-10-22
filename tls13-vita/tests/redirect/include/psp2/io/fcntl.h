#ifndef VITALS_REDIRECT_TEST_FCNTL_H
#define VITALS_REDIRECT_TEST_FCNTL_H
#include <psp2/types.h>

/* File functions, implemented by the test */
#define SCE_O_RDONLY 0x0001
SceUID sceIoOpen(const char *path, int flags, int mode);
int sceIoRead(SceUID fd, void *data, SceSize size);
int sceIoClose(SceUID fd);

#endif
