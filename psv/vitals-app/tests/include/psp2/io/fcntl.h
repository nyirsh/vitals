#ifndef VITALS_APP_TEST_FCNTL_H
#define VITALS_APP_TEST_FCNTL_H
#include <psp2/types.h>

/* Flags as in VitaSDK; vita_files.c maps them onto the host's */
#define SCE_O_RDONLY 0x0001
#define SCE_O_WRONLY 0x0002
#define SCE_O_RDWR 0x0003
#define SCE_O_APPEND 0x0100
#define SCE_O_CREAT 0x0200
#define SCE_O_TRUNC 0x0400
#define SCE_SEEK_SET 0
#define SCE_SEEK_CUR 1
#define SCE_SEEK_END 2

SceUID sceIoOpen(const char *path, int flags, int mode);
int sceIoClose(SceUID fd);
SceSSize sceIoRead(SceUID fd, void *data, SceSize size);
SceSSize sceIoWrite(SceUID fd, const void *data, SceSize size);
SceOff sceIoLseek(SceUID fd, SceOff offset, int whence);
int sceIoRemove(const char *path);
int sceIoRename(const char *from, const char *to);
int sceIoSync(const char *device, unsigned int flags);

#endif
