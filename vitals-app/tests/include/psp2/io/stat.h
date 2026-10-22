#ifndef VITALS_APP_TEST_STAT_H
#define VITALS_APP_TEST_STAT_H
#include <psp2/types.h>

int sceIoGetstat(const char *path, SceIoStat *status);
int sceIoMkdir(const char *path, int mode);
int sceIoRmdir(const char *path);

#endif
