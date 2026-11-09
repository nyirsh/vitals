#ifndef VITALS_APP_TEST_DIRENT_H
#define VITALS_APP_TEST_DIRENT_H
#include <psp2/types.h>

/* A folder's entries, as the installer reads them (vita_files.c): only the name, as it uses */
typedef struct {
    char d_name[256];
} SceIoDirent;

SceUID sceIoDopen(const char *dirname);
int sceIoDread(SceUID fd, SceIoDirent *dir);
int sceIoDclose(SceUID fd);

#endif
