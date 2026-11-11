#ifndef VITALS_APP_TEST_TYPES_H
#define VITALS_APP_TEST_TYPES_H
#include <stddef.h>
#include <stdint.h>

/* The Vita types the installer uses, for host tests */
typedef int32_t SceUID;
typedef uint32_t SceSize;
typedef int32_t SceSSize;
typedef int64_t SceOff;
typedef uint32_t SceUInt;
typedef struct {
    uint64_t st_size;
} SceIoStat;
typedef struct {
    SceSize size;
    char versionString[0x1C];
    SceUInt version;
    SceUInt unk_24;
} SceKernelFwInfo;

#endif
