#ifndef VITALS_HOST_PPU_TYPES_H
#define VITALS_HOST_PPU_TYPES_H

/* PS3DK's ppu-types.h on a host, for the probe's host run (tests/host/http): its integer names
 * only. ATTRIBUTE_PRXPTR stays undefined, so PS3DK's cell/http headers make it empty and their
 * pointers the host's own */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

#endif
