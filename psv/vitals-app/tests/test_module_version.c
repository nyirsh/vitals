/* Host test of reading a module's version from its file header, on module files built here the
 * way vita-make-fself lays them out (compressed or not), and on damaged ones */
#include "module_version.h"
#include "vita_files.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

#define MODULE "ux0:module.suprx"
#define ELF_OFFSET 0x100u
#define SEGMENT_INFO_OFFSET 0x200u
#define SEGMENT_OFFSET 0x300u

enum Damage { INTACT, NOT_A_SELF, BAD_ELF, BAD_SEGMENT, CUT_STREAM, SHORT_SEGMENT };

static void put32(uint8_t *data, uint32_t value)
{
    for (int i = 0; i < 4; ++i)
        data[i] = (uint8_t)(value >> (8 * i));
}

static void put64(uint8_t *data, uint64_t value)
{
    put32(data, (uint32_t)value);
    put32(data + 4, (uint32_t)(value >> 32));
}

/* A module whose info (version major.minor) sits at info_offset in its first segment */
static void write_module(unsigned major, unsigned minor, size_t info_offset, int compressed, enum Damage damage)
{
    size_t plain_size = info_offset + 32;
    uint8_t *plain = calloc(1, plain_size);
    memset(plain, 0xA5, info_offset);
    plain[info_offset + 2] = (uint8_t)minor;
    plain[info_offset + 3] = (uint8_t)major;
    memcpy(plain + info_offset + 4, "vitals_test", sizeof("vitals_test"));

    uLongf segment_size = compressBound((uLong)plain_size);
    uint8_t *segment = malloc(segment_size);
    if (compressed)
        assert(compress(segment, &segment_size, plain, (uLong)plain_size) == Z_OK);
    else
        memcpy(segment, plain, segment_size = (uLongf)plain_size);
    if (damage == CUT_STREAM)
        segment_size /= 2;

    size_t size = SEGMENT_OFFSET + segment_size;
    uint8_t *file = calloc(1, size);
    memcpy(file, damage == NOT_A_SELF ? "ELF\0" : "SCE\0", 4);
    put64(file + 0x40, ELF_OFFSET);
    put64(file + 0x58, damage == BAD_SEGMENT ? size : SEGMENT_INFO_OFFSET);
    memcpy(file + ELF_OFFSET, damage == BAD_ELF ? "\x7f" "ELX" : "\x7f" "ELF", 4);
    /* Segment 0, at info_offset */
    put32(file + ELF_OFFSET + 24, (uint32_t)info_offset);
    file[ELF_OFFSET + 44] = 1;
    put64(file + SEGMENT_INFO_OFFSET, SEGMENT_OFFSET);
    put64(file + SEGMENT_INFO_OFFSET + 8, damage == SHORT_SEGMENT ? info_offset : segment_size);
    put64(file + SEGMENT_INFO_OFFSET + 16, compressed ? 2 : 1);
    memcpy(file + SEGMENT_OFFSET, segment, segment_size);

    FILE *out = fopen(vita_files_path(MODULE), "wb");
    assert(out != NULL && fwrite(file, 1, size, out) == size && fclose(out) == 0);
    free(file);
    free(segment);
    free(plain);
}

static int version(unsigned *major, unsigned *minor)
{
    *major = *minor = 99;
    return vitals_module_version(MODULE, major, minor);
}

int main(void)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/vitals-module-version-XXXXXX", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp");
    assert(mkdtemp(root) != NULL);
    vita_files_root(root);
    char ux0[1100];
    snprintf(ux0, sizeof(ux0), "%s/ux0", root);
    assert(mkdir(ux0, 0700) == 0);
    unsigned major, minor;

    /* No module file */
    assert(version(&major, &minor) < 0 && major == 99);

    /* Compressed, as vitals builds its modules, and uncompressed; near the start of the segment
     * and deep inside it */
    write_module(1, 2, 0x28, 1, INTACT);
    assert(version(&major, &minor) == 0 && major == 1 && minor == 2);
    write_module(12, 34, 0x3028, 1, INTACT);
    assert(version(&major, &minor) == 0 && major == 12 && minor == 34);
    write_module(3, 0, 0x678, 0, INTACT);
    assert(version(&major, &minor) == 0 && major == 3 && minor == 0);

    /* Anything that is not such a module, or is cut short, is refused */
    const enum Damage damages[] = {NOT_A_SELF, BAD_ELF, BAD_SEGMENT, CUT_STREAM, SHORT_SEGMENT};
    for (size_t i = 0; i < sizeof(damages) / sizeof(damages[0]); ++i) {
        for (int compressed = 0; compressed < 2; ++compressed) {
            if (damages[i] == CUT_STREAM && !compressed)
                continue;
            write_module(1, 2, 0x3028, compressed, damages[i]);
            assert(version(&major, &minor) < 0 && major == 99 && minor == 99);
        }
    }

    assert(unlink(vita_files_path(MODULE)) == 0 && rmdir(ux0) == 0 && rmdir(root) == 0);
    puts("module version: compressed and plain modules, damaged and missing files PASS");
    return 0;
}
