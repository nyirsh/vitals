#include "module_version.h"

#include <psp2/io/fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

/* Larger than any vitals module */
#define MODULE_MAX_SIZE 0x100000u
/* SceModuleInfo: attributes (2 bytes), minor and major version (1 byte each), then the name */
#define MODULE_INFO_VERSION 2u
#define SELF_ELF_OFFSET 0x40u
#define SELF_SEGMENT_INFO_OFFSET 0x58u
#define SEGMENT_INFO_SIZE 32u
#define SEGMENT_COMPRESSED 2u

static uint32_t read32(const uint8_t *data) {
    return (uint32_t)data[0] | (uint32_t)data[1] << 8 | (uint32_t)data[2] << 16 | (uint32_t)data[3] << 24;
}

static uint64_t read64(const uint8_t *data) {
    return (uint64_t)read32(data) | (uint64_t)read32(data + 4) << 32;
}

static int read_module(const char *path, uint8_t **data, size_t *size) {
    SceUID fd = sceIoOpen(path, SCE_O_RDONLY, 0);
    if (fd < 0) {
        return fd;
    }
    SceOff length = sceIoLseek(fd, 0, SCE_SEEK_END);
    int result = -1;
    *data = NULL;
    if (length > 0 && length <= MODULE_MAX_SIZE && sceIoLseek(fd, 0, SCE_SEEK_SET) == 0 &&
        (*data = malloc((size_t)length)) != NULL) {
        size_t total = 0;
        int count = 1;
        while (total < (size_t)length &&
               (count = sceIoRead(fd, *data + total, (SceSize)((size_t)length - total))) > 0) {
            total += (size_t)count;
        }
        result = total == (size_t)length ? 0 : (count < 0 ? count : -1);
    }
    (void)sceIoClose(fd);
    if (result < 0) {
        free(*data);
        *data = NULL;
    } else {
        *size = (size_t)length;
    }
    return result;
}

/* The first length bytes of a zlib stream, or -1 when the stream is shorter or damaged */
static int inflate_prefix(const uint8_t *in, size_t in_length, uint8_t *out, size_t length) {
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    if (inflateInit(&stream) != Z_OK) {
        return -1;
    }
    stream.next_in = (Bytef *)in;
    stream.avail_in = (uInt)in_length;
    stream.next_out = out;
    stream.avail_out = (uInt)length;
    int result = inflate(&stream, Z_SYNC_FLUSH);
    int filled = stream.avail_out == 0 && (result == Z_OK || result == Z_STREAM_END || result == Z_BUF_ERROR);
    (void)inflateEnd(&stream);
    return filled ? 0 : -1;
}

int vitals_module_version(const char *path, unsigned *major, unsigned *minor) {
    uint8_t *data, info[MODULE_INFO_VERSION + 2];
    size_t size;
    int result = read_module(path, &data, &size);
    if (result < 0) {
        return result;
    }
    result = -1;
    if (size < SELF_SEGMENT_INFO_OFFSET + 8 || memcmp(data, "SCE\0", 4) != 0) {
        goto done;
    }
    uint64_t elf = read64(data + SELF_ELF_OFFSET);
    uint64_t segments = read64(data + SELF_SEGMENT_INFO_OFFSET);
    if (elf > size - 52 || memcmp(data + elf, "\x7f" "ELF", 4) != 0) {
        goto done;
    }
    /* The entry field of a Vita ELF holds the segment of the module info (top two bits) and
     * its offset in that segment */
    uint32_t entry = read32(data + elf + 24);
    uint32_t segment = entry >> 30, offset = entry & UINT32_C(0x3fffffff);
    uint16_t count = (uint16_t)(data[elf + 44] | data[elf + 45] << 8);
    if (segment >= count || segments > size || (size - segments) / SEGMENT_INFO_SIZE <= segment) {
        goto done;
    }
    const uint8_t *entry_info = data + segments + segment * SEGMENT_INFO_SIZE;
    uint64_t start = read64(entry_info), length = read64(entry_info + 8);
    if (start > size || length > size - start || offset > MODULE_MAX_SIZE) {
        goto done;
    }
    if (read64(entry_info + 16) == SEGMENT_COMPRESSED) {
        uint8_t *prefix = malloc(offset + sizeof(info));
        if (prefix != NULL && inflate_prefix(data + start, (size_t)length, prefix, offset + sizeof(info)) == 0) {
            memcpy(info, prefix + offset, sizeof(info));
            result = 0;
        }
        free(prefix);
    } else if (offset + sizeof(info) <= length) {
        memcpy(info, data + start + offset, sizeof(info));
        result = 0;
    }
    if (result == 0) {
        *minor = info[MODULE_INFO_VERSION];
        *major = info[MODULE_INFO_VERSION + 1];
    }
done:
    free(data);
    return result;
}
