#include <vitasdkkern.h>

#include <stddef.h>

#include "vitals/ca_store.h"
#include "vitals/redirects.h"
#include "vitals/switches.h"
#include "vitals/useragent.h"

/* SCE_ERROR_ERRNO_EINVAL, and ENOENT */
#define VITALS_REDIRECTS_INVALID ((int)0x80010016)
#define VITALS_REDIRECTS_NOT_FOUND ((int)0x80010002)

/* Games run in a sandbox that keeps them out of ux0:data, while the kernel is not; a file is
 * opened for each read, so edits apply to the next game that starts */
static int read_file(const char *path, unsigned int offset, void *buffer, unsigned int size) {
    char data[VITALS_REDIRECTS_CHUNK];
    int state, result;

    if (buffer == NULL || size == 0) {
        return VITALS_REDIRECTS_INVALID;
    }
    if (size > sizeof(data)) {
        size = sizeof(data);
    }
    ENTER_SYSCALL(state);
    SceUID fd = ksceIoOpen(path, SCE_O_RDONLY, 0);
    if (fd < 0) {
        result = fd;
    } else {
        result = ksceIoPread(fd, data, size, (SceOff)offset);
        (void)ksceIoClose(fd);
        /* The copy fails rather than writing outside the caller's memory */
        if (result > 0 && ksceKernelCopyToUser(buffer, data, (SceSize)result) < 0) {
            result = VITALS_REDIRECTS_INVALID;
        }
    }
    EXIT_SYSCALL(state);
    return result;
}

/* The redirect list, as missing while the Options' redirects.off is there (vitals/switches.h): a
 * process that starts then redirects nothing */
int vitals_redirects_read(unsigned int offset, void *buffer, unsigned int size) {
    SceIoStat status;
    int state, off;
    ENTER_SYSCALL(state);
    off = ksceIoGetstat(VITALS_REDIRECTS_OFF, &status) >= 0;
    EXIT_SYSCALL(state);
    if (off) {
        return VITALS_REDIRECTS_NOT_FOUND;
    }
    return read_file(VITALS_REDIRECTS_PATH, offset, buffer, size);
}

int vitals_useragent_read(void *buffer, unsigned int size) {
    return read_file(VITALS_USERAGENT_PATH, 0, buffer, size);
}

/* The certificate store, for vitals-ssl in every process: its parts read as one (ca_store.h), each
 * followed by a line break; a call copies up to VITALS_CA_READ_MAX bytes, a chunk at a time through
 * the kernel stack, as the store's index reads it all (some 260 KB). Each part's size is taken at
 * every call, so a certificate update or an edit of the user's file applies to the next process */
static const char *const ca_parts[] = {VITALS_CA_SONY_PATH, VITALS_CA_MOZILLA_PATH,
                                       VITALS_CUSTOM_CERTIFICATES_PATH};
#define CA_PARTS (sizeof(ca_parts) / sizeof(ca_parts[0]))

int vitals_ca_read(unsigned int offset, void *buffer, unsigned int size) {
    char data[VITALS_REDIRECTS_CHUNK];
    unsigned int lengths[CA_PARTS];
    int state, result = 0;
    unsigned int copied = 0;

    if (buffer == NULL || size == 0) {
        return VITALS_REDIRECTS_INVALID;
    }
    if (size > VITALS_CA_READ_MAX) {
        size = VITALS_CA_READ_MAX;
    }
    ENTER_SYSCALL(state);
    /* Sony's file is the store; the others may be missing (or empty), and then add nothing */
    for (size_t i = 0; i < CA_PARTS && result == 0; ++i) {
        SceIoStat status;
        int stat_result = ksceIoGetstat(ca_parts[i], &status);
        lengths[i] = 0;
        if (stat_result < 0) {
            if (i == 0) result = stat_result;
        } else if (status.st_size < 0 || status.st_size >= 0x40000000) {
            result = VITALS_REDIRECTS_INVALID;
        } else if (status.st_size > 0) {
            lengths[i] = (unsigned int)status.st_size;
        }
    }
    unsigned int start = 0;
    int cut_short = 0;
    for (size_t i = 0; i < CA_PARTS && result == 0 && !cut_short && copied < size; ++i) {
        /* The part, then its line break */
        unsigned int length = lengths[i];
        unsigned int end = length == 0 ? start : start + length + 1u;
        SceUID fd = -1;
        while (result == 0 && copied < size && offset + copied < end) {
            unsigned int position = offset + copied - start;
            int count = 1;
            if (position < length) {
                unsigned int want = size - copied;
                if (want > sizeof(data)) want = sizeof(data);
                if (want > length - position) want = length - position;
                if (fd < 0) {
                    fd = ksceIoOpen(ca_parts[i], SCE_O_RDONLY, 0);
                    if (fd < 0) {
                        result = fd;
                        break;
                    }
                }
                count = ksceIoPread(fd, data, want, (SceOff)position);
                if (count < 0) {
                    result = count;
                    break;
                }
                /* Shorter than its size said (rewritten meanwhile): the store ends here */
                if (count == 0) {
                    cut_short = 1;
                    break;
                }
            } else {
                data[0] = '\n';
            }
            /* The copy fails rather than writing outside the caller's memory */
            if (ksceKernelCopyToUser((char *)buffer + copied, data, (SceSize)count) < 0) {
                result = VITALS_REDIRECTS_INVALID;
                break;
            }
            copied += (unsigned int)count;
        }
        if (fd >= 0) {
            (void)ksceIoClose(fd);
        }
        start = end;
    }
    EXIT_SYSCALL(state);
    return result < 0 ? result : (int)copied;
}
