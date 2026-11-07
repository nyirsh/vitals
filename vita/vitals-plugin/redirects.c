#include <vitasdkkern.h>

#include <stddef.h>

#include "vitals/redirects.h"
#include "vitals/useragent.h"

/* SCE_ERROR_ERRNO_EINVAL */
#define VITALS_REDIRECTS_INVALID ((int)0x80010016)

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

int vitals_redirects_read(unsigned int offset, void *buffer, unsigned int size) {
    return read_file(VITALS_REDIRECTS_PATH, offset, buffer, size);
}

int vitals_useragent_read(void *buffer, unsigned int size) {
    return read_file(VITALS_USERAGENT_PATH, 0, buffer, size);
}
