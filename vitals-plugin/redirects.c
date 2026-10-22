#include <vitasdkkern.h>

#include <stddef.h>

#include "vitals/redirects.h"

/* SCE_ERROR_ERRNO_EINVAL */
#define VITALS_REDIRECTS_INVALID ((int)0x80010016)

/* Games run in a sandbox that keeps them out of ux0:data, while the kernel is not; the list is
 * opened for each read, so edits apply to the next game that starts */
int vitals_redirects_read(unsigned int offset, void *buffer, unsigned int size) {
    char data[VITALS_REDIRECTS_CHUNK];
    int state, result;

    if (buffer == NULL || size == 0) {
        return VITALS_REDIRECTS_INVALID;
    }
    if (size > sizeof(data)) {
        size = sizeof(data);
    }
    ENTER_SYSCALL(state);
    SceUID fd = ksceIoOpen(VITALS_REDIRECTS_PATH, SCE_O_RDONLY, 0);
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
