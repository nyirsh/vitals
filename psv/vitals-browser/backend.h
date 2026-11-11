#ifndef VITALS_BROWSER_BACKEND_H
#define VITALS_BROWSER_BACKEND_H

#include "vitals/browser_abi.h"

#include <stddef.h>
#include <stdint.h>

typedef struct VitalsBrowserOps {
    int (*timeleft)(void *easy, void *now, int during_connect);
    int (*socket_wait)(int read_fd, int read_fd2, int write_fd, int timeout_ms);
    VitalsBrowserContextCallbackValidator is_default_ctx_callback;
    const char *default_ciphers;
    /* The engine's own d2i_X509 and X509_free, for the certificates a refused connection reports
     * to WebKit (NULL: nothing is reported) */
    void *(*d2i_x509)(void **certificate, const unsigned char **der, long size);
    void (*x509_free)(void *certificate);
    /* What the record is allocated with: the engine's C library, which frees it with the request */
    void *(*record_calloc)(size_t count, size_t size);
    void (*record_free)(void *memory);
} VitalsBrowserOps;

typedef int (*VitalsBrowserRecv)(void *connection, int index, void *data,
    unsigned int length, int *error);
typedef int (*VitalsBrowserSend)(void *connection, int index, const void *data,
    unsigned int length, int *error);

int vitals_browser_init(const VitalsBrowserOps *ops);
void vitals_browser_enable(int enabled);
int vitals_browser_destroy(void);
size_t vitals_browser_connection_count(void);
int vitals_browser_connect(void *connection, int index, unsigned char nonblocking,
    unsigned char *done, int *handled);
int vitals_browser_pending(void *connection, int index, int *handled);
int vitals_browser_check(void *connection, int *handled);
int vitals_browser_close(void *connection, int index, int *handled);
int vitals_browser_recv(void *connection, int index, void *data,
    unsigned int length, int *error);
int vitals_browser_send(void *connection, int index, const void *data,
    unsigned int length, int *error);

#endif
