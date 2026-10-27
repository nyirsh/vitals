#ifndef VITALS_THREADING_ALT_H
#define VITALS_THREADING_ALT_H

/* Mbed TLS's mutexes are the kernel's (../provider/platform_shims.c) */
typedef struct
{
    int uid;
} mbedtls_threading_mutex_t;

#endif
