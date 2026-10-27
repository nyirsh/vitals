#ifndef VH_THREADING_ALT_H
#define VH_THREADING_ALT_H

/* Mbed TLS's mutexes are the kernel's (tls_platform.c) */
typedef struct
{
    int uid;
} mbedtls_threading_mutex_t;

#endif
