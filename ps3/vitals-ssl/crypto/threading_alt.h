#ifndef VITALS_THREADING_ALT_H
#define VITALS_THREADING_ALT_H

#if defined(__PPU__)

#include <sys/synchronization.h>

/* TF-PSA-Crypto's mutexes and condition variables are liblv2's lightweight ones
 * (../src/platform/crypto_platform.c); a condition is created on its first wait, as liblv2 ties it
 * to its mutex (as on the Vita, vitals' tls13-vita/crypto/threading_alt.h) */
typedef struct
{
	sys_lwmutex_t lwmutex;
	int created;
} mbedtls_platform_mutex_t;

typedef struct
{
	sys_lwcond_t lwcond;
	sys_lwmutex_t *lwmutex;
	int created;
} mbedtls_platform_condition_variable_t;

#else

#include <pthread.h>

/* On a host, for the tests: pthread's (../../tests/host/crypto_platform_posix.c) */
typedef struct
{
	pthread_mutex_t mutex;
} mbedtls_platform_mutex_t;

typedef struct
{
	pthread_cond_t cond;
} mbedtls_platform_condition_variable_t;

#endif

#endif
