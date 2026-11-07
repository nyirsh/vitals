#ifndef VITALS_CRYPTO_PLATFORM_H
#define VITALS_CRYPTO_PLATFORM_H

#include <stdint.h>

/* Mbed TLS's mutexes (liblv2's), before its first use; 0, or negative without the date (as vitals'
 * tls13-vita/provider/crypto_platform.h) */
int vitals_crypto_platform_init(void);
void vitals_crypto_platform_free(void);
/* The time in seconds since 1970, or -1; Mbed TLS's time (MBEDTLS_PLATFORM_TIME_MACRO) */
int64_t vitals_crypto_time(int64_t *output);

#endif
