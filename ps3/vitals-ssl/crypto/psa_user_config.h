#ifndef VITALS_PSA_USER_CONFIG_H
#define VITALS_PSA_USER_CONFIG_H

/* TF-PSA-Crypto's options, for Mbed TLS 4.2 in vitals' libssl: the system's own mutexes, entropy
 * and time (../src/platform/crypto_platform.c), its memory from libssl's pool, and no files. As
 * vitals' tls13-vita/crypto/psa_user_config.h, with the pool */

#include <stdint.h>

#undef MBEDTLS_THREADING_PTHREAD
#define MBEDTLS_THREADING_C
#define MBEDTLS_THREADING_ALT
#undef MBEDTLS_PSA_BUILTIN_GET_ENTROPY
#define MBEDTLS_PSA_DRIVER_GET_ENTROPY
#define MBEDTLS_PLATFORM_MS_TIME_ALT
#define MBEDTLS_PLATFORM_GMTIME_R_ALT
#define MBEDTLS_PLATFORM_TIME_TYPE_MACRO int64_t
#define MBEDTLS_PLATFORM_TIME_MACRO vitals_crypto_time
/* calloc and free from the pool cellSslInit is given, as Sony's libssl does (none before it,
 * ../src/platform/pool.c) */
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_STD_CALLOC vitals_pool_calloc
#define MBEDTLS_PLATFORM_STD_FREE vitals_pool_free

/* No assembly: Mbed TLS's PowerPC64 multiply (bn_mul.h) uses pointers as 64-bit registers hold
 * them, and on the PS3 (32-bit pointers, ILP32) their upper halves needn't be clear, which GCC's
 * own code allows for and the assembly doesn't: it crashed in mbedtls_mpi_core_mul on the console
 * and in RPCS3 */
#undef MBEDTLS_HAVE_ASM

#undef MBEDTLS_FS_IO
#undef MBEDTLS_PSA_ITS_FILE_C
#undef MBEDTLS_PSA_CRYPTO_STORAGE_C
#undef MBEDTLS_SELF_TEST

#ifdef __cplusplus
extern "C" {
#endif
#include <stddef.h>
int64_t vitals_crypto_time(int64_t *output);
void *vitals_pool_calloc(size_t count, size_t size);
void vitals_pool_free(void *memory);
#ifdef __cplusplus
}
#endif

#endif
