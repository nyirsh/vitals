#ifndef VITALS_APP_PSA_USER_CONFIG_H
#define VITALS_APP_PSA_USER_CONFIG_H

/* TF-PSA-Crypto's options for the app's curl (curl/): as vitals' libssl's
 * (../../vitals-ssl/crypto/psa_user_config.h), with its mutexes, entropy and time
 * (../../vitals-ssl/src/platform/crypto_platform.c, gmtime.c), but its memory from the app's own
 * malloc rather than a pool */

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

/* No assembly: Mbed TLS's PowerPC64 multiply crashes with the PS3's 32-bit pointers (see libssl's) */
#undef MBEDTLS_HAVE_ASM

/* curl is given its CAs in memory (CURLOPT_CAINFO_BLOB), so no files */
#undef MBEDTLS_FS_IO
#undef MBEDTLS_PSA_ITS_FILE_C
#undef MBEDTLS_PSA_CRYPTO_STORAGE_C
#undef MBEDTLS_SELF_TEST

#ifdef __cplusplus
extern "C" {
#endif
int64_t vitals_crypto_time(int64_t *output);
#ifdef __cplusplus
}
#endif

#endif
