#ifndef VITALS_PSA_USER_CONFIG_H
#define VITALS_PSA_USER_CONFIG_H

/* TF-PSA-Crypto's options, for Mbed TLS 4.2 in vitals-ssl: the Vita's own mutexes, entropy and
 * time (../provider/platform_shims.c), and no files */

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
