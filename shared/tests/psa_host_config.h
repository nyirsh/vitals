#ifndef VITALS_PSA_HOST_CONFIG_H
#define VITALS_PSA_HOST_CONFIG_H

/* TF-PSA-Crypto's options for host tests that only read certificates (shared/app/tests/
 * test_ca_update.c on the Vita's tests): its defaults, with the system's entropy, and no threads or
 * files */

#undef MBEDTLS_THREADING_C
#undef MBEDTLS_THREADING_PTHREAD
#undef MBEDTLS_PSA_ITS_FILE_C
#undef MBEDTLS_PSA_CRYPTO_STORAGE_C
#undef MBEDTLS_SELF_TEST

#endif
