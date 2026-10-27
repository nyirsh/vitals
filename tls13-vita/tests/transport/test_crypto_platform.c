#include <vita_mock.h>
#include "crypto_platform.h"
#include <mbedtls/platform.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/threading.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* platform_shims.c's entropy source, which Mbed TLS declares privately */
int mbedtls_hardware_poll(void *data, unsigned char *output, size_t length, size_t *produced);

static mbedtls_threading_mutex_t mutex;
static int counter;

static void *count_worker(void *unused) {
    (void)unused;
    for (int i = 0; i < 1000; ++i) {
        assert(mbedtls_mutex_lock(&mutex) == 0);
        ++counter;
        assert(mbedtls_mutex_unlock(&mutex) == 0);
    }
    return NULL;
}

int main(void) {
    unsigned char random[200];
    size_t produced = 999;
    int64_t seconds = INT64_C(1709164800);
    struct tm date;
    pthread_t workers[2];

    /* The kernel's random numbers, 64 bytes a call at most; a failure leaves nothing behind */
    assert(mbedtls_hardware_poll(NULL, random, sizeof(random), &produced) == 0);
    assert(produced == sizeof(random));
    assert(mock_entropy_calls == 4 && mock_entropy_max_request == 64);
    mock_entropy_calls = 0;
    mock_entropy_fail_after = 1;
    memset(random, 0xab, sizeof(random));
    assert(mbedtls_hardware_poll(NULL, random, sizeof(random), &produced) != 0);
    assert(produced == 0);
    for (size_t i = 0; i < sizeof(random); ++i) assert(random[i] == 0);
    mock_entropy_fail_after = -1;

    /* No date, no TLS: certificates can't be checked */
    mock_clock_failure = 1;
    assert(vitals_crypto_platform_init() != 0);
    mock_clock_failure = 0;
    assert(vitals_crypto_platform_init() == 0);
    assert(vitals_crypto_platform_init() != 0);
    assert(psa_crypto_init() == PSA_SUCCESS);
    assert(psa_generate_random(random, sizeof(random)) == PSA_SUCCESS);
    assert(mbedtls_platform_gmtime_r(&seconds, &date) == &date);
    assert(date.tm_year == 124 && date.tm_mon == 1 && date.tm_mday == 29 && date.tm_yday == 59);
    assert(vitals_crypto_time(NULL) >= (int64_t)time(NULL) - 2);

    /* The kernel's mutexes keep two threads apart */
    mbedtls_mutex_init(&mutex);
    for (int i = 0; i < 2; ++i) assert(pthread_create(&workers[i], NULL, count_worker, NULL) == 0);
    for (int i = 0; i < 2; ++i) assert(pthread_join(workers[i], NULL) == 0);
    assert(counter == 2000);
    mbedtls_mutex_free(&mutex);
    mbedtls_psa_crypto_free();
    vitals_crypto_platform_free();
    puts("crypto platform: entropy bounds/failure, PSA, UTC, mutexes PASS");
    return 0;
}
