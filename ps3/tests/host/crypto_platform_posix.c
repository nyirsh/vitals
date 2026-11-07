/* What TF-PSA-Crypto needs from the system on a host, for the tests (in place of
 * vitals-ssl/src/platform/crypto_platform.c, the date being gmtime.c's on both): pthread's mutexes, the
 * system's entropy and clock */

#include "crypto_platform.h"

#include <mbedtls/platform.h>
#include <mbedtls/platform_time.h>
#include <mbedtls/threading.h>
#include <psa/crypto.h>

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

static int g_threading_initialized;

static int mutex_init(mbedtls_platform_mutex_t *mutex)
{
	return pthread_mutex_init(&mutex->mutex, NULL) == 0 ? 0 : PSA_ERROR_INSUFFICIENT_MEMORY;
}

static void mutex_free(mbedtls_platform_mutex_t *mutex)
{
	pthread_mutex_destroy(&mutex->mutex);
}

static int mutex_lock(mbedtls_platform_mutex_t *mutex)
{
	return pthread_mutex_lock(&mutex->mutex) == 0 ? 0 : MBEDTLS_ERR_THREADING_USAGE_ERROR;
}

static int mutex_unlock(mbedtls_platform_mutex_t *mutex)
{
	return pthread_mutex_unlock(&mutex->mutex) == 0 ? 0 : MBEDTLS_ERR_THREADING_USAGE_ERROR;
}

static int condition_init(mbedtls_platform_condition_variable_t *condition)
{
	return pthread_cond_init(&condition->cond, NULL) == 0 ? 0 : PSA_ERROR_INSUFFICIENT_MEMORY;
}

static void condition_free(mbedtls_platform_condition_variable_t *condition)
{
	pthread_cond_destroy(&condition->cond);
}

static int condition_signal(mbedtls_platform_condition_variable_t *condition)
{
	return pthread_cond_signal(&condition->cond) == 0 ? 0 : MBEDTLS_ERR_THREADING_USAGE_ERROR;
}

static int condition_broadcast(mbedtls_platform_condition_variable_t *condition)
{
	return pthread_cond_broadcast(&condition->cond) == 0 ? 0 : MBEDTLS_ERR_THREADING_USAGE_ERROR;
}

static int condition_wait(mbedtls_platform_condition_variable_t *condition, mbedtls_platform_mutex_t *mutex)
{
	return pthread_cond_wait(&condition->cond, &mutex->mutex) == 0 ? 0 : MBEDTLS_ERR_THREADING_USAGE_ERROR;
}

int mbedtls_platform_get_entropy(psa_driver_get_entropy_flags_t flags, size_t *estimate_bits,
                                 unsigned char *output, size_t output_size)
{
	if (estimate_bits == NULL)
		return PSA_ERROR_INVALID_ARGUMENT;
	*estimate_bits = 0;
	if (flags != PSA_DRIVER_GET_ENTROPY_FLAGS_NONE)
		return PSA_ERROR_NOT_SUPPORTED;
	for (size_t at = 0; at < output_size;) {
		size_t count = output_size - at < 256 ? output_size - at : 256;
		if (getentropy(output + at, count) != 0)
			return PSA_ERROR_INSUFFICIENT_ENTROPY;
		at += count;
	}
	*estimate_bits = output_size * 8;
	return 0;
}

int64_t vitals_crypto_time(int64_t *output)
{
	int64_t seconds = (int64_t)time(NULL);
	if (output != NULL)
		*output = seconds;
	return seconds;
}

mbedtls_ms_time_t mbedtls_ms_time(void)
{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	return (mbedtls_ms_time_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

int vitals_crypto_platform_init(void)
{
	if (g_threading_initialized)
		return -1;
	mbedtls_threading_set_alt(mutex_init, mutex_free, mutex_lock, mutex_unlock, condition_init, condition_free,
	                          condition_signal, condition_broadcast, condition_wait);
	g_threading_initialized = 1;
	return 0;
}

void vitals_crypto_platform_free(void)
{
	if (g_threading_initialized) {
		mbedtls_threading_free_alt();
		g_threading_initialized = 0;
	}
}
