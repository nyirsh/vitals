#include "crypto_platform.h"

#include <mbedtls/platform.h>
#include <mbedtls/platform_time.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/threading.h>
#include <psa/crypto.h>

#include <sys/random_number.h>
#include <sys/synchronization.h>
#include <sys/sys_time.h>
#include <sys/systime.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/* What TF-PSA-Crypto needs from the system, for vitals' libssl: mutexes and condition variables,
 * entropy and the time, from liblv2 and the kernel (as vitals' tls13-vita/provider/platform_shims.c
 * on the Vita); the date from a time is gmtime.c's */

/* sys_get_random_number's largest request (RANDOM_NUMBER_MAX_SIZE); Sony's libssl asks for less */
#define VITALS_RANDOM_MAX_REQUEST ((size_t)4096)
/* 9999-12-31 23:59:59, the last second X.509's dates can name */
#define VITALS_LAST_SECOND INT64_C(253402300799)

static int g_threading_initialized;

static int mutex_init(mbedtls_platform_mutex_t *mutex)
{
	sys_lwmutex_attribute_t attr;
	sys_lwmutex_attribute_initialize(attr);
	sys_lwmutex_attribute_name_set(attr.name, "vcrypto");
	mutex->created = sys_lwmutex_create(&mutex->lwmutex, &attr) == 0;
	return mutex->created ? 0 : PSA_ERROR_INSUFFICIENT_MEMORY;
}

static void mutex_free(mbedtls_platform_mutex_t *mutex)
{
	if (mutex->created)
		(void)sys_lwmutex_destroy(&mutex->lwmutex);
	mutex->created = 0;
}

static int mutex_lock(mbedtls_platform_mutex_t *mutex)
{
	return !mutex->created || sys_lwmutex_lock(&mutex->lwmutex, 0) != 0 ? MBEDTLS_ERR_THREADING_USAGE_ERROR : 0;
}

static int mutex_unlock(mbedtls_platform_mutex_t *mutex)
{
	return !mutex->created || sys_lwmutex_unlock(&mutex->lwmutex) != 0 ? MBEDTLS_ERR_THREADING_USAGE_ERROR : 0;
}

/* liblv2 ties a condition to its mutex when it creates it, which TF-PSA-Crypto's init doesn't
 * give: it is created on the first wait, with the mutex waited on */
static int condition_init(mbedtls_platform_condition_variable_t *condition)
{
	condition->lwmutex = NULL;
	__atomic_store_n(&condition->created, 0, __ATOMIC_RELEASE);
	return 0;
}

static void condition_free(mbedtls_platform_condition_variable_t *condition)
{
	if (__atomic_load_n(&condition->created, __ATOMIC_ACQUIRE))
		(void)sys_lwcond_destroy(&condition->lwcond);
	__atomic_store_n(&condition->created, 0, __ATOMIC_RELEASE);
	condition->lwmutex = NULL;
}

/* Nobody can be waiting on a condition not yet created */
static int condition_signal(mbedtls_platform_condition_variable_t *condition)
{
	if (!__atomic_load_n(&condition->created, __ATOMIC_ACQUIRE))
		return 0;
	return sys_lwcond_signal(&condition->lwcond) != 0 ? MBEDTLS_ERR_THREADING_USAGE_ERROR : 0;
}

static int condition_broadcast(mbedtls_platform_condition_variable_t *condition)
{
	if (!__atomic_load_n(&condition->created, __ATOMIC_ACQUIRE))
		return 0;
	return sys_lwcond_signal_all(&condition->lwcond) != 0 ? MBEDTLS_ERR_THREADING_USAGE_ERROR : 0;
}

/* Called with the mutex held, so the creation is never raced */
static int condition_wait(mbedtls_platform_condition_variable_t *condition, mbedtls_platform_mutex_t *mutex)
{
	if (!mutex->created)
		return MBEDTLS_ERR_THREADING_USAGE_ERROR;
	if (!__atomic_load_n(&condition->created, __ATOMIC_ACQUIRE)) {
		sys_lwcond_attribute_t attr;
		sys_lwcond_attribute_initialize(attr);
		sys_lwcond_attribute_name_set(attr.name, "vcrypto");
		if (sys_lwcond_create(&condition->lwcond, &mutex->lwmutex, &attr) != 0)
			return MBEDTLS_ERR_THREADING_USAGE_ERROR;
		condition->lwmutex = &mutex->lwmutex;
		__atomic_store_n(&condition->created, 1, __ATOMIC_RELEASE);
	}
	if (condition->lwmutex != &mutex->lwmutex)
		return MBEDTLS_ERR_THREADING_USAGE_ERROR;
	return sys_lwcond_wait(&condition->lwcond, 0) != 0 ? MBEDTLS_ERR_THREADING_USAGE_ERROR : 0;
}

/* TF-PSA-Crypto's entropy: the kernel's random numbers, as Sony's libssl's; a failure leaves
 * nothing behind */
int mbedtls_platform_get_entropy(psa_driver_get_entropy_flags_t flags, size_t *estimate_bits,
								 unsigned char *output, size_t output_size)
{
	if (estimate_bits == NULL)
		return PSA_ERROR_INVALID_ARGUMENT;
	*estimate_bits = 0;
	if (flags != PSA_DRIVER_GET_ENTROPY_FLAGS_NONE)
		return PSA_ERROR_NOT_SUPPORTED;
	if ((output == NULL && output_size != 0) || output_size > SIZE_MAX / 8)
		return PSA_ERROR_INVALID_ARGUMENT;
	for (size_t at = 0; at < output_size;) {
		size_t count = output_size - at < VITALS_RANDOM_MAX_REQUEST ? output_size - at : VITALS_RANDOM_MAX_REQUEST;
		if (sys_get_random_number(output + at, count) != 0) {
			mbedtls_platform_zeroize(output, output_size);
			return PSA_ERROR_INSUFFICIENT_ENTROPY;
		}
		at += count;
	}
	*estimate_bits = output_size * 8;
	return 0;
}

/* The kernel's clock: seconds since 1970, UTC */
int64_t vitals_crypto_time(int64_t *output)
{
	u64 seconds, nanoseconds;
	int64_t result = -1;
	if (sysGetCurrentTime(&seconds, &nanoseconds) == 0 && seconds <= (u64)VITALS_LAST_SECOND)
		result = (int64_t)seconds;
	if (output != NULL)
		*output = result;
	return result;
}

/* Microseconds since the console started */
mbedtls_ms_time_t mbedtls_ms_time(void)
{
	return (mbedtls_ms_time_t)(sys_time_get_system_time() / 1000);
}

int vitals_crypto_platform_init(void)
{
	/* Certificates can't be checked without the date */
	if (g_threading_initialized || vitals_crypto_time(NULL) < 0)
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
