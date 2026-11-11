#include "crypto_platform.h"

#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/rng.h>
#include <psp2/kernel/threadmgr/cond.h>
#include <psp2/kernel/threadmgr/mutex.h>
#include <psp2/rtc.h>

#include <mbedtls/platform.h>
#include <mbedtls/platform_time.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/threading.h>
#include <psa/crypto.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/* What TF-PSA-Crypto needs from the system, for vitals-ssl: mutexes and condition variables,
 * entropy and the time, from the kernel and the RTC */

#define VITALS_UNIX_EPOCH_TICKS UINT64_C(62135596800000000)
#define VITALS_UNIX_EPOCH_SECONDS INT64_C(62135596800)
#define VITALS_RNG_MAX_REQUEST ((size_t)64)

static int g_threading_initialized;

static int mutex_init(mbedtls_platform_mutex_t *mutex)
{
    mutex->uid = sceKernelCreateMutex("vitals crypto", 0, 0, NULL);
    return mutex->uid < 0 ? PSA_ERROR_INSUFFICIENT_MEMORY : 0;
}

static void mutex_free(mbedtls_platform_mutex_t *mutex)
{
    if (mutex->uid >= 0)
        (void)sceKernelDeleteMutex(mutex->uid);
    mutex->uid = -1;
}

static int mutex_lock(mbedtls_platform_mutex_t *mutex)
{
    return mutex->uid < 0 || sceKernelLockMutex(mutex->uid, 1, NULL) < 0 ? MBEDTLS_ERR_THREADING_USAGE_ERROR : 0;
}

static int mutex_unlock(mbedtls_platform_mutex_t *mutex)
{
    return mutex->uid < 0 || sceKernelUnlockMutex(mutex->uid, 1) < 0 ? MBEDTLS_ERR_THREADING_USAGE_ERROR : 0;
}

/* The kernel ties a condition to its mutex when it creates it, which TF-PSA-Crypto's init doesn't
 * give: it is created on the first wait, with the mutex waited on */
static int condition_init(mbedtls_platform_condition_variable_t *condition)
{
    condition->mutex_uid = -1;
    __atomic_store_n(&condition->uid, -1, __ATOMIC_RELEASE);
    return 0;
}

static void condition_free(mbedtls_platform_condition_variable_t *condition)
{
    int uid = __atomic_load_n(&condition->uid, __ATOMIC_ACQUIRE);
    if (uid >= 0)
        (void)sceKernelDeleteCond(uid);
    __atomic_store_n(&condition->uid, -1, __ATOMIC_RELEASE);
    condition->mutex_uid = -1;
}

/* Nobody can be waiting on a condition not yet created */
static int condition_signal(mbedtls_platform_condition_variable_t *condition)
{
    int uid = __atomic_load_n(&condition->uid, __ATOMIC_ACQUIRE);
    return uid >= 0 && sceKernelSignalCond(uid) < 0 ? MBEDTLS_ERR_THREADING_USAGE_ERROR : 0;
}

static int condition_broadcast(mbedtls_platform_condition_variable_t *condition)
{
    int uid = __atomic_load_n(&condition->uid, __ATOMIC_ACQUIRE);
    return uid >= 0 && sceKernelSignalCondAll(uid) < 0 ? MBEDTLS_ERR_THREADING_USAGE_ERROR : 0;
}

/* Called with the mutex held, so the creation is never raced */
static int condition_wait(mbedtls_platform_condition_variable_t *condition, mbedtls_platform_mutex_t *mutex)
{
    if (mutex->uid < 0)
        return MBEDTLS_ERR_THREADING_USAGE_ERROR;
    int uid = __atomic_load_n(&condition->uid, __ATOMIC_ACQUIRE);
    if (uid < 0) {
        uid = sceKernelCreateCond("vitals crypto", 0, mutex->uid, NULL);
        if (uid < 0)
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        condition->mutex_uid = mutex->uid;
        __atomic_store_n(&condition->uid, uid, __ATOMIC_RELEASE);
    }
    if (condition->mutex_uid != mutex->uid)
        return MBEDTLS_ERR_THREADING_USAGE_ERROR;
    return sceKernelWaitCond(uid, NULL) < 0 ? MBEDTLS_ERR_THREADING_USAGE_ERROR : 0;
}

/* TF-PSA-Crypto's entropy: the kernel's random numbers, at most 64 bytes a call; a failure leaves
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
        size_t count = output_size - at < VITALS_RNG_MAX_REQUEST ? output_size - at : VITALS_RNG_MAX_REQUEST;
        if (sceKernelGetRandomNumber(output + at, (SceSize)count) < 0) {
            mbedtls_platform_zeroize(output, output_size);
            return PSA_ERROR_INSUFFICIENT_ENTROPY;
        }
        at += count;
    }
    *estimate_bits = output_size * 8;
    return 0;
}

int64_t vitals_crypto_time(int64_t *output)
{
    SceRtcTick tick;
    int64_t seconds = -1;
    if (sceRtcGetCurrentTick(&tick) >= 0 && tick.tick >= VITALS_UNIX_EPOCH_TICKS)
        seconds = (int64_t)((tick.tick - VITALS_UNIX_EPOCH_TICKS) / UINT64_C(1000000));
    if (output != NULL)
        *output = seconds;
    return seconds;
}

mbedtls_ms_time_t mbedtls_ms_time(void)
{
    return (mbedtls_ms_time_t)(sceKernelGetSystemTimeWide() / UINT64_C(1000));
}

struct tm *mbedtls_platform_gmtime_r(const mbedtls_time_t *seconds, struct tm *result)
{
    SceDateTime date;
    SceRtcTick tick;

    if (seconds == NULL || result == NULL || *seconds < -VITALS_UNIX_EPOCH_SECONDS ||
        *seconds > INT64_C(253402300799))
        return NULL;
    tick.tick = (uint64_t)(*seconds + VITALS_UNIX_EPOCH_SECONDS) * UINT64_C(1000000);
    if (sceRtcSetTick(&date, &tick) < 0)
        return NULL;
    int yday = date.day - 1;
    for (int month = 1; month < date.month; ++month) {
        int days = sceRtcGetDaysInMonth(date.year, month);
        if (days < 0)
            return NULL;
        yday += days;
    }
    int wday = sceRtcGetDayOfWeek(date.year, date.month, date.day);
    if (wday < 0)
        return NULL;
    memset(result, 0, sizeof(*result));
    result->tm_year = date.year - 1900;
    result->tm_mon = date.month - 1;
    result->tm_mday = date.day;
    result->tm_hour = date.hour;
    result->tm_min = date.minute;
    result->tm_sec = date.second;
    result->tm_yday = yday;
    result->tm_wday = wday;
    return result;
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
