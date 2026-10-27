#include "vh.h"

#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/rng.h>
#include <psp2/kernel/threadmgr/mutex.h>
#include <psp2/rtc.h>

#include <mbedtls/platform_time.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/threading.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/* What Mbed TLS 3.6 needs from the system: mutexes, entropy and the time, from the kernel and the
 * RTC (as tls13-vita's platform_shims.c gives Mbed TLS 4) */

#define VH_UNIX_EPOCH_TICKS UINT64_C(62135596800000000)
#define VH_UNIX_EPOCH_SECONDS INT64_C(62135596800)
#define VH_RNG_MAX_REQUEST ((size_t)64)

/* Mbed TLS's own prototype is in a private header */
int mbedtls_hardware_poll(void *data, unsigned char *output, size_t length, size_t *produced);

static void mutex_init(mbedtls_threading_mutex_t *mutex)
{
    mutex->uid = sceKernelCreateMutex("vh tls", 0, 0, NULL);
}

static void mutex_free(mbedtls_threading_mutex_t *mutex)
{
    if (mutex->uid >= 0)
        (void)sceKernelDeleteMutex(mutex->uid);
    mutex->uid = -1;
}

static int mutex_lock(mbedtls_threading_mutex_t *mutex)
{
    return mutex->uid < 0 || sceKernelLockMutex(mutex->uid, 1, NULL) < 0 ? MBEDTLS_ERR_THREADING_MUTEX_ERROR : 0;
}

static int mutex_unlock(mbedtls_threading_mutex_t *mutex)
{
    return mutex->uid < 0 || sceKernelUnlockMutex(mutex->uid, 1) < 0 ? MBEDTLS_ERR_THREADING_MUTEX_ERROR : 0;
}

int mbedtls_hardware_poll(void *data, unsigned char *output, size_t length, size_t *produced)
{
    (void)data;
    *produced = 0;
    for (size_t at = 0; at < length;) {
        size_t count = length - at < VH_RNG_MAX_REQUEST ? length - at : VH_RNG_MAX_REQUEST;
        if (sceKernelGetRandomNumber(output + at, (SceSize)count) < 0) {
            mbedtls_platform_zeroize(output, length);
            return -1;
        }
        at += count;
    }
    *produced = length;
    return 0;
}

int64_t vh_mbedtls_time(int64_t *output)
{
    SceRtcTick tick;
    int64_t seconds = -1;
    if (sceRtcGetCurrentTick(&tick) >= 0 && tick.tick >= VH_UNIX_EPOCH_TICKS)
        seconds = (int64_t)((tick.tick - VH_UNIX_EPOCH_TICKS) / UINT64_C(1000000));
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

    if (seconds == NULL || result == NULL || *seconds < -VH_UNIX_EPOCH_SECONDS || *seconds > INT64_C(253402300799))
        return NULL;
    tick.tick = (uint64_t)(*seconds + VH_UNIX_EPOCH_SECONDS) * UINT64_C(1000000);
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

int vh_tls_platform_init(void)
{
    if (vh_mbedtls_time(NULL) < 0)
        return -1;
    mbedtls_threading_set_alt(mutex_init, mutex_free, mutex_lock, mutex_unlock);
    return 0;
}
