/* Mbed TLS's gmtime_r (MBEDTLS_PLATFORM_GMTIME_R_ALT): the date of a time, by arithmetic alone, so
 * it needs nothing from the system and the host tests check it against the host's own gmtime_r */

#include <mbedtls/platform_time.h>
#include <mbedtls/platform_util.h>

#include <stdint.h>
#include <string.h>
#include <time.h>

/* 9999-12-31 23:59:59, the last second X.509's dates can name, and 0000-01-01 00:00:00 */
#define VITALS_LAST_SECOND INT64_C(253402300799)
#define VITALS_FIRST_SECOND INT64_C(-62167219200)
#define VITALS_SECONDS_PER_DAY INT64_C(86400)

/* The date of a day counted from 1970-01-01 (Howard Hinnant's civil_from_days, in the proleptic
 * Gregorian calendar X.509 uses) */
static void civil_from_days(int64_t days, int64_t *year, int *month, int *day)
{
	days += 719468;
	int64_t era = (days >= 0 ? days : days - 146096) / 146097;
	int64_t of_era = days - era * 146097;
	int64_t year_of_era = (of_era - of_era / 1460 + of_era / 36524 - of_era / 146096) / 365;
	int64_t day_of_year = of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
	int64_t month_index = (5 * day_of_year + 2) / 153;
	*day = (int)(day_of_year - (153 * month_index + 2) / 5 + 1);
	*month = (int)(month_index < 10 ? month_index + 3 : month_index - 9);
	*year = year_of_era + era * 400 + (*month <= 2);
}

static int is_leap(int64_t year)
{
	return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
}

struct tm *mbedtls_platform_gmtime_r(const mbedtls_time_t *seconds, struct tm *result)
{
	static const int days_before_month[12] = {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};

	/* 0000-01-01 to 9999-12-31, X.509's dates */
	if (seconds == NULL || result == NULL || *seconds < VITALS_FIRST_SECOND || *seconds > VITALS_LAST_SECOND)
		return NULL;
	int64_t days = *seconds / VITALS_SECONDS_PER_DAY;
	int64_t of_day = *seconds % VITALS_SECONDS_PER_DAY;
	if (of_day < 0) {
		of_day += VITALS_SECONDS_PER_DAY;
		--days;
	}
	int64_t year;
	int month, day;
	civil_from_days(days, &year, &month, &day);
	memset(result, 0, sizeof(*result));
	result->tm_year = (int)(year - 1900);
	result->tm_mon = month - 1;
	result->tm_mday = day;
	result->tm_hour = (int)(of_day / 3600);
	result->tm_min = (int)(of_day / 60 % 60);
	result->tm_sec = (int)(of_day % 60);
	result->tm_yday = days_before_month[month - 1] + day - 1 + (month > 2 && is_leap(year));
	/* 1970-01-01 was a Thursday */
	result->tm_wday = (int)(((days % 7) + 11) % 7);
	return result;
}

