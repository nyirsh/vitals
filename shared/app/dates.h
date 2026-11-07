#ifndef VITALS_APP_DATES_H
#define VITALS_APP_DATES_H

/* Whether a date (year, month 1 to 12, day) is more than three calendar months before another: the
 * certificates' age, which the menu shows in red past it */
static inline int vitals_older_than_three_months(int year, int month, int day, int now_year, int now_month, int now_day)
{
	int limit_year = now_year, limit_month = now_month - 3;
	if (limit_month < 1) {
		limit_month += 12;
		--limit_year;
	}
	if (year != limit_year)
		return year < limit_year;
	if (month != limit_month)
		return month < limit_month;
	return day < now_day;
}

#endif
