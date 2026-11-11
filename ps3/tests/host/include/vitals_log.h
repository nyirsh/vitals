#ifndef VITALS_LOG_H
#define VITALS_LOG_H

#include <stdio.h>
#include <stdlib.h>

/* common/vitals_log.h on a host, for the tests: the line on stderr when VS_TEST_LOG is set (the
 * console's writes the TTY and /dev_hdd0/vitals/logs/vitals.log through lv2's syscalls) */
static inline void vitals_log(const char *who, const char *text)
{
	if (getenv("VS_TEST_LOG") != NULL)
		fprintf(stderr, "%s: %s\n", who, text);
}

#endif
