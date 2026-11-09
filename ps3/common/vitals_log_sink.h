#ifndef VITALS_LOG_SINK_H
#define VITALS_LOG_SINK_H

/* Where the PS3's log lines go (vitals/log.h): vitals.log and the TTY (vitals_log.h). Three kinds of
 * module get there their own way:
 *   the app (VITALS_LOG_APP): its app_log
 *   the modules with a C library, libhttp and libssl: their printf-like function, VITALS_LOG_PRINTF
 *   the plugins without one (VITALS_LOG_PLAIN): vitals_log_plain, each its own, on vitals_log_format.h */

#if defined(VITALS_LOG_APP)
#include "app_log.h"
#define VITALS_LOG_SINK(...) app_log(__VA_ARGS__)
#elif defined(VITALS_LOG_PLAIN)
void vitals_log_plain(const char *format, ...) __attribute__((format(printf, 1, 2)));
#define VITALS_LOG_SINK(...) vitals_log_plain(__VA_ARGS__)
/* Their values stay used at every level, and the compiler drops the rest */
#define VITALS_LOG_OFF(...)                 \
	do {                                    \
		if (0)                              \
			vitals_log_plain(__VA_ARGS__);  \
	} while (0)
#else
void VITALS_LOG_PRINTF(const char *format, ...) __attribute__((format(printf, 1, 2)));
#define VITALS_LOG_SINK(...) VITALS_LOG_PRINTF(__VA_ARGS__)
#endif

#endif
