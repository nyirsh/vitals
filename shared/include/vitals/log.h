#ifndef VITALS_SHARED_LOG_H
#define VITALS_SHARED_LOG_H

/* The log of every part of vitals, on both consoles. A line is "<name>: <text>", name being the
 * component's: vitals-boot, vitals-dns, vitals-http, vitals-ssl, vitals-browser or vitals-app.
 *
 * A build sets VITALS_LOG_NAME and VITALS_DEBUG (make DEBUG=<level>), then uses:
 *   VITALS_LOG(format, ...)      from level 1: the calls, with their results, start-up and failures
 *   VITALS_VERBOSE(format, ...)  from level 2: the details, such as URLs, header values, cookies, sockets,
 *                                certificates and memory, and every step, retry and lock
 * Level 0 logs nothing. The app is one build for every level, so it asks the installed level per line.
 * with printf's format, without a line break. Where a line goes is each console's, and each kind of
 * module's, vitals_log_sink.h, on the include path next to vitals_paths.h */

#ifndef VITALS_DEBUG
#define VITALS_DEBUG 0
#endif
#ifndef VITALS_LOG_NAME
#define VITALS_LOG_NAME "vitals"
#endif

#ifndef VITALS_LOG_APP
#include "vitals_log_sink.h"
#endif

/* A level the build is below: nothing, unless the sink needs its arguments kept alive */
#ifndef VITALS_LOG_OFF
#define VITALS_LOG_OFF(...) ((void)0)
#endif

#ifdef VITALS_LOG_APP
#include "app_log.h"
#define VITALS_LOG(...) app_log(1, __VA_ARGS__)
#define VITALS_VERBOSE(...) app_log(2, __VA_ARGS__)
#else

#if VITALS_DEBUG >= 1
#define VITALS_LOG(...) VITALS_LOG_SINK(__VA_ARGS__)
#else
#define VITALS_LOG(...) VITALS_LOG_OFF(__VA_ARGS__)
#endif

#if VITALS_DEBUG >= 2
#define VITALS_VERBOSE(...) VITALS_LOG_SINK(__VA_ARGS__)
#elif VITALS_DEBUG == 1
/* Compiled away, while what only a detail shows still counts as used */
#define VITALS_VERBOSE(...) do { if (0) VITALS_LOG_SINK(__VA_ARGS__); } while (0)
#else
#define VITALS_VERBOSE(...) VITALS_LOG_OFF(__VA_ARGS__)
#endif

#endif

#endif
