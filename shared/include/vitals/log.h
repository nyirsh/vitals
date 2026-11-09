#ifndef VITALS_SHARED_LOG_H
#define VITALS_SHARED_LOG_H

/* The log of every part of vitals, on both consoles. A line is "<name>: <text>", name being the
 * component's: vitals-boot, vitals-dns, vitals-http, vitals-ssl, vitals-browser or vitals-app.
 *
 * A build sets VITALS_LOG_NAME and VITALS_DEBUG (make DEBUG=<level>), then uses:
 *   VITALS_LOG(format, ...)         from level 1: start-up, one line per step that matters, failures
 *   VITALS_VERBOSE(format, ...)     from level 2: every step, retry, lock and socket read or write
 *   VITALS_LOG_ALWAYS(format, ...)  at every level
 * with printf's format, without a line break. Where a line goes is each console's, and each kind of
 * module's, vitals_log_sink.h, on the include path next to vitals_paths.h */

#ifndef VITALS_DEBUG
#define VITALS_DEBUG 0
#endif
#ifndef VITALS_LOG_NAME
#define VITALS_LOG_NAME "vitals"
#endif

#include "vitals_log_sink.h"

/* A level the build is below: nothing, unless the sink needs its arguments kept alive */
#ifndef VITALS_LOG_OFF
#define VITALS_LOG_OFF(...) ((void)0)
#endif

#define VITALS_LOG_ALWAYS(...) VITALS_LOG_SINK(__VA_ARGS__)

#if VITALS_DEBUG >= 1
#define VITALS_LOG(...) VITALS_LOG_SINK(__VA_ARGS__)
#else
#define VITALS_LOG(...) VITALS_LOG_OFF(__VA_ARGS__)
#endif

#if VITALS_DEBUG >= 2
#define VITALS_VERBOSE(...) VITALS_LOG_SINK(__VA_ARGS__)
#else
#define VITALS_VERBOSE(...) VITALS_LOG_OFF(__VA_ARGS__)
#endif

#endif
