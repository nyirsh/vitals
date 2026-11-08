#ifndef VITALS_DIAGNOSTICS_H
#define VITALS_DIAGNOSTICS_H

/* Debug output on the Vita's debug console (make DEBUG=<level>):
 *   0  nothing (release builds)
 *   1  VITALS_LOG: start-up, heap use, the app's sceHttp calls, one line per connection
 *      step that matters (connect, certificate decision, handshake result) and failures
 *   2  also VITALS_VERBOSE: every step, retry, lock and socket read/write */
#ifndef VITALS_DEBUG
#define VITALS_DEBUG 0
#endif
#ifndef VITALS_LOG_PREFIX
#define VITALS_LOG_PREFIX "vitals"
#endif

#if VITALS_DEBUG >= 1
#include <psp2/kernel/clib.h>
#define VITALS_LOG(format, ...) sceClibPrintf(VITALS_LOG_PREFIX ": " format "\n", ##__VA_ARGS__)
#else
#define VITALS_LOG(format, ...) ((void)0)
#endif

#if VITALS_DEBUG >= 2
#define VITALS_VERBOSE(format, ...) VITALS_LOG(format, ##__VA_ARGS__)
#else
#define VITALS_VERBOSE(format, ...) ((void)0)
#endif

#endif
