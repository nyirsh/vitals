#ifndef VITALS_LOG_SINK_H
#define VITALS_LOG_SINK_H

/* Where the Vita's log lines go (vitals/log.h): the debug console, from user modules through
 * sceClibPrintf and from the kernel plugin (VITALS_LOG_KERNEL) through ksceDebugPrintf; the app's
 * (VITALS_LOG_APP) through its app_log */

#if defined(VITALS_LOG_APP)
#include "app_log.h"
#define VITALS_LOG_SINK(...) app_log(__VA_ARGS__)
#elif defined(VITALS_LOG_KERNEL)
#define VITALS_LOG_SINK(format, ...) ksceDebugPrintf(VITALS_LOG_NAME ": " format "\n", ##__VA_ARGS__)
#else
#if VITALS_DEBUG >= 1
#include <psp2/kernel/clib.h>
#endif
#define VITALS_LOG_SINK(format, ...) sceClibPrintf(VITALS_LOG_NAME ": " format "\n", ##__VA_ARGS__)
#endif

#endif
