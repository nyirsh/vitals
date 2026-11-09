#ifndef VITALS_LOG_SINK_H
#define VITALS_LOG_SINK_H

/* Where the Vita's log lines go (vitals/log.h): the debug console, from user modules through
 * sceClibPrintf and from the kernel plugin (VITALS_LOG_KERNEL) through ksceDebugPrintf, or, in the
 * debug builds, the file when that's the Logs option (vitals-boot/log_file.c, vitals_log_user and
 * vitals_log_kernel deciding).
 * VITALS_LOG_CONSOLE_ONLY: host tests, where there's no kernel plugin */

#if defined(VITALS_LOG_KERNEL)
#if VITALS_DEBUG >= 1 && !defined(VITALS_LOG_CONSOLE_ONLY)
void vitals_log_kernel(const char *name, const char *format, ...) __attribute__((format(printf, 2, 3)));
#define VITALS_LOG_SINK(format, ...) vitals_log_kernel(VITALS_LOG_NAME, format "\n", ##__VA_ARGS__)
#else
#define VITALS_LOG_SINK(format, ...) ksceDebugPrintf(VITALS_LOG_NAME ": " format "\n", ##__VA_ARGS__)
#endif
/* Off: compiled away, while what only a line shows still counts as used */
#define VITALS_LOG_OFF(...) do { if (0) VITALS_LOG_SINK(__VA_ARGS__); } while (0)
#elif VITALS_DEBUG >= 1 && !defined(VITALS_LOG_CONSOLE_ONLY)
void vitals_log_user(const char *name, const char *format, ...) __attribute__((format(printf, 2, 3)));
#define VITALS_LOG_SINK(format, ...) vitals_log_user(VITALS_LOG_NAME, format "\n", ##__VA_ARGS__)
#else
#if VITALS_DEBUG >= 1
#include <psp2/kernel/clib.h>
#endif
#define VITALS_LOG_SINK(format, ...) sceClibPrintf(VITALS_LOG_NAME ": " format "\n", ##__VA_ARGS__)
#endif

#endif
