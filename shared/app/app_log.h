#ifndef VITALS_APP_LOG_H
#define VITALS_APP_LOG_H

/* The app's own log, on both consoles: logs/vitals-app.log in vitals' folder, and the TTY on the PS3 or
 * the debug console on the Vita. A line a step of starting up and of each operation, each written and
 * synced at once, so a crash leaves the last step before it. Off (the installed debug level) writes
 * nothing, Basic the calls and failures, Full the details too */

#include "vitals_paths.h"

#include <stddef.h>

/* Starts the log afresh, unless debug output is Off */
void app_log_start(void);
/* One line, when the installed debug level is at least level (1 or 2) */
void app_log(int level, const char *format, ...) __attribute__((format(printf, 2, 3)));
/* A download's log (download.h): curl's notes at level 2, why it failed at level 1 */
void app_log_download(const char *line);
/* Each console's: a whole line, its break included, out */
void app_log_write(const char *line, size_t length);

#endif
