#ifndef VITALS_APP_LOG_H
#define VITALS_APP_LOG_H

/* The app's own log, /dev_hdd0/vitals/logs/vitals-app.log (VITALS_APP_LOG, common/vitals_paths.h; and
 * the TTY): a line a step of starting up and of each operation, each written and synced at once, so
 * a crash leaves the last step before it */

#include "vitals_paths.h"

/* Starts the log afresh */
void app_log_start(void);
void app_log(const char *format, ...) __attribute__((format(printf, 1, 2)));

#endif
