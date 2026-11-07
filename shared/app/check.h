#ifndef VITALS_APP_CHECK_H
#define VITALS_APP_CHECK_H

#include <stddef.h>

#include "model.h"

/* The connection test, which each console runs on a worker thread through its own HTTP library
 * (the PS3's check.c): the TLS tiles, the TLS report, the badssl.com checks, the redirects and the
 * DNS rules */

/* Starts a fresh run, unless one is running */
void vitals_check_start(void);
/* Ends a running test at its current request */
void vitals_check_cancel(void);
/* Copies the current results and notice; 1 while a run is in progress */
int vitals_check_poll(CheckService *view, char *notice, size_t size);
/* Saves the last run's report in the console's reports folder, once, and only when that run completed without
 * being cancelled; 0 when saved, 1 when it was saved already, -1 when there is no such run or the
 * write failed */
int vitals_check_save_report(void);
/* Cancels a running test and waits for its thread */
void vitals_check_stop(void);

#endif
