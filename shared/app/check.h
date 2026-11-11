#ifndef VITALS_APP_CHECK_H
#define VITALS_APP_CHECK_H

#include <stddef.h>

#include "check_run.h"
#include "model.h"

/* The connection test (check_service.c): a run on a worker thread (check_run.c), its results for the
 * screen, cancelling it and saving its report; each console's check.c gives its own part
 * (CheckConsole, below): the TLS tiles, the TLS report, the badssl.com checks, the redirects and the
 * DNS rules through its own HTTP library */

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

/* What each console's check.c gives the test */
typedef struct {
	/* The run's requests, judges and system calls (check_run.h); its lock and unlock are
	 * check_lock and check_unlock */
	const CheckBackend *backend;
	/* Before each run: the console's cancelled state cleared */
	void (*reset)(void);
	/* Ends the run at its current request: the user cancelled, or the app is leaving the test */
	void (*cancel)(void);
	/* At each poll while a run goes: NULL, or ends a request that hangs past its deadline */
	void (*watch)(void);
	/* Writes a finished run's report (check_report.h): 0 with its path, else -1 */
	int (*save)(const CheckService *service, char *path, size_t size);
} CheckConsole;
extern const CheckConsole check_console;

/* The lock the results are kept under, which the console's own state of the run may use too (not
 * recursive); nothing before the first run started */
void check_lock(void);
void check_unlock(void);

#endif
