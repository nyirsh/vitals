#ifndef VITALS_APP_CHECK_H
#define VITALS_APP_CHECK_H

#include <stddef.h>

#include "model.h"
#include "options.h"

/* The connection test
 * The network must already be connected before vitals_check_open */
/* Loads HTTPS and starts sceSsl/sceHttp; 0 on success, otherwise the failing call's result */
int vitals_check_open(void);
/* Cancels a running test and releases what vitals_check_open set up */
void vitals_check_close(void);
/* Cancels a running test but keeps the HTTP libraries loaded for the next one
 * vitals' provider stays attached to the libhttp it started with, so unloading and loading it
 * again would leave the next test without modern TLS */
void vitals_check_stop(void);
/* Starts a fresh run of every check on a worker thread */
void vitals_check_start(void);
void vitals_check_cancel(void);
/* Saves the last run's log in ux0:data/vitals/, once, and only when that run completed without
 * being cancelled; 0 when saved, 1 when it was saved already, -1 when there is no such run, or a
 * negative write error */
int vitals_check_save_report(void);
/* Copies the current results and notice; returns 1 while a run is in progress */
int vitals_check_poll(CheckService *view, char *notice, size_t size);

#endif
