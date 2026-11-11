#ifndef VITALS_APP_CHECK_REPORT_H
#define VITALS_APP_CHECK_REPORT_H

#include <stddef.h>
#include <stdint.h>

#include "model.h"

/* The connection test's saved report, the same on every console (check_report.c): what the run
 * was, each TLS tile, the badssl.com checks, the host redirects, the DNS rules and the TLS report's
 * handshake. What a console adds: the lines on itself and its parts of vitals, and each request's
 * own fields (its HTTP library's errors and details). The console writes the text to its file */

/* The report's text, as it's added to: it stops at capacity */
typedef struct {
	char *data;
	size_t used, capacity;
} CheckReport;

void check_report_add(CheckReport *report, const char *format, ...) __attribute__((format(printf, 2, 3)));

typedef struct {
	/* The console's name ("PS Vita", "PS3") and its HTTP API ("sceHttp", "cellHttp") */
	const char *console, *api;
	/* Lines after the header: how requests are made, the console, which parts of vitals answered */
	void (*about)(CheckReport *report, const CheckService *service);
	/* A request's own fields, after its state, HTTP status and error */
	void (*result)(CheckReport *report, const CheckResult *result);
	/* More on a TLS tile (test 0 to 3) after its classification; NULL for none */
	void (*protocol)(CheckReport *report, unsigned test, const CheckResult *result);
} CheckReportFormat;

/* service's report into report (data and capacity set, used 0) */
void check_report_write(const CheckReportFormat *format, const CheckService *service, CheckReport *report);

/* A report's file name in directory: name-YYYY-MM-DD_HH-MM-SS.txt from the console's local time
 * (time NULL when it has none), else name-<fallback>.txt */
typedef struct {
	unsigned year, month, day, hour, minute, second;
} CheckReportTime;
void check_report_path(char *path, size_t size, const char *directory, const char *name, const CheckReportTime *time,
                       uint64_t fallback);

#endif
