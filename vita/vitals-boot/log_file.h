#ifndef VITALS_LOG_FILE_H
#define VITALS_LOG_FILE_H

/* The debug output's file (the app's Options, Logs: File), which only the kernel can write for every
 * process: ux0:data/vitals/logs/vitals.log, the last boot's as vitals.log.old. Lines from the hooks
 * and from the modules' system call wait in a ring, and a thread of its own writes them, so no hook
 * ever waits on a file. Until ux0: is there and the choice can be read, lines go to the debug console
 * too; with File chosen, only to the file; else only to the console. Debug builds only */

#define VITALS_LOG_LINE_MAX 256u

void vitals_log_file_start(void);
void vitals_log_file_stop(void);
/* One pass of the thread: find out the choice, write what's waiting; for the host tests too */
void vitals_log_file_step(void);
/* The kernel plugin's own lines (vitals_log_sink.h) */
void vitals_log_kernel(const char *name, const char *format, ...) __attribute__((format(printf, 2, 3)));
/* The line (with its line break) kept for the file: 1 when the file alone takes it */
int vitals_log_file_put(const char *text, unsigned int length);

#endif
