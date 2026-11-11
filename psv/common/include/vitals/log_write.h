#ifndef VITALS_LOG_WRITE_H
#define VITALS_LOG_WRITE_H

/* The kernel plugin's system call for the modules' log lines (vitals_log_sink.h), as a game's
 * process can't open ux0:data/vitals itself: the line, with its line break. 1 when the file alone
 * takes it, 0 when it's still the caller's to print */
int vitals_log_write(const char *text, unsigned int length);

#endif
