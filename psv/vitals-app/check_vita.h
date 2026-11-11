#ifndef VITALS_VITA_CHECK_VITA_H
#define VITALS_VITA_CHECK_VITA_H

/* What the Vita's connection test adds to the shared check.h: the HTTP libraries stay loaded from
 * one run to the next, since vitals' provider stays attached to the libhttp it started with, and
 * unloading and loading it again would leave the next run without modern TLS. Before vitals' modules
 * are replaced, and as the app exits, they're released: this cancels a running test and unloads them */
void vitals_check_close(void);

#endif
