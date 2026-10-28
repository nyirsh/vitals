#ifndef VITALS_DIAG_H
#define VITALS_DIAG_H

#include <psp2kern/types.h>

/* A temporary diagnostic for the PS Store (NPXS10002), on only when ur0:data/vitals-diag/ holds
 * Sony's libhttp (lhttp.suprx) and the logging module (vitals-diag.suprx) at boot: every process
 * gets Sony's libhttp in place of vitals-http, as in 1.4 (libhttp is shared between processes, so
 * it can't differ in one), and the logging module goes into the shell, after its libhttp, and into
 * the Store, after its SceNpCommerce2 */

/* Sony's libhttp's path while the diagnostic is on; NULL otherwise */
const char *vitals_diag_libhttp(SceUID pid);
/* After a load: remembers the shell's libhttp and the Store's SceNpCommerce2 (path is the one the
 * process asked for) */
void vitals_diag_loaded(SceUID pid, const char *path, SceUID module);
/* After a start: loads the logging module once one of those has started */
void vitals_diag_started(SceUID pid, SceUID module, int result);

#endif
