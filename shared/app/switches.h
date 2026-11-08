#ifndef VITALS_APP_SWITCHES_H
#define VITALS_APP_SWITCHES_H

#include <stddef.h>

#include "console.h"

/* The Options' switches (console.h's ConsoleSwitch) on the console's flag files: which state a switch
 * is in, and making it so. Plain C on two functions the caller gives (the console's
 * console_flag_exists and console_flag_set), so the host tests run it as it is */

typedef int (*SwitchFileExists)(const char *path);
typedef int (*SwitchFileSet)(const char *path, int present);

/* The state whose files are exactly the ones there; failing that, the last whose files are all there
 * (http.off with a stray redirects.off is Off), else the first */
unsigned switch_state(const ConsoleSwitch *s, SwitchFileExists exists);

/* Each of the switch's files there, or not, as state has them: 0, or the first failure. line says
 * what changed, for the Options' progress ("HTTP: Redirects off, wrote redirects.off") */
int switch_apply(const ConsoleSwitch *s, unsigned state, SwitchFileSet set, char *line, size_t size);

#endif
