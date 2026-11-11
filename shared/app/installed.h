#ifndef VITALS_APP_INSTALLED_H
#define VITALS_APP_INSTALLED_H

#include <stddef.h>

#include "console.h"

/* What both consoles' installers do the same way (installed.c), on the platform's files (platform.h)
 * and each console's vitals_paths.h: */

/* installed.txt (VITALS_INSTALLED), which every install writes: the release that installed vitals.
 * 0 with it in version, or -1 when it isn't there or can't be read */
int vitals_installed_read(char *version, size_t size);
int vitals_installed_write(void);

/* The installed modules' debug level, as a marker in flags/ next to the Options' switches:
 * debug.1 for Basic, debug.2 for Full, neither for Off (an install's, or the Options') */
#define VITALS_DEBUG_MARKER VITALS_FLAGS_DIRECTORY "/debug.%d"
int vitals_debug_read(void);
/* The level's marker written and the other levels' deleted (all of them for Off): 0, or -1 */
int vitals_debug_write(int debug_level);

/* The connection test's reports earlier versions saved in VITALS_DIRECTORY itself, the PS3's
 * connection-test-<time>.txt and the Vita's vitals-testresults-<time>.txt, moved into
 * VITALS_REPORTS_DIRECTORY as connection-test-<time>.txt; one already there under that name is kept,
 * and the earlier one left where it was. The folder is made when it isn't there */
void vitals_move_earlier_reports(VitalsNote note);

#endif
