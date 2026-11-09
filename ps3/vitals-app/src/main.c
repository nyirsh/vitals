/* vitals for the PS3: the shared app (app.c) on the PS3's part of it (console_ps3.c, install.c,
 * platform_ps3.c, check.c) */

#include "app.h"
#include "vitals/log.h"
#include "install.h"

#include <cell/cell_fs.h>
#include <sys/process.h>

SYS_PROCESS_PARAM(1001, 0x100000);

/* With a file named "autotest" in the app's USRDIR, the test runs as the app starts, its report is
 * saved, and the app exits once it's done: a run with no one at the pad, in RPCS3 */
#define AUTOTEST_SWITCH "/dev_hdd0/game/" VITALS_TITLE_ID "/USRDIR/autotest"

int main(int argc, char **argv)
{
	app_log_start();
	VITALS_LOG_ALWAYS("vitals app %s starting, argv[0] %s", VITALS_VERSION, argc > 0 && argv != NULL && argv[0] != NULL ? argv[0] : "-");
	if (argc > 0 && argv != NULL && argv[0] != NULL)
		vitals_install_set_source(argv[0]);
	CellFsStat status;
	int autotest = cellFsStat(AUTOTEST_SWITCH, &status) == CELL_FS_SUCCEEDED;
	return app_main(autotest);
}
