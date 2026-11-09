/* The PS3's side of the app's log (app_log.h): the TTY and vitals-app.log */

#include "app_log.h"

#include <cell/cell_fs.h>
#include <stdio.h>

void app_log_write(const char *line, size_t length)
{
	printf("vitals-app: %s", line);
	int fd;
	if (cellFsOpen(VITALS_APP_LOG, CELL_FS_O_WRONLY | CELL_FS_O_CREAT | CELL_FS_O_APPEND, &fd, NULL, 0) != CELL_FS_SUCCEEDED)
		return;
	uint64_t written;
	cellFsWrite(fd, line, length, &written);
	cellFsFsync(fd);
	cellFsClose(fd);
}
