#include "app_log.h"
#include "installed.h"

#include <cell/cell_fs.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/sys_time.h>

void app_log_start(void)
{
	if (vitals_debug_read() == 0)
		return;
	int fd;
	/* Its folder, before anything is installed */
	cellFsMkdir(VITALS_DIRECTORY, CELL_FS_S_IFDIR | 0777);
	cellFsMkdir(VITALS_LOGS_DIRECTORY, CELL_FS_S_IFDIR | 0777);
	if (cellFsOpen(VITALS_APP_LOG, CELL_FS_O_WRONLY | CELL_FS_O_CREAT | CELL_FS_O_TRUNC, &fd, NULL, 0) == CELL_FS_SUCCEEDED)
		cellFsClose(fd);
}

void app_log(int level, const char *format, ...)
{
	/* The level installed right now, as Options can change it while the app runs */
	if (vitals_debug_read() < level)
		return;
	char line[256];
	int used = snprintf(line, sizeof(line), "[%llu ms] ", (unsigned long long)(sys_time_get_system_time() / 1000));
	va_list arguments;
	va_start(arguments, format);
	vsnprintf(line + used, sizeof(line) - (size_t)used - 1, format, arguments);
	va_end(arguments);
	size_t length = strlen(line);
	line[length++] = '\n';
	line[length] = '\0';
	printf("vitals-app: %s", line);
	int fd;
	if (cellFsOpen(VITALS_APP_LOG, CELL_FS_O_WRONLY | CELL_FS_O_CREAT | CELL_FS_O_APPEND, &fd, NULL, 0) != CELL_FS_SUCCEEDED)
		return;
	uint64_t written;
	cellFsWrite(fd, line, length, &written);
	cellFsFsync(fd);
	cellFsClose(fd);
}
