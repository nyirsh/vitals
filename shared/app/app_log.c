/* The app's log on both consoles (app_log.h): which lines the installed debug level keeps, and how
 * they read. Each console writes them out with its app_log_write */

#include "app_log.h"

#include "installed.h"
#include "platform.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

void app_log_start(void)
{
	if (vitals_debug_read() == 0)
		return;
	/* Its folders, before anything is installed */
	(void)platform_make_folder(VITALS_DIRECTORY);
	(void)platform_make_folder(VITALS_LOGS_DIRECTORY);
	(void)platform_write_file(VITALS_APP_LOG, "", 0);
}

void app_log(int level, const char *format, ...)
{
	/* The level installed right now, as Options can change it while the app runs */
	if (vitals_debug_read() < level)
		return;
	char line[256];
	int used = snprintf(line, sizeof(line), "[%llu ms] ", (unsigned long long)platform_now_ms());
	va_list arguments;
	va_start(arguments, format);
	vsnprintf(line + used, sizeof(line) - (size_t)used - 1, format, arguments);
	va_end(arguments);
	size_t length = strlen(line);
	line[length++] = '\n';
	line[length] = '\0';
	app_log_write(line, length);
}

void app_log_download(const char *line)
{
	/* curl's notes are details; what's left is why a download failed */
	app_log(strncmp(line, "curl: ", 6) == 0 ? 2 : 1, "%s", line);
}
