/* The app's log on both consoles (shared/app/app_log.c): what each debug level keeps, how a line
 * reads, and that Off touches nothing. Built in both consoles' tests */

#include "app_log.h"

#include "installed.h"
#include "platform.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static int level, writes, folders, wiped, to_file = 1;
static char last[300];
static size_t last_length;

int vitals_debug_read(void) { return level; }
int app_log_to_file(void) { return to_file; }
uint64_t platform_now_ms(void) { return 5; }
int platform_make_folder(const char *path) { (void)path; ++folders; return 0; }
int platform_write_file(const char *path, const void *data, size_t length)
{
	(void)data;
	assert(strcmp(path, VITALS_APP_LOG) == 0 && length == 0);
	++wiped;
	return 0;
}
void app_log_write(const char *line, size_t length)
{
	++writes;
	last_length = length;
	snprintf(last, sizeof(last), "%s", line);
}

int main(void)
{
	/* Off: no folders, the last file left alone, nothing written */
	level = 0;
	app_log_start();
	assert(folders == 0 && wiped == 0);
	app_log(1, "call");
	app_log(2, "detail");
	app_log_download("curl: a note");
	app_log_download("the reason it failed");
	assert(writes == 0);

	/* Basic: started afresh, the calls and a failed download, no details */
	level = 1;
	app_log_start();
	assert(folders == 2 && wiped == 1);
	app_log(1, "call %d", 7);
	assert(writes == 1 && strcmp(last, "[5 ms] call 7\n") == 0 && last_length == strlen(last));
	app_log(2, "detail");
	app_log_download("curl: a note");
	assert(writes == 1);
	app_log_download("the reason it failed");
	assert(writes == 2 && strcmp(last, "[5 ms] the reason it failed\n") == 0);

	/* Full: the details too */
	level = 2;
	writes = 0;
	app_log(1, "call");
	app_log(2, "detail");
	app_log_download("curl: a note");
	assert(writes == 3 && strcmp(last, "[5 ms] curl: a note\n") == 0);

	/* Not to the file (the Vita's Logs on Network): lines still go out, the file is left alone */
	to_file = 0;
	wiped = folders = writes = 0;
	app_log_start();
	assert(wiped == 0 && folders == 0);
	app_log(1, "call");
	assert(writes == 1);
	to_file = 1;

	/* A long line is cut, and still ends its line */
	char longer[400];
	memset(longer, 'x', sizeof(longer) - 1);
	longer[sizeof(longer) - 1] = '\0';
	app_log(1, "%s", longer);
	assert(last_length == 255 && last[last_length - 1] == '\n');

	puts("app log: each debug level's lines, nothing at Off PASS");
	return 0;
}
