/* What both installers do the same way (shared/app/installed.c), on this machine's files under a
 * temporary folder standing for the console's paths (each console's vitals_paths.h): installed.txt
 * written and read back, and the reports earlier versions saved moved into reports/. Built in both
 * consoles' tests */

#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include "installed.h"
#include "platform.h"
#include "vitals_paths.h"

#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ---- the platform's files, under root: "ux0:data/x" and "/dev_hdd0/x" become <root>/ux0/data/x
 * and <root>/dev_hdd0/x ---- */

static char root[256];

static const char *map(const char *path, char *host, size_t size)
{
	const char *colon = strchr(path, ':');
	if (colon != NULL)
		snprintf(host, size, "%s/%.*s/%s", root, (int)(colon - path), path, colon + 1);
	else
		snprintf(host, size, "%s%s", root, path);
	return host;
}

long platform_read_file(const char *path, char *data, size_t capacity)
{
	char host[512];
	FILE *file = fopen(map(path, host, sizeof(host)), "rb");
	if (file == NULL)
		return -1;
	size_t length = fread(data, 1, capacity, file);
	fclose(file);
	return (long)length;
}

int platform_write_file(const char *path, const void *data, size_t length)
{
	char host[512];
	FILE *file = fopen(map(path, host, sizeof(host)), "wb");
	if (file == NULL)
		return -1;
	int rc = fwrite(data, 1, length, file) == length ? 0 : -1;
	return fclose(file) == 0 ? rc : -1;
}

int platform_file_exists(const char *path)
{
	char host[512];
	struct stat status;
	return stat(map(path, host, sizeof(host)), &status) == 0;
}

int platform_make_folder(const char *path)
{
	char host[512];
	map(path, host, sizeof(host));
	return mkdir(host, 0777) == 0 || platform_file_exists(path) ? 0 : -1;
}

int platform_remove_file(const char *path)
{
	char host[512];
	return unlink(map(path, host, sizeof(host))) == 0 ? 0 : -1;
}

int platform_rename(const char *from, const char *to)
{
	char a[512], b[512];
	return rename(map(from, a, sizeof(a)), map(to, b, sizeof(b))) == 0 ? 0 : -1;
}

int platform_list_folder(const char *path, void (*each)(void *context, const char *name), void *context)
{
	char host[512];
	DIR *folder = opendir(map(path, host, sizeof(host)));
	if (folder == NULL)
		return -1;
	for (struct dirent *entry; (entry = readdir(folder)) != NULL;)
		if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
			each(context, entry->d_name);
	closedir(folder);
	return 0;
}

/* ---- helpers ---- */

/* Every folder on the way to path's own folder */
static void folders(const char *path)
{
	char host[512];
	map(path, host, sizeof(host));
	for (char *slash = host + strlen(root) + 1; (slash = strchr(slash, '/')) != NULL; ++slash) {
		*slash = '\0';
		(void)mkdir(host, 0777);
		*slash = '/';
	}
}

static void put(const char *path, const char *text)
{
	folders(path);
	assert(platform_write_file(path, text, strlen(text)) == 0);
}

static int is(const char *path, const char *text)
{
	char data[256];
	long length = platform_read_file(path, data, sizeof(data) - 1);
	if (length < 0)
		return 0;
	data[length] = '\0';
	return strcmp(data, text) == 0;
}

static char notes[1024];
static void note(const char *line)
{
	strncat(notes, line, sizeof(notes) - strlen(notes) - 2);
	strcat(notes, "\n");
}

int main(void)
{
	snprintf(root, sizeof(root), "%s/vitals-installed-XXXXXX", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp");
	assert(mkdtemp(root) != NULL);
	char version[16];
	int level = 0;

	/* installed.txt: none yet, then this release written and read back; an earlier release's file,
	 * with its debug= line, still gives its release */
	assert(vitals_installed_read(version, sizeof(version)) == -1);
	folders(VITALS_INSTALLED);
	assert(vitals_installed_write() == 0);
	assert(is(VITALS_INSTALLED, "version=" VITALS_VERSION "\n"));
	assert(vitals_installed_read(version, sizeof(version)) == 0 && strcmp(version, VITALS_VERSION) == 0);
	put(VITALS_INSTALLED, "version=1.0\r\ndebug=2\r\n");
	assert(vitals_installed_read(version, sizeof(version)) == 0 && strcmp(version, "1.0") == 0);

	/* The debug level: a marker in flags/, made when it isn't there; one level's at a time, none for
	 * Off, and the fullest read should both be there */
	char one[128], two[128];
	snprintf(one, sizeof(one), VITALS_DEBUG_MARKER, 1);
	snprintf(two, sizeof(two), VITALS_DEBUG_MARKER, 2);
	assert(vitals_debug_read() == 0);
	assert(vitals_debug_write(2) == 0 && platform_file_exists(two) && !platform_file_exists(one));
	assert(vitals_debug_read() == 2);
	assert(vitals_debug_write(1) == 0 && platform_file_exists(one) && !platform_file_exists(two));
	assert(vitals_debug_read() == 1);
	put(two, "");
	assert(vitals_debug_read() == 2);
	assert(vitals_debug_write(0) == 0 && !platform_file_exists(one) && !platform_file_exists(two));
	assert(vitals_debug_read() == 0);
	assert(vitals_debug_write(3) == -1 && vitals_debug_write(-1) == -1);
	(void)level;

	/* Earlier reports: the PS3's moved as they are, the Vita's renamed, one already moved kept, and
	 * everything else left */
	put(VITALS_DIRECTORY "/connection-test-2026-01-01_00-00-00.txt", "a PS3 report\n");
	put(VITALS_DIRECTORY "/vitals-testresults-2026-01-02_00-00-00.txt", "a Vita report\n");
	put(VITALS_DIRECTORY "/vitals-testresults-2026-01-03_00-00-00.txt", "older\n");
	put(VITALS_REPORTS_DIRECTORY "/connection-test-2026-01-03_00-00-00.txt", "already moved\n");
	put(VITALS_DIRECTORY "/notes.txt", "the user's\n");
	put(VITALS_DIRECTORY "/connection-test-without-a-txt", "not a report\n");
	vitals_move_earlier_reports(note);
	assert(is(VITALS_REPORTS_DIRECTORY "/connection-test-2026-01-01_00-00-00.txt", "a PS3 report\n"));
	assert(is(VITALS_REPORTS_DIRECTORY "/connection-test-2026-01-02_00-00-00.txt", "a Vita report\n"));
	assert(!platform_file_exists(VITALS_DIRECTORY "/connection-test-2026-01-01_00-00-00.txt"));
	assert(!platform_file_exists(VITALS_DIRECTORY "/vitals-testresults-2026-01-02_00-00-00.txt"));
	assert(is(VITALS_DIRECTORY "/vitals-testresults-2026-01-03_00-00-00.txt", "older\n"));
	assert(is(VITALS_REPORTS_DIRECTORY "/connection-test-2026-01-03_00-00-00.txt", "already moved\n"));
	assert(is(VITALS_DIRECTORY "/notes.txt", "the user's\n"));
	assert(is(VITALS_DIRECTORY "/connection-test-without-a-txt", "not a report\n"));
	assert(strstr(notes, "Moved vitals-testresults-2026-01-02_00-00-00.txt to " VITALS_REPORTS_DIRECTORY) != NULL);
	/* Nothing left to move: nothing changes, and no folder is missing */
	notes[0] = '\0';
	vitals_move_earlier_reports(note);
	assert(notes[0] == '\0');

	char command[300];
	snprintf(command, sizeof(command), "rm -rf '%s'", root);
	assert(system(command) == 0);
	puts("installers: installed.txt, the debug level's marker, earlier reports moved PASS");
	return 0;
}
