/* What both consoles' installers do the same way (installed.h) */

#include "installed.h"

#include "platform.h"
#include "vitals_paths.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int vitals_installed_read(char *version, size_t size)
{
	char text[256];
	long length = platform_read_file(VITALS_INSTALLED, text, sizeof(text) - 1);
	if (length < 0)
		return -1;
	text[length] = '\0';
	if (size != 0)
		version[0] = '\0';
	/* "version=..." on its own line; an earlier release's debug= line after it is left alone */
	for (char *line = text; *line != '\0';) {
		size_t end = strcspn(line, "\r\n");
		char saved = line[end];
		line[end] = '\0';
		if (strncmp(line, "version=", 8) == 0 && size != 0)
			snprintf(version, size, "%s", line + 8);
		line += end + (saved != '\0');
	}
	return 0;
}

int vitals_installed_write(void)
{
	char text[64];
	int length = snprintf(text, sizeof(text), "version=%s\n", VITALS_VERSION);
	return platform_write_file(VITALS_INSTALLED, text, (size_t)length);
}

static void marker(int level, char *path, size_t size)
{
	snprintf(path, size, VITALS_DEBUG_MARKER, level);
}

int vitals_debug_read(void)
{
	char path[128];
	/* The fullest there, should both be */
	for (int level = VITALS_DEBUG_LEVEL_COUNT - 1; level > 0; --level) {
		marker(level, path, sizeof(path));
		if (platform_file_exists(path))
			return level;
	}
	return 0;
}

int vitals_debug_write(int debug_level)
{
	char path[128];
	if (debug_level < 0 || debug_level >= VITALS_DEBUG_LEVEL_COUNT)
		return -1;
	for (int level = 1; level < VITALS_DEBUG_LEVEL_COUNT; ++level)
		if (level != debug_level) {
			marker(level, path, sizeof(path));
			if (platform_file_exists(path) && platform_remove_file(path) < 0)
				return -1;
		}
	if (debug_level == 0)
		return 0;
	(void)platform_make_folder(VITALS_FLAGS_DIRECTORY);
	marker(debug_level, path, sizeof(path));
	return platform_file_exists(path) ? 0 : platform_write_file(path, "", 0);
}

/* A report's name is under 64 characters ("vitals-testresults-2026-11-05_21-40-00.txt") */
#define REPORTS_MAX 32
typedef struct {
	char names[REPORTS_MAX][64];
	unsigned count;
} Reports;

static const char *const earlier[] = {"connection-test-", "vitals-testresults-"};

static void collect(void *context, const char *name)
{
	Reports *reports = context;
	size_t length = strlen(name);
	if (reports->count == REPORTS_MAX || length >= sizeof(reports->names[0]) || length <= 4 ||
	    strcmp(name + length - 4, ".txt") != 0)
		return;
	for (unsigned i = 0; i < sizeof(earlier) / sizeof(earlier[0]); ++i)
		if (strncmp(name, earlier[i], strlen(earlier[i])) == 0) {
			memcpy(reports->names[reports->count++], name, length + 1);
			return;
		}
}

void vitals_move_earlier_reports(VitalsNote note)
{
	(void)platform_make_folder(VITALS_DIRECTORY);
	(void)platform_make_folder(VITALS_REPORTS_DIRECTORY);
	/* Names first, then each moved, so the folder isn't changed while it's read */
	Reports *reports = calloc(1, sizeof(*reports));
	if (reports == NULL || platform_list_folder(VITALS_DIRECTORY, collect, reports) < 0) {
		free(reports);
		return;
	}
	for (unsigned i = 0; i < reports->count; ++i) {
		const char *name = reports->names[i];
		/* The time after whichever prefix it has */
		const char *time = name + strlen(strncmp(name, earlier[0], strlen(earlier[0])) == 0 ? earlier[0] : earlier[1]);
		char from[160], to[160], line[200];
		snprintf(from, sizeof(from), VITALS_DIRECTORY "/%.63s", name);
		snprintf(to, sizeof(to), VITALS_REPORTS_DIRECTORY "/connection-test-%.50s", time);
		if (!platform_file_exists(to) && platform_rename(from, to) == 0 && note != NULL) {
			snprintf(line, sizeof(line), "Moved %.63s to " VITALS_REPORTS_DIRECTORY, name);
			note(line);
		}
	}
	free(reports);
}
