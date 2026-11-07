/* boot_plugins.txt's editing (boot_plugins.c): the plugin's line added once at the end and removed
 * wherever it is, other lines kept in their order with their own text, the file's line ending kept,
 * blank lines and trailing whitespace dropped; and a long list with mixed endings, which grows by a
 * byte a line when "\r\n" wins, edited without writing past the buffer (AddressSanitizer) */
#include "boot_plugins.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PLUGIN "/dev_hdd0/plugins/vitals_boot.sprx"

static void expect(const char *current, int add, const char *expected, int expected_had)
{
	char *edited = NULL;
	size_t length = 0;
	int had = -1;
	assert(boot_plugins_edit(current, current != NULL ? strlen(current) : 0, PLUGIN, add, &edited, &length, &had) == 0);
	if (strcmp(edited, expected) != 0 || length != strlen(expected) || had != expected_had) {
		fprintf(stderr, "edit of \"%s\" (add %d): \"%s\" (had %d), expected \"%s\" (had %d)\n", current ? current : "(none)",
		        add, edited, had, expected, expected_had);
		assert(0);
	}
	free(edited);
}

int main(void)
{
	/* No list, or an empty one: just the plugin's line */
	expect(NULL, 1, PLUGIN "\n", 0);
	expect("", 1, PLUGIN "\n", 0);
	expect(NULL, 0, "", 0);

	/* Added after the others, which keep their order; once only */
	expect("/dev_hdd0/plugins/webftp_server.sprx\n", 1,
	       "/dev_hdd0/plugins/webftp_server.sprx\n" PLUGIN "\n", 0);
	expect("/dev_hdd0/plugins/a.sprx\n" PLUGIN "\n/dev_hdd0/plugins/b.sprx\n", 1,
	       "/dev_hdd0/plugins/a.sprx\n/dev_hdd0/plugins/b.sprx\n" PLUGIN "\n", 1);
	/* Removed wherever it is, even twice, and with whitespace around it */
	expect("/dev_hdd0/plugins/a.sprx\n  " PLUGIN "\t\n/dev_hdd0/plugins/b.sprx\n" PLUGIN, 0,
	       "/dev_hdd0/plugins/a.sprx\n/dev_hdd0/plugins/b.sprx\n", 1);
	expect("/dev_hdd0/plugins/a.sprx\n", 0, "/dev_hdd0/plugins/a.sprx\n", 0);
	/* Another plugin whose path only starts like vitals' stays */
	expect(PLUGIN ".old\n", 0, PLUGIN ".old\n", 0);

	/* The file's line ending: "\r\n" when it has any; blank lines and trailing whitespace go, a
	 * line's leading whitespace stays; a last line without an ending gets one */
	expect("/dev_hdd0/plugins/a.sprx\r\n\r\n/dev_hdd0/plugins/b.sprx   \r\n", 1,
	       "/dev_hdd0/plugins/a.sprx\r\n/dev_hdd0/plugins/b.sprx\r\n" PLUGIN "\r\n", 0);
	expect(" /dev_hdd0/plugins/a.sprx", 1, " /dev_hdd0/plugins/a.sprx\n" PLUGIN "\n", 0);

	/* A long list of "\n" lines with one "\r\n": every line comes out a byte longer */
	static char many[64 * 1024];
	size_t used = 0;
	for (int i = 0; i < 4000; ++i)
		used += (size_t)snprintf(many + used, sizeof(many) - used, "/x/%d\n", i % 10);
	strcpy(many + used, "/x/last\r\n");
	char *edited = NULL;
	size_t length = 0;
	int had = 0;
	assert(boot_plugins_edit(many, strlen(many), PLUGIN, 1, &edited, &length, &had) == 0);
	assert(had == 0 && length == strlen(many) + 4000 + strlen(PLUGIN) + 2);
	assert(strncmp(edited, "/x/0\r\n/x/1\r\n", 12) == 0);
	assert(strcmp(edited + length - strlen(PLUGIN) - 2, PLUGIN "\r\n") == 0);
	free(edited);

	puts("boot_plugins: added once at the end, removed anywhere, other lines kept, line endings, a long mixed list PASS");
	return 0;
}
