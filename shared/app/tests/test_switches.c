/* The Options' switches on flag files (shared/app/switches.c): two-state ones, and HTTP's three
 * (On, Redirects off, Off), read back from what's there and written as each state has them */

#include "switches.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static const char *const names[] = {"flags/tls.off", "flags/http.off", "flags/redirects.off"};
static int there[3], fail_on = -1;

static int index_of(const char *path)
{
	for (int i = 0; i < 3; ++i)
		if (strcmp(path, names[i]) == 0)
			return i;
	assert(0);
	return -1;
}

static int exists(const char *path)
{
	return there[index_of(path)];
}

static int set(const char *path, int present)
{
	int i = index_of(path);
	if (i == fail_on)
		return -5;
	there[i] = present;
	return 0;
}

static const ConsoleSwitchState two[] = {{"On", "vitals TLS enabled", CONSOLE_TONE_USUAL, 0},
                                         {"Off", "Sony TLS enabled", CONSOLE_TONE_RED, 1}};
static const ConsoleSwitch tls = {"TLS", {"flags/tls.off", NULL, NULL}, two, 2};
static const ConsoleSwitchState three[] = {{"On", "vitals HTTP and redirects enabled", CONSOLE_TONE_USUAL, 0},
                                           {"Redirects off", "vitals HTTP enabled, redirects off", CONSOLE_TONE_ORANGE, 2},
                                           {"Off", "Sony HTTP enabled", CONSOLE_TONE_RED, 1}};
static const ConsoleSwitch http = {"HTTP", {"flags/http.off", "flags/redirects.off", NULL}, three, 3};

int main(void)
{
	char line[160];

	/* Two states, as before */
	memset(there, 0, sizeof(there));
	assert(switch_state(&tls, exists) == 0);
	assert(switch_apply(&tls, 1, set, line, sizeof(line)) == 0 && there[0] == 1);
	assert(strcmp(line, "TLS: Off, wrote tls.off") == 0);
	assert(switch_state(&tls, exists) == 1);
	assert(switch_apply(&tls, 0, set, line, sizeof(line)) == 0 && there[0] == 0);
	assert(strcmp(line, "TLS: On, deleted tls.off") == 0);

	/* HTTP's three, each written and read back */
	memset(there, 0, sizeof(there));
	assert(switch_state(&http, exists) == 0);
	assert(switch_apply(&http, 1, set, line, sizeof(line)) == 0 && !there[1] && there[2]);
	assert(strcmp(line, "HTTP: Redirects off, deleted http.off; wrote redirects.off") == 0);
	assert(switch_state(&http, exists) == 1);
	assert(switch_apply(&http, 2, set, line, sizeof(line)) == 0 && there[1] && !there[2]);
	assert(switch_state(&http, exists) == 2);
	assert(switch_apply(&http, 0, set, line, sizeof(line)) == 0 && !there[1] && !there[2]);
	assert(switch_state(&http, exists) == 0);

	/* What earlier versions' two switches left: both files is Off, as Sony's HTTP has no redirects */
	there[1] = there[2] = 1;
	assert(switch_state(&http, exists) == 2);
	assert(switch_apply(&http, 2, set, line, sizeof(line)) == 0 && there[1] && !there[2]);

	/* A failed write is reported, and the rest is still written */
	memset(there, 0, sizeof(there));
	fail_on = 1;
	assert(switch_apply(&http, 2, set, line, sizeof(line)) == -5);
	assert(strcmp(line, "HTTP: Off, wrote http.off (failed); deleted redirects.off") == 0);
	fail_on = -1;
	/* A state past the last is the first */
	there[1] = 1;
	assert(switch_apply(&http, 7, set, line, sizeof(line)) == 0 && !there[1] && !there[2]);

	puts("Options' switches: two and three states on flag files, read back and written PASS");
	return 0;
}
