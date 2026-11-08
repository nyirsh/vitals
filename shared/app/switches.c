/* The Options' switches on the console's flag files (switches.h) */

#include "switches.h"

#include <stdio.h>
#include <string.h>

static unsigned present_files(const ConsoleSwitch *s, SwitchFileExists exists)
{
	unsigned present = 0;
	for (unsigned i = 0; i < CONSOLE_SWITCH_FILES && s->files[i] != NULL; ++i)
		if (exists(s->files[i]))
			present |= 1u << i;
	return present;
}

unsigned switch_state(const ConsoleSwitch *s, SwitchFileExists exists)
{
	unsigned present = present_files(s, exists);
	for (unsigned i = 0; i < s->state_count; ++i)
		if (s->states[i].files == present)
			return i;
	for (unsigned i = s->state_count; i-- > 0;)
		if ((s->states[i].files & present) == s->states[i].files && s->states[i].files != 0)
			return i;
	return 0;
}

/* A path's name, after its last '/' */
static const char *name_of(const char *path)
{
	const char *slash = strrchr(path, '/');
	return slash != NULL ? slash + 1 : path;
}

int switch_apply(const ConsoleSwitch *s, unsigned state, SwitchFileSet set, char *line, size_t size)
{
	if (state >= s->state_count)
		state = 0;
	int result = 0;
	size_t used = (size_t)snprintf(line, size, "%s: %s", s->label, s->states[state].name);
	for (unsigned i = 0; i < CONSOLE_SWITCH_FILES && s->files[i] != NULL; ++i) {
		int wanted = (s->states[state].files >> i) & 1u;
		int rc = set(s->files[i], wanted);
		if (used < size)
			used += (size_t)snprintf(line + used, size - used, "%s %s %s%s", i == 0 ? "," : ";",
			                         wanted ? "wrote" : "deleted", name_of(s->files[i]), rc == 0 ? "" : " (failed)");
		if (rc != 0 && result == 0)
			result = rc;
	}
	return result;
}
