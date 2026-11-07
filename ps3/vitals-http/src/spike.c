/* The spike (README, plan step 5.1): every function Sony's libhttp exports, each saying it was called,
 * with a running count, on the TTY and in /dev_hdd0/vitals/logs/vitals.log, and returning 0. That tells
 * which functions a game or the vitals app calls, in what order, and that the module loads in
 * libhttp's place. Written functions will replace these at link time, as in vitals-ssl/src/spike.c */

#include <stddef.h>
#include <stdint.h>

#include <sys/prx_module.h>

#include "vitals_log.h"
#include "vitals_xmb.h"

/* Calls so far: written on every call, so a run also proves the module's data segment can be
 * written once loaded */
static uint32_t g_calls;

/* In the debug builds only: a release build writes no log (the count goes on all the same) */
static void say(const char *name)
{
#if VITALS_DEBUG < 1
	(void)name;
	++g_calls;
#else
	char line[96], count[9];
	uint32_t at = 0;
	vitals_log_hex(++g_calls, count);
	for (const char *part = count; *part != '\0'; ++part)
		line[at++] = *part;
	line[at++] = ' ';
	for (; *name != '\0' && at < sizeof(line) - 1; ++name)
		line[at++] = *name;
	line[at] = '\0';
	vitals_log("vitals-http spike", line);
#endif
}

/* Weak: a function written elsewhere takes the place of its stub */
#define CELLHTTP_EXPORT(nid, name)                  \
	int name(void) __attribute__((weak));       \
	int name(void)                              \
	{                                           \
		say(#name);                         \
		return 0;                           \
	}
#define CELLHTTPUTIL_EXPORT(nid, name) CELLHTTP_EXPORT(nid, name)
#include "cellhttp_exports.h"

/* Every function's NID and descriptor, cellHttp's then cellHttpUtil's: what the boot plugin asks for
 * when it loads this module into the XMB (common/vitals_xmb.h) */
#undef CELLHTTP_EXPORT
#undef CELLHTTPUTIL_EXPORT
#define CELLHTTP_EXPORT(nid, name) {nid, (uint32_t)(uintptr_t)name},
#define CELLHTTPUTIL_EXPORT(nid, name) CELLHTTP_EXPORT(nid, name)
static const VitalsXmbFunction k_functions[] = {
#include "cellhttp_exports.h"
};

int module_start(size_t args, void *argp)
{
	VitalsXmbRequest *request = argp;
	if (args == sizeof(*request) && request != NULL && request->magic == VITALS_XMB_MAGIC) {
		uint32_t count = sizeof(k_functions) / sizeof(k_functions[0]);
		if (count > VITALS_XMB_FUNCTIONS)
			count = VITALS_XMB_FUNCTIONS;
		for (uint32_t i = 0; i < count; ++i)
			request->functions[i] = k_functions[i];
		request->count = count;
		say("module_start: the XMB's functions given");
		return SYS_PRX_RESIDENT;
	}
	say("module_start");
	return SYS_PRX_RESIDENT;
}
