/* The functions not written yet: each says it was called, on the TTY and in
 * /dev_hdd0/vitals/logs/vitals.log, and returns 0: NULL for the ones that return an object, which is what
 * callers check for (a non-zero failure would read as an object and be used), failure for
 * OpenSSL's int ones, and success for the public cellSsl ones. The written ones (core.c,
 * connection.c) replace these at link time. */

#include "vitals_marker.h"
#include <stddef.h>
#include <stdint.h>

#include <sys/prx_module.h>

#include "vitals_log.h"
#define VITALS_LOG_PRINTF vs_log
#include "vitals/log.h"
#include "vitals_xmb.h"

/* Calls so far: written on every call, so a run also proves the module's data segment can be
 * written once loaded (a console refuses a segment both writable and executable) */
static uint32_t g_calls;

/* In the debug builds only: a release build writes no log (the count goes on all the same) */
static void say(const char *name)
{
#if VITALS_DEBUG < 1
	(void)name;
	++g_calls;
#else
	char count[9];
	vitals_log_hex(++g_calls, count);
	VITALS_LOG("not written yet: call %s of %s", count, name);
#endif
}

/* Weak: a function written elsewhere (core.c, connection.c) takes the place of its stub */
#define CELLSSL_EXPORT(nid, name)                   \
	int name(void) __attribute__((weak));       \
	int name(void)                              \
	{                                           \
		say(#name);                         \
		return 0;                           \
	}
#include "cellssl_exports.h"

/* Every function's NID and descriptor, in cellssl_exports.h's order: what the boot plugin asks for
 * when it loads this module into the XMB (common/vitals_xmb.h) */
#undef CELLSSL_EXPORT
#define CELLSSL_EXPORT(nid, name) {nid, (uint32_t)(uintptr_t)name},
static const VitalsXmbFunction k_functions[] = {
#include "cellssl_exports.h"
};

/* What tells this module from Sony's in the app's connection test (common/vitals_marker.h) */
static const char k_marker[] = VITALS_MARKER("libssl");

int module_start(size_t args, void *argp)
{
	VITALS_KEEP_MARKER(k_marker);
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
