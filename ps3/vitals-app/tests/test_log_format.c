/* The formatter of the PS3 plugins with no C library (common/vitals_log_format.h), held to printf's
 * output for every format they use, and to the size it's given */

#include "vitals_log_format.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static char ours[64];

__attribute__((format(printf, 1, 2))) static void same(const char *format, ...)
{
	char theirs[64];
	va_list arguments, again;
	va_start(arguments, format);
	va_copy(again, arguments);
	uint32_t used = vitals_log_vformat(ours, sizeof(ours), format, arguments);
	vsnprintf(theirs, sizeof(theirs), format, again);
	va_end(again);
	va_end(arguments);
	if (strcmp(ours, theirs) != 0) {
		fprintf(stderr, "\"%s\": \"%s\", printf says \"%s\"\n", format, ours, theirs);
		assert(0);
	}
	assert(used == strlen(ours));
}

__attribute__((format(printf, 2, 3))) static uint32_t into(uint32_t size, const char *format, ...)
{
	va_list arguments;
	va_start(arguments, format);
	uint32_t used = vitals_log_vformat(ours, size, format, arguments);
	va_end(arguments);
	return used;
}

int main(void)
{
	same("plain text");
	same("%s %08X", "xmb: watch:", 0x80010005u);
	same("%s", "a path/with: anything");
	same("%srules: %02u", "dns.txt cut at 16 KB; ", 7u);
	same("%srules: %02u", "", 32u);
	same("status 0x%016llx", 0x8000000000123456ull);
	same("%d %d %d", 0, -1, 2147483647);
	same("%u %x %X", 4294967295u, 0xabcu, 0xABCu);
	same("%lld %llu", -9000000000ll, 18446744073709551615ull);
	same("%5u|%05u|%5d|%05d", 42u, 42u, -42, -42);
	same("%c%c 100%%", 'o', 'k');
	/* Cut at its size, always ended; nothing written past it */
	memset(ours, 'z', sizeof(ours));
	assert(into(5, "%s", "too long a line") == 4 && strcmp(ours, "too ") == 0 && ours[5] == 'z');
	assert(into(1, "x") == 0 && ours[0] == '\0');
	/* A NULL string doesn't crash the plugin */
	const char *none = NULL;
	assert(into(sizeof(ours), "[%s]", none) == 8 && strcmp(ours, "[(null)]") == 0);
	puts("log format: printf's output for the plugins' formats, sizes PASS");
	return 0;
}
