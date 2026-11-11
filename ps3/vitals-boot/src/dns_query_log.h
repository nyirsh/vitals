#ifndef VITALS_DNS_QUERY_LOG_H
#define VITALS_DNS_QUERY_LOG_H

/* Each DNS query in the log, on the PS3. The DNS kernel plugin's hooks can't write a file (one that
 * did froze the console: vitals-dns/kernel/plugin.c), so they only keep the last queries in memory,
 * and the boot plugin's debug builds read them from there with Cobra's peek and log the new ones. The
 * layout is plugin.c's State. Only ever reads the kernel's memory. Its lines read as the Vita's */

#include <stdarg.h>
#include <stdint.h>

#include "vitals_log_format.h"

#define VITALS_DNS_STATE_QUERIES 24u
#define VITALS_DNS_STATE_RECENT 64u
#define VITALS_DNS_RECENT_COUNT 8u
#define VITALS_DNS_RECENT_SIZE 64u
#define VITALS_DNS_RECENT_NAME 56u

typedef uint64_t (*VitalsDnsPeek)(uint64_t address);
typedef void (*VitalsDnsLine)(const char *line);

static inline void vitals_dns_log_line(VitalsDnsLine out, const char *format, ...)
    __attribute__((format(printf, 2, 3)));
static inline void vitals_dns_log_line(VitalsDnsLine out, const char *format, ...)
{
	char line[128];
	va_list arguments;
	va_start(arguments, format);
	vitals_log_vformat(line, sizeof(line), format, arguments);
	va_end(arguments);
	out(line);
}

/* Logs the queries after the first seen ones of the State at state; returns how many are now seen.
 * A slot the hook is still writing (its how is 0) waits for the next pass. details: also how it went
 * out, for Full debug */
static inline uint64_t vitals_dns_log_step(uint64_t state, uint64_t seen, VitalsDnsPeek peek, VitalsDnsLine out,
                                           int details)
{
	uint64_t queries = peek(state + VITALS_DNS_STATE_QUERIES);
	if (queries - seen > VITALS_DNS_RECENT_COUNT) {
		uint64_t lost = queries - seen - VITALS_DNS_RECENT_COUNT;
		vitals_dns_log_line(out, "%llu queries not logged, too many at once", (unsigned long long)lost);
		seen = queries - VITALS_DNS_RECENT_COUNT;
	}
	for (; seen < queries; ++seen) {
		uint64_t slot = state + VITALS_DNS_STATE_RECENT + seen % VITALS_DNS_RECENT_COUNT * VITALS_DNS_RECENT_SIZE;
		uint64_t last = peek(slot + VITALS_DNS_RECENT_NAME);
		uint32_t type = (uint32_t)(last >> 32), how = (uint32_t)last;
		if (how == 0)
			break;
		char name[VITALS_DNS_RECENT_NAME];
		for (unsigned word = 0; word * 8 < VITALS_DNS_RECENT_NAME; ++word) {
			uint64_t value = peek(slot + word * 8u);
			for (unsigned byte = 0; byte < 8; ++byte)
				name[word * 8 + byte] = (char)(value >> (56 - 8 * byte));
		}
		name[VITALS_DNS_RECENT_NAME - 1] = '\0';
		vitals_dns_log_line(out, "query name=%s type=%u%s%s%s", name, (unsigned)type, how & 16 ? " rule" : "",
		                    how & 32 ? " renamed" : "", details && (how & 15) == 2 ? " connected" : "");
	}
	return seen;
}

#endif
