/* Each DNS query in the PS3's log (vitals-boot/src/dns_query_log.h), read from a stand-in for the DNS
 * kernel plugin's State: the new ones only, a slot still being written waited for, and what the
 * eight slots couldn't hold counted */

#include "dns_query_log.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define WORDS (8u + 8u * 8u)
static uint64_t memory[WORDS];
static char lines[16][128];
static unsigned count;

static uint64_t peek(uint64_t address)
{
	assert(address % 8 == 0 && address / 8 < WORDS);
	return memory[address / 8];
}

static void line(const char *text)
{
	assert(count < 16);
	strcpy(lines[count++], text);
}

/* Query number index in its slot, as the hook writes it: the name's bytes in the console's order */
static void put(unsigned index, const char *name, uint32_t type, uint32_t how)
{
	uint64_t *slot = &memory[8 + index % 8 * 8];
	memset(slot, 0, 64);
	for (unsigned i = 0; name[i] != '\0' && i < 55; ++i)
		slot[i / 8] |= (uint64_t)(unsigned char)name[i] << (56 - 8 * (i % 8));
	slot[7] = (uint64_t)type << 32 | how;
}

#define QUERIES memory[3]

int main(void)
{
	/* Nothing new, nothing read */
	assert(vitals_dns_log_step(0, 0, peek, line, 0) == 0 && count == 0);

	/* The new ones, once, with what happened to them */
	put(0, "a.example", 1, 1);
	put(1, "b.example", 28, 2 | 16 | 32);
	QUERIES = 2;
	uint64_t seen = vitals_dns_log_step(0, 0, peek, line, 0);
	assert(seen == 2 && count == 2);
	assert(strcmp(lines[0], "query name=a.example type=1") == 0);
	assert(strcmp(lines[1], "query name=b.example type=28 rule renamed") == 0);
	assert(vitals_dns_log_step(0, seen, peek, line, 0) == 2 && count == 2);

	/* Full debug also says how it went out */
	count = 0;
	assert(vitals_dns_log_step(0, 1, peek, line, 1) == 2);
	assert(strcmp(lines[0], "query name=b.example type=28 rule renamed connected") == 0);

	/* A slot still being written waits, and comes on the next pass */
	count = 0;
	put(2, "", 0, 0);
	QUERIES = 3;
	assert(vitals_dns_log_step(0, 2, peek, line, 0) == 2 && count == 0);
	put(2, "c.example", 1, 1);
	assert(vitals_dns_log_step(0, 2, peek, line, 0) == 3 && count == 1);

	/* More than the slots hold since the last pass: counted, and the last eight logged */
	count = 0;
	for (unsigned i = 3; i < 13; ++i)
		put(i, "many.example", 1, 1);
	QUERIES = 13;
	assert(vitals_dns_log_step(0, 3, peek, line, 0) == 13);
	assert(count == 9 && strcmp(lines[0], "2 queries not logged, too many at once") == 0);

	/* The longest name a slot holds is still ended */
	count = 0;
	char longest[60];
	memset(longest, 'x', sizeof(longest) - 1);
	longest[sizeof(longest) - 1] = '\0';
	put(13, longest, 1, 1);
	QUERIES = 14;
	assert(vitals_dns_log_step(0, 13, peek, line, 0) == 14);
	assert(strlen(lines[0]) == strlen("query name= type=1") + 55);

	puts("dns query log: new queries once, a slot being written waited for, lost ones counted PASS");
	return 0;
}
