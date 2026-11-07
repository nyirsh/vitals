/* The DNS rules (vitals-dns/src/dns_rules.c) on this machine with AddressSanitizer: queries and
 * answers built here as a resolver and a server would send them, through each kind of rule (another
 * name, an address, block), and what must be left alone: other names and types, other sockets and
 * processes, answers too late or to another query; the pending queries' limit, and the list read
 * again once it's old */
#include "dns_rules.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static const char *g_list = "";

static int read_list(unsigned int offset, void *buffer, unsigned int size)
{
	size_t length = strlen(g_list);
	if (offset >= length)
		return 0;
	size_t count = length - offset < size ? length - offset : size;
	memcpy(buffer, g_list + offset, count);
	return (int)count;
}

/* name as DNS labels at out: its length */
static size_t put_name(unsigned char *out, const char *name)
{
	size_t at = 0;
	while (*name != '\0') {
		const char *dot = strchr(name, '.');
		size_t label = dot != NULL ? (size_t)(dot - name) : strlen(name);
		out[at++] = (unsigned char)label;
		memcpy(out + at, name, label);
		at += label;
		name += label + (dot != NULL);
	}
	out[at++] = 0;
	return at;
}

/* A resolver's standard query for name, of type, with one OPT record as resolvers often add */
static size_t query(unsigned char *out, unsigned id, const char *name, unsigned type)
{
	static const unsigned char header[12] = {0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0};
	memcpy(out, header, sizeof(header));
	out[0] = (unsigned char)(id >> 8), out[1] = (unsigned char)id;
	size_t at = 12 + put_name(out + 12, name);
	out[at++] = 0, out[at++] = (unsigned char)type, out[at++] = 0, out[at++] = 1;
	return at;
}

/* A server's answer to a query for name: count A records (10.0.0.1, 10.0.0.2, ...) with ttl, under
 * a CNAME when cname isn't NULL; rcode in the header */
static size_t answer(unsigned char *out, unsigned id, const char *name, const char *cname, unsigned count, uint32_t ttl,
                     unsigned rcode)
{
	unsigned answers = count + (cname != NULL);
	unsigned char header[12] = {0, 0, 0x81, (unsigned char)(0x80 | rcode), 0, 1, 0, (unsigned char)answers, 0, 0, 0, 0};
	memcpy(out, header, sizeof(header));
	out[0] = (unsigned char)(id >> 8), out[1] = (unsigned char)id;
	size_t at = 12 + put_name(out + 12, name);
	out[at++] = 0, out[at++] = 1, out[at++] = 0, out[at++] = 1;
	const char *owner = name;
	if (cname != NULL) {
		at += put_name(out + at, name);
		unsigned char record[8] = {0, 5, 0, 1, (unsigned char)(ttl >> 24), (unsigned char)(ttl >> 16), (unsigned char)(ttl >> 8),
		                           (unsigned char)ttl};
		memcpy(out + at, record, 8);
		at += 8;
		unsigned char target[300];
		size_t target_length = put_name(target, cname);
		out[at++] = (unsigned char)(target_length >> 8), out[at++] = (unsigned char)target_length;
		memcpy(out + at, target, target_length);
		at += target_length;
		owner = cname;
	}
	for (unsigned i = 0; i < count; ++i) {
		at += put_name(out + at, owner);
		unsigned char record[14] = {0, 1, 0, 1, (unsigned char)(ttl >> 24), (unsigned char)(ttl >> 16), (unsigned char)(ttl >> 8),
		                            (unsigned char)ttl, 0, 4, 10, 0, 0, (unsigned char)(i + 1)};
		memcpy(out + at, record, 14);
		at += 14;
	}
	return at;
}

/* The question's name in a message (offset 12), dotted */
static void question(const unsigned char *message, char *name)
{
	size_t at = 12, used = 0;
	while (message[at] != 0) {
		unsigned label = message[at++];
		if (used != 0)
			name[used++] = '.';
		memcpy(name + used, message + at, label);
		used += label;
		at += label;
	}
	name[used] = '\0';
}

static VitalsDnsRules rules;
static unsigned char sent[512], reply[512], out[512];

static void expect_addresses(const unsigned char *message, size_t length, unsigned id, unsigned count, const char *first,
                             uint32_t ttl)
{
	VitalsDnsAddress addresses[VITALS_DNS_ADDRESSES_MAX];
	uint32_t got_ttl = 0;
	int got = vitals_dns_answer_addresses(message, length, (uint16_t)id, addresses, VITALS_DNS_ADDRESSES_MAX, &got_ttl);
	assert(got == (int)count);
	if (count != 0) {
		char text[16];
		snprintf(text, sizeof(text), "%u.%u.%u.%u", addresses[0].octets[0], addresses[0].octets[1], addresses[0].octets[2],
		         addresses[0].octets[3]);
		assert(strcmp(text, first) == 0);
		assert(got_ttl == ttl);
	}
}

static void renamed(void)
{
	g_list = "# rules\nold.game.example  new.game.example\n";
	vitals_dns_rules_init(&rules, read_list);
	char target[64], name[300];
	size_t length = query(sent, 0x1234, "OLD.game.example", 1), renamed_length = 0;
	VitalsDnsQueryAction action =
	    vitals_dns_rules_query(&rules, 7, 3, sent, length, 1000, out, sizeof(out), &renamed_length, target, sizeof(target));
	assert(action == VITALS_DNS_RENAMED && strcmp(target, "new.game.example") == 0);
	/* The server is asked for the new name, with the query's id */
	question(out, name);
	assert(strcmp(name, "new.game.example") == 0 && out[0] == 0x12 && out[1] == 0x34);
	assert(vitals_dns_rules_waiting(&rules, 7, 3) && !vitals_dns_rules_waiting(&rules, 7, 4) && !vitals_dns_rules_waiting(&rules, 8, 3));
	/* Its answer, under a CNAME, comes back for the old name, with its TTL capped */
	size_t reply_length = answer(reply, 0x1234, "new.game.example", "edge.example", 2, 3600, 0);
	assert(vitals_dns_rules_answer(&rules, 8, 3, reply, reply_length, 2000, out, sizeof(out)) == 0);
	size_t size = vitals_dns_rules_answer(&rules, 7, 3, reply, reply_length, 2000, out, sizeof(out));
	assert(size != 0);
	question(out, name);
	assert(strcmp(name, "OLD.game.example") == 0);
	expect_addresses(out, size, 0x1234, 2, "10.0.0.1", VITALS_DNS_TTL_MAX);
	/* Answered once */
	assert(!vitals_dns_rules_waiting(&rules, 7, 3));
	assert(vitals_dns_rules_answer(&rules, 7, 3, reply, reply_length, 2000, out, sizeof(out)) == 0);
}

static void address_and_block(void)
{
	g_list = "literal.example 203.0.113.5\ntelemetry.example BLOCK\n";
	vitals_dns_rules_init(&rules, read_list);
	size_t length = query(sent, 0x0101, "literal.example", 1), renamed_length = 1;
	assert(vitals_dns_rules_query(&rules, 1, 9, sent, length, 0, out, sizeof(out), &renamed_length, NULL, 0) == VITALS_DNS_WATCH);
	assert(renamed_length == 0);
	/* Whatever the server says, the answer is the address on the list */
	size_t reply_length = answer(reply, 0x0101, "literal.example", NULL, 1, 30, 0);
	size_t size = vitals_dns_rules_answer(&rules, 1, 9, reply, reply_length, 1, out, sizeof(out));
	assert(size != 0);
	expect_addresses(out, size, 0x0101, 1, "203.0.113.5", VITALS_DNS_ADDRESS_TTL);
	reply_length = answer(reply, 0x0102, "literal.example", NULL, 0, 0, 3);
	length = query(sent, 0x0102, "literal.example", 1);
	(void)vitals_dns_rules_query(&rules, 1, 9, sent, length, 2, out, sizeof(out), &renamed_length, NULL, 0);
	size = vitals_dns_rules_answer(&rules, 1, 9, reply, reply_length, 3, out, sizeof(out));
	expect_addresses(out, size, 0x0102, 1, "203.0.113.5", VITALS_DNS_ADDRESS_TTL);

	/* A blocked name doesn't exist, even when the server has an address for it */
	length = query(sent, 0x0202, "telemetry.example", 1);
	assert(vitals_dns_rules_query(&rules, 1, 10, sent, length, 0, out, sizeof(out), &renamed_length, NULL, 0) == VITALS_DNS_WATCH);
	reply_length = answer(reply, 0x0202, "telemetry.example", NULL, 1, 30, 0);
	size = vitals_dns_rules_answer(&rules, 1, 10, reply, reply_length, 1, out, sizeof(out));
	assert(size != 0 && (out[3] & 0x0f) == 3);
	expect_addresses(out, size, 0x0202, 0, NULL, 0);
}

static void left_alone(void)
{
	g_list = "old.game.example new.game.example\n";
	vitals_dns_rules_init(&rules, read_list);
	size_t renamed_length = 0, length;
	/* Other names, other types, answers rather than queries, and broken messages */
	length = query(sent, 1, "other.example", 1);
	assert(vitals_dns_rules_query(&rules, 1, 1, sent, length, 0, out, sizeof(out), &renamed_length, NULL, 0) == VITALS_DNS_PASS);
	length = query(sent, 1, "old.game.example", 28);
	assert(vitals_dns_rules_query(&rules, 1, 1, sent, length, 0, out, sizeof(out), &renamed_length, NULL, 0) == VITALS_DNS_PASS);
	length = answer(sent, 1, "old.game.example", NULL, 1, 30, 0);
	assert(vitals_dns_rules_query(&rules, 1, 1, sent, length, 0, out, sizeof(out), &renamed_length, NULL, 0) == VITALS_DNS_PASS);
	length = query(sent, 1, "old.game.example", 1);
	for (size_t cut = 0; cut < length; ++cut)
		assert(vitals_dns_rules_query(&rules, 1, 1, sent, cut, 0, out, sizeof(out), &renamed_length, NULL, 0) == VITALS_DNS_PASS);
	assert(rules.pending_count == 0);
	/* Too small a buffer for the renamed query: sent as it is */
	assert(vitals_dns_rules_query(&rules, 1, 1, sent, length, 0, out, 12, &renamed_length, NULL, 0) == VITALS_DNS_PASS);

	/* An answer to another query id, or after the wait: left as it is */
	assert(vitals_dns_rules_query(&rules, 1, 1, sent, length, 0, out, sizeof(out), &renamed_length, NULL, 0) == VITALS_DNS_RENAMED);
	size_t reply_length = answer(reply, 2, "new.game.example", NULL, 1, 30, 0);
	assert(vitals_dns_rules_answer(&rules, 1, 1, reply, reply_length, 1, out, sizeof(out)) == 0);
	reply_length = answer(reply, 1, "new.game.example", NULL, 1, 30, 0);
	assert(vitals_dns_rules_answer(&rules, 1, 1, reply, reply_length, VITALS_DNS_PENDING_LIFETIME, out, sizeof(out)) == 0);
	assert(rules.pending_count == 0);
	/* Truncated answers aren't rewritten */
	assert(vitals_dns_rules_query(&rules, 1, 1, sent, length, 0, out, sizeof(out), &renamed_length, NULL, 0) == VITALS_DNS_RENAMED);
	for (size_t cut = 0; cut < reply_length; ++cut)
		assert(vitals_dns_rules_answer(&rules, 1, 1, reply, cut, 1, out, sizeof(out)) == 0);
	/* Nor into a buffer too small for the rewritten one */
	assert(vitals_dns_rules_answer(&rules, 1, 1, reply, reply_length, 1, out, 20) == 0);
}

static void limits(void)
{
	g_list = "old.game.example new.game.example\n";
	vitals_dns_rules_init(&rules, read_list);
	size_t renamed_length = 0, length = query(sent, 5, "old.game.example", 1);
	/* One more socket than there's room for: the oldest gives way */
	for (int socket = 0; socket <= (int)VITALS_DNS_PENDING_MAX; ++socket)
		assert(vitals_dns_rules_query(&rules, 1, socket, sent, length, socket, out, sizeof(out), &renamed_length, NULL, 0) ==
		       VITALS_DNS_RENAMED);
	assert(rules.pending_count == VITALS_DNS_PENDING_MAX);
	assert(!vitals_dns_rules_waiting(&rules, 1, 0) && vitals_dns_rules_waiting(&rules, 1, 1) &&
	       vitals_dns_rules_waiting(&rules, 1, (int)VITALS_DNS_PENDING_MAX));
	/* A socket asking again replaces its own entry */
	assert(vitals_dns_rules_query(&rules, 1, 1, sent, length, 100, out, sizeof(out), &renamed_length, NULL, 0) == VITALS_DNS_RENAMED);
	assert(rules.pending_count == VITALS_DNS_PENDING_MAX);

	/* The list is read again once it's old: a rule added since applies then, not before */
	g_list = "old.game.example new.game.example\nlater.example block\n";
	length = query(sent, 6, "later.example", 1);
	assert(vitals_dns_rules_query(&rules, 2, 1, sent, length, VITALS_DNS_LIST_REFRESH - 1, out, sizeof(out), &renamed_length,
	                              NULL, 0) == VITALS_DNS_PASS);
	assert(vitals_dns_rules_query(&rules, 2, 1, sent, length, VITALS_DNS_LIST_REFRESH, out, sizeof(out), &renamed_length, NULL,
	                              0) == VITALS_DNS_WATCH);
	/* No list, or none to read: nothing applies */
	vitals_dns_rules_init(&rules, NULL);
	length = query(sent, 7, "old.game.example", 1);
	assert(vitals_dns_rules_query(&rules, 1, 1, sent, length, 0, out, sizeof(out), &renamed_length, NULL, 0) == VITALS_DNS_PASS);
}

/* The kernel's switches: the list read once and never again by itself, and host name targets left
 * alone while addresses and block still apply */
static void kernel_switches(void)
{
	g_list = "old.game.example new.game.example\nliteral.example 192.0.2.7\n";
	vitals_dns_rules_init(&rules, read_list);
	rules.refresh = 0;
	rules.rename = 0;
	assert(vitals_dns_rules_reload(&rules, 0) == 2);
	size_t renamed_length = 1, length = query(sent, 0x10, "old.game.example", 1);
	assert(vitals_dns_rules_query(&rules, 1, 1, sent, length, 0, out, sizeof(out), &renamed_length, NULL, 0) == VITALS_DNS_PASS);
	assert(renamed_length == 0 && rules.pending_count == 0);
	length = query(sent, 0x11, "literal.example", 1);
	assert(vitals_dns_rules_query(&rules, 1, 1, sent, length, 0, out, sizeof(out), &renamed_length, NULL, 0) == VITALS_DNS_WATCH);
	size_t reply_length = answer(reply, 0x11, "literal.example", NULL, 1, 30, 0);
	size_t size = vitals_dns_rules_answer(&rules, 1, 1, reply, reply_length, 1, out, sizeof(out));
	expect_addresses(out, size, 0x11, 1, "192.0.2.7", VITALS_DNS_ADDRESS_TTL);
	/* A list changed since isn't read by itself, however long ago it was read */
	g_list = "";
	length = query(sent, 0x12, "literal.example", 1);
	assert(vitals_dns_rules_query(&rules, 1, 1, sent, length, INT64_C(1) << 40, out, sizeof(out), &renamed_length, NULL, 0) ==
	       VITALS_DNS_WATCH);
	assert(vitals_dns_rules_reload(&rules, 0) == 0);
	/* Thread pointers as keys: 64-bit values tell queries apart */
	g_list = "literal.example 192.0.2.7\n";
	(void)vitals_dns_rules_reload(&rules, 0);
	length = query(sent, 0x13, "literal.example", 1);
	(void)vitals_dns_rules_query(&rules, UINT64_C(0x8000000000700000), 1, sent, length, 0, out, sizeof(out), &renamed_length, NULL, 0);
	assert(vitals_dns_rules_waiting(&rules, UINT64_C(0x8000000000700000), 1));
	assert(!vitals_dns_rules_waiting(&rules, UINT64_C(0x8000000000700100), 1) && !vitals_dns_rules_waiting(&rules, 0x700000, 1));
}

/* The kernel's loader, from text in memory without callbacks: the same rules as the reader's, and the
 * list not read again by itself */
static void loaded_from_text(void)
{
	static char text[256];
	const char *list = "# comment\r\nliteral.example 192.0.2.9\nTELEMETRY.example block # why\n\nbroken line here\nlast.example 192.0.2.10";
	strcpy(text, list);
	g_list = "";
	vitals_dns_rules_init(&rules, read_list);
	assert(vitals_dns_rules_load_text(&rules, text, strlen(list), 0) == 3);
	size_t renamed_length = 0, length = query(sent, 0x21, "literal.example", 1);
	assert(vitals_dns_rules_query(&rules, 1, 1, sent, length, INT64_C(1) << 40, out, sizeof(out), &renamed_length, NULL, 0) ==
	       VITALS_DNS_WATCH);
	size_t reply_length = answer(reply, 0x21, "literal.example", NULL, 1, 30, 0);
	size_t size = vitals_dns_rules_answer(&rules, 1, 1, reply, reply_length, INT64_C(1) << 40, out, sizeof(out));
	expect_addresses(out, size, 0x21, 1, "192.0.2.9", VITALS_DNS_ADDRESS_TTL);
	length = query(sent, 0x22, "telemetry.example", 1);
	assert(vitals_dns_rules_query(&rules, 1, 2, sent, length, 0, out, sizeof(out), &renamed_length, NULL, 0) == VITALS_DNS_WATCH);
	/* The last line, without its newline, counts too */
	length = query(sent, 0x23, "last.example", 1);
	assert(vitals_dns_rules_query(&rules, 1, 3, sent, length, 0, out, sizeof(out), &renamed_length, NULL, 0) == VITALS_DNS_WATCH);
	/* The same list through the reader gives the same rules */
	g_list = list;
	vitals_dns_rules_init(&rules, read_list);
	assert(vitals_dns_rules_reload(&rules, 0) == 3);
}

int main(void)
{
	renamed();
	address_and_block();
	left_alone();
	limits();
	kernel_switches();
	loaded_from_text();
	puts("dns_rules: renamed, address, block, left alone, limits, the list read again, the kernel's switches and its loader PASS");
	return 0;
}
