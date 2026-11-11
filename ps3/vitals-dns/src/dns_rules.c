/* The DNS rules, as the Vita's dns_watch.c decides them (dns_rules.h); no system calls and no libc
 * beyond what the compiler provides, so the kernel plugin can carry it */

#include "dns_rules.h"

static size_t name_length(const char *name)
{
	size_t length = 0;
	while (length < VITALS_DNS_HOST_MAX - 1 && name[length] != '\0')
		++length;
	return length;
}

static void copy_name(char *to, const char *from, size_t length)
{
	if (length > VITALS_DNS_HOST_MAX - 1)
		length = VITALS_DNS_HOST_MAX - 1;
	for (size_t i = 0; i < length; ++i)
		to[i] = from[i];
	to[length] = '\0';
}

static void clear(void *memory, size_t size)
{
	unsigned char *bytes = memory;
	for (size_t i = 0; i < size; ++i)
		bytes[i] = 0;
}

/* "block", without case: the target that makes a name not exist */
static int is_block(const char *target, size_t length)
{
	static const char word[] = "block";
	if (length != sizeof(word) - 1)
		return 0;
	for (size_t i = 0; i < length; ++i)
		if ((target[i] | 0x20) != word[i])
			return 0;
	return 1;
}

void vitals_dns_rules_init(VitalsDnsRules *rules, VitalsRedirectListRead read)
{
	clear(rules, sizeof(*rules));
	rules->read = read;
	rules->refresh = VITALS_DNS_LIST_REFRESH;
	rules->rename = 1;
}

/* The reader through callbacks (vitals_redirect_list_read): not in the kernel plugin's build, which
 * can't call through C function pointers and loads text instead (VITALS_DNS_NO_READER) */
#ifndef VITALS_DNS_NO_READER
/* One pair into names; the space holds the most rules the map takes */
static int keep_rule(void *context, const VitalsHostRule *rule)
{
	VitalsDnsRules *rules = context;
	char *from = rules->names + rules->names_used;
	copy_name(from, rule->from, rule->from_length);
	char *to = from + rule->from_length + 1;
	copy_name(to, rule->to, rule->to_length);
	rules->names_used += rule->from_length + rule->to_length + 2;
	rules->map.rules[rules->map.count++] = (VitalsHostRule){from, to, rule->from_length, rule->to_length};
	return rules->map.count == VITALS_HOST_MAP_MAX_RULES;
}

/* Reads the list again once the last read is older than the refresh time; a missing or unreadable
 * list has no rules */
static void read_list(VitalsDnsRules *rules, int64_t now)
{
	rules->list_read = 1;
	rules->read_at = now;
	rules->map.count = 0;
	rules->names_used = 0;
	if (rules->read == NULL || vitals_redirect_list_read(rules->read, rules->work, keep_rule, rules) < 0)
		rules->map.count = 0;
}

static void refresh(VitalsDnsRules *rules, int64_t now)
{
	if (rules->list_read && (rules->refresh == 0 || now - rules->read_at < rules->refresh))
		return;
	read_list(rules, now);
}

unsigned vitals_dns_rules_reload(VitalsDnsRules *rules, int64_t now)
{
	read_list(rules, now);
	return (unsigned)rules->map.count;
}
#else
/* Without the reader, a list is only ever what vitals_dns_rules_load_text gave */
static void refresh(VitalsDnsRules *rules, int64_t now)
{
	(void)rules, (void)now;
}
#endif

unsigned vitals_dns_rules_load_text(VitalsDnsRules *rules, char *text, size_t length, int64_t now)
{
	rules->list_read = 1;
	rules->read_at = now;
	rules->refresh = 0;
	rules->names_used = 0;
	text[length] = '\0';
	return (unsigned)vitals_host_map_parse(&rules->map, text, length);
}

/* One socket waits for one answer; when every place is taken, the one closest to expiring goes */
static void add_pending(VitalsDnsRules *rules, const VitalsDnsPending *entry)
{
	unsigned slot = 0;
	for (unsigned i = 0; i < VITALS_DNS_PENDING_MAX; ++i) {
		const VitalsDnsPending *p = &rules->pending[i];
		if (p->expires != 0 && p->process == entry->process && p->socket == entry->socket) {
			slot = i;
			break;
		}
		if (p->expires == 0 || (rules->pending[slot].expires != 0 && p->expires < rules->pending[slot].expires))
			slot = i;
	}
	if (rules->pending[slot].expires == 0)
		++rules->pending_count;
	rules->pending[slot] = *entry;
}

static void drop_pending(VitalsDnsRules *rules, unsigned slot)
{
	rules->pending[slot].expires = 0;
	--rules->pending_count;
}

VitalsDnsQueryAction vitals_dns_rules_query(VitalsDnsRules *rules, uint64_t process, int socket, const unsigned char *message,
                                            size_t length, int64_t now, unsigned char *out, size_t capacity,
                                            size_t *out_length, char *target, size_t target_size)
{
	/* In the rules' own memory, not on the stack: the kernel's is small, and callers hold their
	 * lock around each call anyway */
	char *name = rules->name;
	unsigned type = 0;
	*out_length = 0;
	if (length > VITALS_DNS_MESSAGE_MAX || vitals_dns_query_name(message, length, name, sizeof(rules->name), &type) != 0 ||
	    type != VITALS_DNS_TYPE_A)
		return VITALS_DNS_PASS;
	refresh(rules, now);
	const VitalsHostRule *rule = vitals_host_map_find(&rules->map, name, name_length(name));
	if (rule == NULL)
		return VITALS_DNS_PASS;
	if (target != NULL && target_size != 0)
		copy_name(target, rule->to, rule->to_length < target_size ? rule->to_length : target_size - 1);
	VitalsDnsPending *entry = &rules->entry;
	clear(entry, sizeof(*entry));
	entry->process = process;
	entry->socket = socket;
	entry->id = (unsigned)message[0] << 8 | message[1];
	copy_name(entry->name, name, name_length(name));
	entry->blocked = is_block(rule->to, rule->to_length);
	entry->literal = !entry->blocked && vitals_dns_parse_address(rule->to, rule->to_length, &entry->address);
	if (!entry->literal && !entry->blocked && !rules->rename)
		return VITALS_DNS_PASS;
	VitalsDnsQueryAction action = VITALS_DNS_WATCH;
	if (entry->literal || entry->blocked)
		copy_name(entry->asked, name, name_length(name));
	else {
		copy_name(entry->asked, rule->to, rule->to_length);
		*out_length = vitals_dns_rename_query(message, length, rule->to, rule->to_length, out, capacity);
		if (*out_length == 0)
			return VITALS_DNS_PASS;
		action = VITALS_DNS_RENAMED;
	}
	entry->expires = now + VITALS_DNS_PENDING_LIFETIME;
	add_pending(rules, entry);
	return action;
}

int vitals_dns_rules_waiting(const VitalsDnsRules *rules, uint64_t process, int socket)
{
	if (rules->pending_count == 0)
		return 0;
	for (unsigned i = 0; i < VITALS_DNS_PENDING_MAX; ++i)
		if (rules->pending[i].expires != 0 && rules->pending[i].process == process && rules->pending[i].socket == socket)
			return 1;
	return 0;
}

size_t vitals_dns_rules_answer(VitalsDnsRules *rules, uint64_t process, int socket, const unsigned char *message,
                               size_t length, int64_t now, unsigned char *out, size_t capacity)
{
	unsigned slot = VITALS_DNS_PENDING_MAX;
	for (unsigned i = 0; i < VITALS_DNS_PENDING_MAX; ++i) {
		VitalsDnsPending *p = &rules->pending[i];
		if (p->expires == 0)
			continue;
		if (p->expires <= now)
			drop_pending(rules, i);
		else if (p->process == process && p->socket == socket)
			slot = i;
	}
	if (slot == VITALS_DNS_PENDING_MAX || length > VITALS_DNS_MESSAGE_MAX)
		return 0;
	const VitalsDnsPending *entry = &rules->pending[slot];
	VitalsDnsAddress addresses[VITALS_DNS_ADDRESSES_MAX];
	uint32_t ttl = VITALS_DNS_ADDRESS_TTL;
	int count = 1;
	if (entry->blocked)
		count = 0;
	else if (entry->literal)
		addresses[0] = entry->address;
	else
		count = vitals_dns_answer_addresses(message, length, (uint16_t)entry->id, addresses, VITALS_DNS_ADDRESSES_MAX, &ttl);
	if (count < 0)
		return 0;
	if (ttl > VITALS_DNS_TTL_MAX)
		ttl = VITALS_DNS_TTL_MAX;
	size_t size = vitals_dns_rewrite_answer(message, length, (uint16_t)entry->id, entry->asked, entry->name, addresses,
	                                        (unsigned)count, ttl, out, capacity);
	if (size == 0)
		return 0;
	/* A blocked name doesn't exist, whatever the server said: NXDOMAIN */
	if (entry->blocked)
		out[3] = (unsigned char)((out[3] & 0xf0u) | 3u);
	drop_pending(rules, slot);
	return size;
}
