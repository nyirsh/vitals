#ifndef VITALS_DNS_RULES_H
#define VITALS_DNS_RULES_H

#include <stddef.h>
#include <stdint.h>

#include "dns_message.h"
#include "vitals/host_map.h"
#include "vitals/redirect_list.h"

/* The DNS rules (/dev_hdd0/vitals/dns.txt) as the Vita's kernel plugin applies them
 * (vitals-dns/dns_watch.c), without any system call, so the host tests run them (tests/host)
 * and the kernel plugin only copies messages in and out:
 *   another host name  the query is sent asking for that name, and its answer is rewritten to
 *                      answer the old name
 *   an IPv4 address    the query goes out as it is, and its answer becomes that address
 *   block              the query goes out as it is, and its answer becomes "no such name"
 * Only standard A queries are touched. A query owed a rewritten answer is remembered by its
 * process, socket and id for a while; at most VITALS_DNS_PENDING_MAX of them, the oldest giving
 * way. The list is read through a callback, again once it's older than VITALS_DNS_LIST_REFRESH.
 * Not thread-safe: the caller holds its own lock around each call.
 *
 * Two switches for the kernel plugin, which must not read files inside a syscall nor give the
 * syscall a message from its own memory (sendto copies from the process's): refresh 0 reads the
 * list once (vitals_dns_rules_reload) and never again by itself; rename 0 leaves a query for a host
 * name target alone, so only addresses and block apply */

#define VITALS_DNS_LIST_PATH "/dev_hdd0/vitals/dns.txt"
#define VITALS_DNS_PENDING_MAX 8u
/* Microseconds: how long a query waits for its answer, and how often the list is read again */
#define VITALS_DNS_PENDING_LIFETIME INT64_C(10000000)
#define VITALS_DNS_LIST_REFRESH INT64_C(5000000)
/* The TTL given for an address on the list, and the most a rewritten answer keeps */
#define VITALS_DNS_ADDRESS_TTL 60u
#define VITALS_DNS_TTL_MAX 300u

typedef struct VitalsDnsPending {
	uint64_t process;
	int socket;
	unsigned id;
	int literal, blocked;
	int64_t expires;
	char name[VITALS_DNS_HOST_MAX];
	char asked[VITALS_DNS_HOST_MAX];
	VitalsDnsAddress address;
} VitalsDnsPending;

typedef struct VitalsDnsRules {
	VitalsRedirectListRead read;
	VitalsHostMap map;
	char names[VITALS_HOST_MAP_MAX_RULES * 2u * (VITALS_HOST_MAP_MAX_HOST + 1u)];
	size_t names_used;
	char work[VITALS_REDIRECT_LIST_WORK_SIZE];
	int64_t read_at;
	int list_read;
	/* How often the list is read again (VITALS_DNS_LIST_REFRESH; 0: never by itself), and whether
	 * queries for host name targets are renamed (1, the Vita's) or left alone (0) */
	int64_t refresh;
	int rename;
	VitalsDnsPending pending[VITALS_DNS_PENDING_MAX];
	unsigned pending_count;
	/* A query's name and pending entry while it's looked at: here rather than on the kernel's small
	 * stack (the caller's lock covers them) */
	char name[VITALS_DNS_HOST_MAX];
	VitalsDnsPending entry;
} VitalsDnsRules;

/* What a query on its way out becomes */
typedef enum VitalsDnsQueryAction {
	/* Sent as it is, with nothing owed (not a query on the list) */
	VITALS_DNS_PASS,
	/* Sent as it is; its answer will be rewritten (an address or block) */
	VITALS_DNS_WATCH,
	/* The query in out is sent in its place; its answer will be rewritten */
	VITALS_DNS_RENAMED,
} VitalsDnsQueryAction;

void vitals_dns_rules_init(VitalsDnsRules *rules, VitalsRedirectListRead read);
/* Reads the list now; returns how many rules it has (not with VITALS_DNS_NO_READER) */
unsigned vitals_dns_rules_reload(VitalsDnsRules *rules, int64_t now);
/* The list from text already in memory (length bytes), parsed in place: text must outlive the rules
 * and have room for a NUL at text[length]. For the kernel plugin, which can't call through C function
 * pointers (vitals_redirect_list_read's callbacks: PS3DK's are CellOS's 32-bit descriptors). Returns
 * how many rules it has; the list isn't read again by itself after this */
unsigned vitals_dns_rules_load_text(VitalsDnsRules *rules, char *text, size_t length, int64_t now);
/* A message process sends on socket at now: when it's a standard A query for a name on the list,
 * what to send. For VITALS_DNS_RENAMED, out holds *out_length bytes. target, when not NULL, gets
 * the rule's target (for the log) */
VitalsDnsQueryAction vitals_dns_rules_query(VitalsDnsRules *rules, uint64_t process, int socket, const unsigned char *message,
                                            size_t length, int64_t now, unsigned char *out, size_t capacity,
                                            size_t *out_length, char *target, size_t target_size);
/* A message process received on socket at now: when it's the answer to a query owed one, the
 * answer to give the process instead, in out (at most capacity bytes, the process's buffer), its
 * size returned; 0 to leave the message as it is */
size_t vitals_dns_rules_answer(VitalsDnsRules *rules, uint64_t process, int socket, const unsigned char *message,
                               size_t length, int64_t now, unsigned char *out, size_t capacity);
/* 1 when a message is worth handing to vitals_dns_rules_answer: some query on socket is owed */
int vitals_dns_rules_waiting(const VitalsDnsRules *rules, uint64_t process, int socket);

#endif
