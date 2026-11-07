/* vitals' DNS kernel plugin: it hooks sys_net_bnet_sendto (710) and sys_net_bnet_recvfrom (707) for
 * every process and applies /dev_hdd0/vitals/dns.txt's rules (vitals-dns/src/dns_rules.c, the
 * Vita's), the answer replaced in the process's own buffer:
 *   another host   the query is sent asking for it, then the answer is for the old name again, with
 *                  the new host's addresses
 *   an address     the query goes out as it is, and its answer becomes the address
 *   block          the query goes out as it is, and its answer becomes "no such name"
 * A renamed query is written over the process's own (libnet builds queries in buffers of 1024 or
 * 2048 bytes, and a renamed one is 512 at most), sent, and the original written back at once, with
 * the original's length returned: the resolver checks both. A game with a resolver
 * of its own and a buffer sized to its query is the case this doesn't cover. The list is read once, when the plugin starts; nothing in a hook writes or reads
 * a file (a first version that logged from inside the syscall froze the console). Answers are matched
 * to queries by socket and DNS id (the engine also checks the question), not yet by process.
 * The hooks also count their calls and keep the last RECENT_MAX queries they saw, read over the
 * network with webMAN's lv2 peek (plugin_main logs where they are).
 * Loaded by the boot plugin as the boot starts, with Cobra's syscall 8 as webMAN MOD's
 * /kernelplugin.ps3mapi does (vitals-boot/src/boot.c). Early versions froze the console when loaded
 * at boot: their hooks' frames (a 992-byte one for sendto) overflowed some early thread's kernel
 * stack, so nothing big goes on the stack here (the buffers, below). plugin_main's checks come first, and it
 * only hooks when the syscall table still holds lv2's own descriptors for both, so it never hooks over
 * another hook or itself. A reboot undoes it (the table is in RAM). The plugin's memory must stay:
 * webMAN's unload of its slot would free code the table points at.
 * Kernel code: no libc, lv2's functions through lv2_call (entry.S) */

#include <stdint.h>

#include "dns_message.h"
#include "dns_rules.h"
#include "lv2_493.h"
#include "lv2_493_signatures.h"
#include "vitals_paths.h"

uint64_t lv2_call(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t function,
                  uint64_t toc);

#define LV2(offset) (LV2_BASE + (uint64_t)(offset))
#define CALL(symbol, a0, a1, a2, a3, a4, a5)                                                                         \
	lv2_call((uint64_t)(a0), (uint64_t)(a1), (uint64_t)(a2), (uint64_t)(a3), (uint64_t)(a4), (uint64_t)(a5),            \
	         LV2(symbol), LV2(LV2_TOC))

/* cellFs's flags, as lv2 takes them */
#define FS_O_RDONLY 0
#define FS_O_WRONLY 1
#define FS_O_CREAT 0100
#define FS_O_TRUNC 01000
#define FS_O_APPEND 02000

#define LOG VITALS_LOG

/* A DNS query: a 12-byte header, at least a one-letter name, and the type and class */
#define DNS_MESSAGE_MIN 17u
#define DNS_PORT 53u
#define NET_INET 2u

/* lv2's 16-byte function descriptors */
typedef struct Lv2Descriptor {
	uint64_t function, toc;
} Lv2Descriptor;

static Lv2Descriptor g_sendto_hook, g_recvfrom_hook;
static Lv2Descriptor g_sendto_original, g_recvfrom_original;

/* The last DNS queries: each slot is a name (cut at RECENT_NAME - 1 characters, NUL-terminated),
 * then its type and how it went out (1 to port 53, 2 on a connected socket, plus 16 when a rule
 * applies to it and 32 when it was renamed) */
#define RECENT_MAX 8u
#define RECENT_NAME 56u
typedef struct Recent {
	char name[RECENT_NAME];
	uint32_t type, how;
} Recent;

/* What plugin_main did, for tools/peek_dns.py: it may have had no safe way to log it */
enum {
	STATUS_STARTED = 1,
	STATUS_OFF = 3,        /* dns.off is there */
	STATUS_NO_RULES,       /* dns.txt has no rules: nothing to hook for */
	STATUS_TABLE_CHANGED,  /* the table doesn't hold lv2's own descriptors (hooked already?) */
	STATUS_HOOKED,
	STATUS_DISPATCH = 0x100,  /* the syscall dispatcher isn't 4.93's */
	STATUS_TOC_SLOT,          /* lv2's TOC isn't where 4.93 keeps it */
	STATUS_SIGNATURE = 0x200, /* plus the index of the lv2 function that isn't 4.93's
	                           * (lv2_493_signatures.h) */
};

/* What webMAN's lv2 peek reads, after a marker; the boot plugin finds it through the image's byte 0x50
 * (entry.S's state_offset) and reads the rules and the status for its notification */
typedef struct State {
	char marker[8] __attribute__((nonstring));
	uint64_t sendto_calls, recvfrom_calls, queries, rules, answers_rewritten, queries_renamed, status;
	Recent recent[RECENT_MAX];
} State;
State g_state = {"vitalsdn", 0, 0, 0, 0, 0, 0, 0, {{{0}, 0, 0}}};

/* ---- the rules: read once into memory, applied under a spinlock ----
 * A first version took the lock on every recvfrom of every process, where a thread lv2 preempted
 * while holding it could be kept off the CPU by higher-priority threads spinning for it (suspected
 * for the freezes at boot, which turned out to be the stack). Now:
 *   - ordinary traffic never takes it: recvfrom first reads, without the lock, whether any query is
 *     owed an answer at all and until when (g_owed, g_owed_until);
 *   - nothing can preempt its holder: interrupts are off while it's held (and while waiting for it),
 *     so the wait is only ever for the other hardware thread, which is never paused inside;
 *   - only the engine's pure work happens inside: no lv2 call, no copy to or from a process (those
 *     can fault and wait), into a buffer from a small pool taken without the lock */

#define LIST_MAX 16384u
/* One more byte for the NUL the parser puts after the last line */
static char g_list[LIST_MAX + 1];
static uint64_t g_list_length;
static VitalsDnsRules g_rules;
static uint32_t g_lock;
/* How many queries are owed an answer (the engine's pending_count, written under the lock), and
 * the time after which none still is: recvfrom reads them without the lock */
static uint32_t g_owed;
static int64_t g_owed_until;

/* Everything a hook copies or builds, off the kernel stack: each hook's frame stays near the
 * pass-through's (about 150 bytes). Early in the boot, hooks with the message and name on the stack
 * (a 928-byte frame, before lv2's own handler runs on top) crashed the console, where hooks that only
 * count and pass on ran fine. A hook takes a buffer for the message it copies
 * (message), the name read from it (name) and what the engine builds (out), and gives it back when
 * done, all without the lock. When all are taken (more than BUFFER_COUNT DNS messages at the same
 * instant), the message is left as it is */
typedef struct HookBuffer {
	unsigned char message[VITALS_DNS_MESSAGE_MAX];
	unsigned char out[VITALS_DNS_MESSAGE_MAX];
	char name[VITALS_DNS_HOST_MAX];
} HookBuffer;
#define BUFFER_COUNT 8u
static HookBuffer g_buffers[BUFFER_COUNT];
static uint32_t g_buffer_taken[BUFFER_COUNT];

/* MSR[EE]: external and decrementer interrupts, what lets lv2 preempt a thread */
#define MSR_EE 0x8000u

/* Interrupts off, then the lock: returns the MSR to give unlock */
static uint64_t lock(void)
{
	uint64_t msr;
	__asm__ volatile("mfmsr %0" : "=r"(msr));
	__asm__ volatile("mtmsrd %0, 1" : : "r"(msr & ~(uint64_t)MSR_EE) : "memory");
	while (__atomic_exchange_n(&g_lock, 1, __ATOMIC_ACQUIRE) != 0)
		while (__atomic_load_n(&g_lock, __ATOMIC_RELAXED) != 0)
			;
	return msr;
}

/* The lock, then interrupts as they were */
static void unlock(uint64_t msr)
{
	__atomic_store_n(&g_lock, 0, __ATOMIC_RELEASE);
	__asm__ volatile("mtmsrd %0, 1" : : "r"(msr) : "memory");
}

static HookBuffer *take_buffer(void)
{
	for (unsigned i = 0; i < BUFFER_COUNT; ++i)
		if (__atomic_exchange_n(&g_buffer_taken[i], 1, __ATOMIC_ACQUIRE) == 0)
			return &g_buffers[i];
	return 0;
}

static void give_buffer(HookBuffer *buffer)
{
	if (buffer != 0)
		__atomic_store_n(&g_buffer_taken[buffer - g_buffers], 0, __ATOMIC_RELEASE);
}

/* Microseconds from the time base (79.8 MHz on the PS3): for the queries' expiry, no call needed */
static int64_t now_us(void)
{
	uint64_t ticks;
	__asm__ volatile("mftb %0" : "=r"(ticks));
	return (int64_t)(ticks / 798 * 10);
}

/* Under the lock, after the engine ran: what recvfrom reads without it */
static void publish_owed(int64_t until)
{
	if (until > g_owed_until)
		__atomic_store_n(&g_owed_until, until, __ATOMIC_RELAXED);
	__atomic_store_n(&g_owed, g_rules.pending_count, __ATOMIC_RELEASE);
}

/* Without the lock: whether any query could still be owed an answer */
static int maybe_owed(void)
{
	return __atomic_load_n(&g_owed, __ATOMIC_ACQUIRE) != 0 && now_us() < __atomic_load_n(&g_owed_until, __ATOMIC_RELAXED);
}

/* The compiler copies and clears structures with these; the engine's are small */
void *memcpy(void *destination, const void *source, unsigned long size)
{
	char *d = destination;
	const char *s = source;
	while (size-- != 0)
		*d++ = *s++;
	return destination;
}

void *memset(void *destination, int value, unsigned long size)
{
	char *d = destination;
	while (size-- != 0)
		*d++ = (char)value;
	return destination;
}

static uint64_t count(uint64_t *counter)
{
	return __atomic_fetch_add(counter, 1, __ATOMIC_RELAXED);
}

static int fs_open(const char *path, int flags, int *fd)
{
	return (int)CALL(LV2_CELLFS_OPEN, path, flags, fd, 0666, 0, 0);
}

static void fs_close(int fd)
{
	(void)CALL(LV2_CELLFS_CLOSE, fd, 0, 0, 0, 0, 0);
}


/* ---- the log, from plugin_main only: lines built by hand (no libc), appended to vitals.log ---- */

typedef struct Line {
	char text[160];
	uint64_t used;
} Line;

static void add_text(Line *line, const char *text)
{
	while (*text != '\0' && line->used < sizeof(line->text) - 1)
		line->text[line->used++] = *text++;
}

static void add_hex(Line *line, uint64_t value)
{
	static const char hex[] = "0123456789abcdef";
	add_text(line, "0x");
	for (int i = 0; i < 16 && line->used < sizeof(line->text) - 1; ++i)
		line->text[line->used++] = hex[(value >> (60 - 4 * i)) & 0xf];
}

/* The debug log, a build of its own per level as libssl's and libhttp's (make dns-plugin DEBUG=N,
 * build/vitals-dns-debugN; the app installs the one the user picks): 0 writes nothing, 1 (Basic
 * debug) what plugin_main did, 2 (Full debug) also where it is */
#ifndef VITALS_DEBUG
#define VITALS_DEBUG 0
#endif

static void write_line_at(uint64_t level, Line *line)
{
	if (VITALS_DEBUG < level)
		return;
	int fd = -1;
	uint64_t written = 0;
	line->text[line->used++] = '\n';
	if (fs_open(LOG, FS_O_WRONLY | FS_O_CREAT | FS_O_APPEND, &fd) != 0)
		return;
	(void)CALL(LV2_CELLFS_WRITE, fd, line->text, line->used, &written, 0, 0);
	fs_close(fd);
}

static void write_line(Line *line)
{
	write_line_at(1, line);
}

static void log_text_now(const char *text)
{
	Line line;
	line.used = 0;
	add_text(&line, text);
	write_line(&line);
}

/* ---- the hooks ---- */

/* A user pointer as lv2 takes it: its low 32 bits */
static uint64_t user_pointer(uint64_t pointer)
{
	return pointer & 0xFFFFFFFFu;
}

/* copy_from_user(user source, kernel destination, size): 0 when it worked */
static int from_user(uint64_t user, void *kernel, uint64_t size)
{
	return (int)CALL(LV2_COPY_FROM_USER, user_pointer(user), kernel, size, 0, 0, 0);
}

/* copy_to_user(kernel source, user destination, size): 0 when it worked */
static int to_user(const void *kernel, uint64_t user, uint64_t size)
{
	return (int)CALL(LV2_COPY_TO_USER, kernel, user_pointer(user), size, 0, 0, 0);
}

/* A message on its way out: when it's a DNS query (to IPv4 port 53, or on a connected socket with no
 * address given), the engine sees it, and its name and type go in the ring. buffer->message gets a
 * copy of it. For a host name rule, the renamed query is written over the process's message: the
 * return is then its size, and the caller sends that and writes buffer->message back after; 0
 * otherwise, the message as it was */
static uint64_t watch_query(int64_t socket, uint64_t message, uint64_t length, uint64_t to, uint64_t to_length,
                            HookBuffer *buffer)
{
	if (length < DNS_MESSAGE_MIN || length > VITALS_DNS_MESSAGE_MAX || message == 0)
		return 0;
	if (to != 0) {
		unsigned char address[8];
		if (to_length < sizeof(address) || from_user(to, address, sizeof(address)) != 0 || address[1] != NET_INET ||
		    address[2] != 0 || address[3] != DNS_PORT)
			return 0;
	}
	unsigned char *query = buffer->message;
	if (from_user(message, query, length) != 0 || !vitals_dns_query_header(query))
		return 0;
	unsigned type = 0;
	if (vitals_dns_query_name(query, length, buffer->name, sizeof(buffer->name), &type) != 0)
		return 0;
	uint64_t renamed_length = 0;
	VitalsDnsQueryAction action = VITALS_DNS_PASS;
#ifdef VITALS_DNS_WATCH_ONLY
	(void)socket;
#else
	size_t renamed = 0;
	int64_t now = now_us();
	uint64_t msr = lock();
	action = vitals_dns_rules_query(&g_rules, 0, (int)socket, query, length, now, buffer->out, sizeof(buffer->out),
	                                &renamed, 0, 0);
	publish_owed(action != VITALS_DNS_PASS ? now + VITALS_DNS_PENDING_LIFETIME : 0);
	unlock(msr);
	/* The renamed query over the process's own, outside the lock */
	if (action == VITALS_DNS_RENAMED && renamed != 0 && to_user(buffer->out, message, renamed) == 0)
		renamed_length = renamed;
#endif
	Recent *slot = &g_state.recent[count(&g_state.queries) % RECENT_MAX];
	unsigned i = 0;
	for (; i < RECENT_NAME - 1 && buffer->name[i] != '\0'; ++i)
		slot->name[i] = buffer->name[i];
	slot->name[i] = '\0';
	slot->type = type;
	slot->how = (to != 0 ? 1 : 2) | (action != VITALS_DNS_PASS ? 16 : 0) | (renamed_length != 0 ? 32 : 0);
	return renamed_length;
}

/* What recvfrom gave the process (received bytes at user, which holds capacity): when it's the
 * answer to a query owed one, the rewritten answer in its place. Returns the size to give back */
static int64_t rewrite_answer(int64_t socket, uint64_t user, uint64_t capacity, int64_t received)
{
	/* Nearly every call ends here, without the lock */
	if (received < (int64_t)DNS_MESSAGE_MIN || user == 0 || (uint64_t)received > VITALS_DNS_MESSAGE_MAX ||
	    !maybe_owed())
		return received;
	uint64_t msr = lock();
	int waiting = vitals_dns_rules_waiting(&g_rules, 0, (int)socket);
	unlock(msr);
	if (!waiting)
		return received;
	HookBuffer *buffer = take_buffer();
	if (buffer == 0)
		return received;
	size_t size = 0;
	if (from_user(user, buffer->message, (uint64_t)received) == 0) {
		uint64_t room = capacity < sizeof(buffer->out) ? capacity : sizeof(buffer->out);
		int64_t now = now_us();
		msr = lock();
		size = vitals_dns_rules_answer(&g_rules, 0, (int)socket, buffer->message, (size_t)received, now, buffer->out, room);
		publish_owed(0);
		unlock(msr);
	}
	/* The answer over what the process received, outside the lock */
	int written = size != 0 && to_user(buffer->out, user, size) == 0;
	give_buffer(buffer);
	if (!written)
		return received;
	count(&g_state.answers_rewritten);
	return (int64_t)size;
}

/* For diagnosis (tools/build_dns_plugin.sh pass-through or watch-only): with -DVITALS_DNS_PASS_THROUGH
 * the hooks only count their calls and call lv2's handlers; with -DVITALS_DNS_WATCH_ONLY, sendto also
 * copies and reads each DNS query (the ring), but no rule is applied and recvfrom passes on */
int64_t sendto_hook(int64_t socket, uint64_t message, uint64_t length, int64_t flags, uint64_t to, uint64_t to_length)
{
	count(&g_state.sendto_calls);
#ifdef VITALS_DNS_PASS_THROUGH
	return (int64_t)lv2_call((uint64_t)socket, message, length, (uint64_t)flags, to, to_length, g_sendto_original.function,
	                         g_sendto_original.toc);
#endif
	/* Only a message the size of a DNS query takes a buffer */
	HookBuffer *buffer = length >= DNS_MESSAGE_MIN && length <= VITALS_DNS_MESSAGE_MAX && message != 0 ? take_buffer() : 0;
	uint64_t renamed = buffer != 0 ? watch_query(socket, message, length, to, to_length, buffer) : 0;
	if (renamed != 0) {
		/* The renamed query is sent, the process's own put back, and the original's length given: the
		 * resolver checks that send took its whole query */
		int64_t sent = (int64_t)lv2_call((uint64_t)socket, message, renamed, (uint64_t)flags, to, to_length,
		                                 g_sendto_original.function, g_sendto_original.toc);
		(void)to_user(buffer->message, message, length);
		give_buffer(buffer);
		count(&g_state.queries_renamed);
		return sent == (int64_t)renamed ? (int64_t)length : sent;
	}
	give_buffer(buffer);
	return (int64_t)lv2_call((uint64_t)socket, message, length, (uint64_t)flags, to, to_length, g_sendto_original.function,
	                         g_sendto_original.toc);
}

int64_t recvfrom_hook(int64_t socket, uint64_t buffer, uint64_t length, int64_t flags, uint64_t from, uint64_t from_length)
{
	count(&g_state.recvfrom_calls);
	int64_t received = (int64_t)lv2_call((uint64_t)socket, buffer, length, (uint64_t)flags, from, from_length,
	                                     g_recvfrom_original.function, g_recvfrom_original.toc);
#if defined(VITALS_DNS_PASS_THROUGH) || defined(VITALS_DNS_WATCH_ONLY)
	return received;
#endif
	return rewrite_answer(socket, buffer, length, received);
}

static void sync_memory(void)
{
	__asm__ volatile("sync" ::: "memory");
}

/* Whether this is the lv2 the addresses are for, by reading memory only (no call into lv2 before it
 * says yes): the first instructions of each function the plugin calls or chains to, the syscall
 * dispatcher's call, and the slot it loads lv2's TOC from. 0, or the STATUS_* of the first
 * difference */
static uint64_t verify_lv2(void)
{
	const volatile uint32_t *dispatch = (const volatile uint32_t *)LV2(LV2_SYSCALL_CALL - 16);
	for (unsigned i = 0; i < 5; ++i)
		if (dispatch[i] != k_lv2_dispatch[i])
			return STATUS_DISPATCH;
	if (*(const volatile uint64_t *)LV2(LV2_TOC_SLOT) != LV2(LV2_TOC))
		return STATUS_TOC_SLOT;
	for (unsigned i = 0; i < LV2_SIGNATURE_COUNT; ++i) {
		const volatile uint32_t *code = (const volatile uint32_t *)LV2(k_lv2_signatures[i].offset);
		for (unsigned w = 0; w < 4; ++w)
			if (code[w] != k_lv2_signatures[i].words[w])
				return STATUS_SIGNATURE + i;
	}
	return 0;
}

/* Only the four cellFs functions (signatures 0 to 3) and lv2's TOC: what the log needs */
static int verify_lv2_files(void)
{
	if (*(const volatile uint64_t *)LV2(LV2_TOC_SLOT) != LV2(LV2_TOC))
		return 0;
	for (unsigned i = 0; i < 4; ++i) {
		const volatile uint32_t *code = (const volatile uint32_t *)LV2(k_lv2_signatures[i].offset);
		for (unsigned w = 0; w < 4; ++w)
			if (code[w] != k_lv2_signatures[i].words[w])
				return 0;
	}
	return 1;
}

static void log_status_now(const char *text, uint64_t status)
{
	Line line;
	line.used = 0;
	add_text(&line, text);
	add_hex(&line, status);
	write_line(&line);
}

/* Each line only in the builds of its level, its text with it */
#define log_text(text)                                                                                                \
	do {                                                                                                               \
		if (VITALS_DEBUG >= 1)                                                                                         \
			log_text_now(text);                                                                                        \
	} while (0)
#define log_status(text, status)                                                                                      \
	do {                                                                                                               \
		if (VITALS_DEBUG >= 1)                                                                                         \
			log_status_now((text), (status));                                                                          \
	} while (0)

/* 1 when there's a file at path (opened and closed again) */
static int file_exists(const char *path)
{
	int fd = -1;
	if (fs_open(path, FS_O_RDONLY, &fd) != 0)
		return 0;
	fs_close(fd);
	return 1;
}

#define OFF_FLAG VITALS_DNS_OFF

/* base: where byte 0 is; the hooks' entries, from entry.S. In order: lv2 is the one the addresses are
 * for (else nothing at all, as a call into a different lv2 could crash; logged when the file
 * functions at least are 4.93's), dns.off, rules in dns.txt (none: nothing to hook for),
 * then the table holds lv2's own descriptors; only then the hooks */
int plugin_main(uint64_t base, uint64_t sendto_entry, uint64_t recvfrom_entry)
{
	g_state.status = STATUS_STARTED;
	uint64_t mismatch = verify_lv2();
	if (mismatch != 0) {
		g_state.status = mismatch;
		/* The log needs cellFs: only when its four functions are the ones expected (indices 0 to 3) */
		if (mismatch >= STATUS_SIGNATURE + 4 || mismatch < STATUS_SIGNATURE)
			if (verify_lv2_files()) {
				log_status("vitals-dns: not 4.93's lv2, nothing hooked; status ", mismatch);
			}
		return 0;
	}
	uint64_t toc;
	__asm__("mr %0, 2" : "=r"(toc));
	Line line;
	if (VITALS_DEBUG >= 2) {
		line.used = 0;
		add_text(&line, "vitals-dns: kernel plugin loaded at ");
		add_hex(&line, base);
		add_text(&line, ", counts at ");
		add_hex(&line, (uint64_t)&g_state);
		write_line_at(2, &line);
	}
	if (file_exists(OFF_FLAG)) {
		g_state.status = STATUS_OFF;
		log_text("vitals-dns: dns.off is there: nothing hooked");
		return 0;
	}

	/* The rules, read once now (never from inside a hook) */
	int fd = -1;
	uint64_t got = 0;
	g_list_length = 0;
	if (fs_open(VITALS_DNS_LIST_PATH, FS_O_RDONLY, &fd) == 0) {
		(void)CALL(LV2_CELLFS_READ, fd, g_list, LIST_MAX, &got, 0, 0);
		fs_close(fd);
		g_list_length = got <= LIST_MAX ? got : 0;
	}
	/* No callbacks: C function pointers can't reach kernel addresses here (dns_rules.h) */
	vitals_dns_rules_init(&g_rules, 0);
	g_rules.rename = 1;
	g_state.rules = vitals_dns_rules_load_text(&g_rules, g_list, g_list_length, now_us());
	if (VITALS_DEBUG >= 1) {
		line.used = 0;
		add_text(&line, g_list_length == LIST_MAX ? "vitals-dns: dns.txt cut at 16 KB; rules: " : "vitals-dns: rules: ");
		line.text[line.used++] = (char)('0' + g_state.rules / 10 % 10);
		line.text[line.used++] = (char)('0' + g_state.rules % 10);
		write_line(&line);
	}
	if (g_state.rules == 0) {
		g_state.status = STATUS_NO_RULES;
		log_text("vitals-dns: no rules in dns.txt: nothing hooked");
		return 0;
	}

	volatile uint64_t *table = (volatile uint64_t *)LV2(LV2_SYSCALL_TABLE);
	if (table[LV2_SYSCALL_NET_SENDTO] != LV2(LV2_DESCRIPTOR_NET_SENDTO) ||
	    table[LV2_SYSCALL_NET_RECVFROM] != LV2(LV2_DESCRIPTOR_NET_RECVFROM) ||
	    ((const Lv2Descriptor *)table[LV2_SYSCALL_NET_SENDTO])->function != LV2(LV2_HANDLER_NET_SENDTO) ||
	    ((const Lv2Descriptor *)table[LV2_SYSCALL_NET_RECVFROM])->function != LV2(LV2_HANDLER_NET_RECVFROM)) {
		g_state.status = STATUS_TABLE_CHANGED;
		log_text("vitals-dns: not hooked: the syscall table doesn't hold lv2's own sendto and recvfrom");
		return 0;
	}
	const Lv2Descriptor *sendto = (const Lv2Descriptor *)table[LV2_SYSCALL_NET_SENDTO];
	const Lv2Descriptor *recvfrom = (const Lv2Descriptor *)table[LV2_SYSCALL_NET_RECVFROM];
	g_sendto_original.function = sendto->function;
	g_sendto_original.toc = sendto->toc;
	g_recvfrom_original.function = recvfrom->function;
	g_recvfrom_original.toc = recvfrom->toc;
	g_sendto_hook.function = sendto_entry;
	g_sendto_hook.toc = toc;
	g_recvfrom_hook.function = recvfrom_entry;
	g_recvfrom_hook.toc = toc;
	/* The descriptors are whole before the table points at them */
	sync_memory();
	if (VITALS_DEBUG >= 2) {
		line.used = 0;
		add_text(&line, "vitals-dns: swapping the table's entries");
		write_line_at(2, &line);
	}
	table[LV2_SYSCALL_NET_SENDTO] = (uint64_t)&g_sendto_hook;
	table[LV2_SYSCALL_NET_RECVFROM] = (uint64_t)&g_recvfrom_hook;
	sync_memory();
	g_state.status = STATUS_HOOKED;
	log_text("vitals-dns: sendto and recvfrom hooked");
	return 0;
}
