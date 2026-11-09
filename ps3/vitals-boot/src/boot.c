/* vitals' boot plugin, which Cobra loads into the XMB at boot (a line in /dev_hdd0/boot_plugins.txt):
 * it points Sony's libssl at vitals' with Cobra's path redirection, so every later load of
 * /dev_flash/sys/external/libssl.sprx, by the XMB or a game, gets vitals' file instead. Nothing in
 * flash changes, and the redirection ends at the next boot without the plugin. Its work done at
 * start, the plugin asks to be unloaded; the redirection stays in Cobra's table.
 *
 * libhttp is redirected the same way, to /dev_hdd0/vitals/system/libhttp.sprx, at every boot it's
 * there. vitals' modules answer as Sony's do, under Sony's names; the app's test tells them apart by
 * the marker each carries (common/vitals_marker.h).
 *
 * The DNS kernel plugin (/dev_hdd0/vitals/system/vitals_dns.bin) is loaded from here too, with
 * Cobra's syscall 8 as webMAN MOD loads one. Early versions froze the console when loaded at boot,
 * from here or from boot_plugins_kernel.txt: their hooks overflowed the kernel stack. It isn't loaded on a boot after one that didn't end properly (TURNOFF,
 * below): a power cut or a freeze, so a plugin that froze the console is left out of the next boot.
 *
 * The XMB's own TLS (the browser, PSN, the Store, trophies) is SSL-C built into vsh.elf, which the
 * redirection doesn't reach, and stays Sony's: vitals' libssl in the XMB, even loaded and unused,
 * takes the system down when a game starts. Built with VITALS_XMB (make plugin
 * XMB=1, for working on it only), xmb.c puts vitals' libssl in SSL-C's place, in memory, on 4.93's
 * XMB only, and not on a boot after one that didn't end properly; the plugin then stays loaded, as
 * the XMB's SSL calls go through its bridge, and xmb-tls.off and xmb-http.off turn it off.
 *
 * Each component has a switch in /dev_hdd0/vitals/flags (common/vitals_paths.h): while tls.off is
 * there, Sony's libssl stays for games (vitals' libhttp works on either); http.off, Sony's libhttp; dns.off, no DNS rules; redirects.off, no host redirects (vitals'
 * libhttp reads that one).
 *
 * Thirty seconds after start, a thread shows what this boot did in the XMB's own notification (the
 * vshtask_notify webMAN MOD and other plugins use): whether vitals' TLS and HTTP are on (Off when
 * turned off, and why when not installed or not mapped), how many DNS
 * rules are (read from the DNS plugin's state in kernel memory with Cobra's peek) and how many host
 * redirects redirects.txt has, with a check mark when all is on, a caution sign when something is
 * off and an error sign when something failed (the icon code is webMAN MOD's way, credited below). The plugin stays loaded (resident) for that thread's code. */

#include "vitals/log.h"
#include <stddef.h>
#include <stdint.h>

#include <sys/prx_module.h>

#include "vitals/host_map.h"
#include "vitals_log.h"
#include "vitals_log_format.h"
#include "vitals_paths.h"
#ifdef VITALS_XMB
#include "xmb.h"
#endif

/* The debug log, a build of its own per level as libssl's and libhttp's (make plugin DEBUG=N,
 * build/vitals-boot-debugN; the app installs the one the user picks): 0 writes nothing, 1 (Basic
 * debug) what happened at boot, 2 (Full debug) also addresses, codes and times. A line above the
 * build's level isn't in it */
#ifndef VITALS_DEBUG
#define VITALS_DEBUG 0
#endif
#ifndef VITALS_VERSION
#define VITALS_VERSION ""
#endif


/* vitals' files (common/vitals_paths.h): the modules in /dev_hdd0/vitals/system, the switches in
 * /dev_hdd0/vitals/flags */
#define SONY_LIBSSL "/dev_flash/sys/external/libssl.sprx"
#define SONY_LIBHTTP "/dev_flash/sys/external/libhttp.sprx"

/* Cobra's sys_map_path (lv2 syscall 35): old path, new path (NULL removes the redirection) */
#define COBRA_MAP_PATH 35
#define VITALS_LV2_FS_OPEN 801
#define VITALS_FS_READ_ONLY 0

#if VITALS_DEBUG >= 1
/* The log's sink here (vitals_log_sink.h): no C library, and vitals_log for the line */
void vitals_log_plain(const char *format, ...)
{
	char line[200];
	va_list arguments;
	va_start(arguments, format);
	vitals_log_vformat(line, sizeof(line), format, arguments);
	va_end(arguments);
	vitals_log(VITALS_LOG_NAME, line);
}
#endif

static int map_path(const char *from, const char *to)
{
	lv2syscall2(COBRA_MAP_PATH, (uint64_t)(uintptr_t)from, (uint64_t)(uintptr_t)to);
	return (int)p1;
}

/* Whether the file is there, so a missing install never sends Sony's modules to nothing */
static int file_exists(const char *path)
{
	int fd = -1;
	lv2syscall6(VITALS_LV2_FS_OPEN, (uint64_t)(uintptr_t)path, VITALS_FS_READ_ONLY, (uint64_t)(uintptr_t)&fd, 0, 0, 0);
	if (p1 != 0)
		return 0;
	vitals_log_close(fd);
	return 1;
}

/* Whether a component is on, and if not why, for the popup */
enum { ON, OFF_BY_FLAG, OFF_MISSING, OFF_FAILED };

/* vitals' libssl, unless tls.off is there or the module isn't */
static int map_libssl(void)
{
	char hex[9];
	if (file_exists(VITALS_TLS_OFF)) {
		VITALS_LOG("tls.off is there: Sony's libssl stays");
		return OFF_BY_FLAG;
	}
	if (!file_exists(VITALS_LIBSSL)) {
		VITALS_LOG("no " VITALS_LIBSSL ": Sony's libssl stays");
		return OFF_MISSING;
	}
	int result = map_path(SONY_LIBSSL, VITALS_LIBSSL);
	VITALS_LOG("map " SONY_LIBSSL " -> " VITALS_LIBSSL);
	VITALS_LOG("%s", vitals_log_hex((uint32_t)result, hex));
	return result == 0 ? ON : OFF_FAILED;
}

/* vitals' libhttp, unless http.off is there or the module isn't */
static int map_libhttp(void)
{
	char hex[9];
	if (file_exists(VITALS_HTTP_OFF)) {
		VITALS_LOG("http.off is there: Sony's libhttp stays");
		return OFF_BY_FLAG;
	}
	if (!file_exists(VITALS_LIBHTTP)) {
		VITALS_LOG("no " VITALS_LIBHTTP ": Sony's libhttp stays");
		return OFF_MISSING;
	}
	int result = map_path(SONY_LIBHTTP, VITALS_LIBHTTP);
	VITALS_LOG("map " SONY_LIBHTTP " -> " VITALS_LIBHTTP);
	VITALS_LOG("%s", vitals_log_hex((uint32_t)result, hex));
	return result == 0 ? ON : OFF_FAILED;
}

/* For diagnosis: built with -DVITALS_BOOT_STAY, the plugin stays loaded, so webMAN MOD's list of VSH
 * plugins shows whether the loader took it */
#ifdef VITALS_BOOT_STAY
#define VITALS_BOOT_DONE SYS_PRX_RESIDENT
#else
#define VITALS_BOOT_DONE SYS_PRX_NO_RESIDENT
#endif

/* ---- the DNS kernel plugin ---- */

#define DNS_PLUGIN VITALS_DNS_PLUGIN
#define DNS_OFF VITALS_DNS_OFF
/* The system's own marker while it runs: written a few seconds into each boot (after this plugin
 * starts), deleted at a proper shutdown. Found when this plugin starts, with a time from before, the
 * last boot didn't end properly (power cut, freeze): DNS isn't loaded on that boot */
#define TURNOFF "/dev_hdd0/tmp/turnoff"
/* A marker this much older than now is the last boot's, not this one's */
#define TURNOFF_STALE_SECONDS 10
/* The plugin's buffer: its 64 KB pages, larger than any build so far (about 57 KB) */
#define DNS_PLUGIN_MAX 0x20000u

#define VITALS_LV2_FS_READ 802
#define VITALS_LV2_FS_STAT 808
#define VITALS_LV2_TIME_NOW 145
#define VITALS_LV2_MEMORY_ALLOCATE 348
#define VITALS_LV2_MEMORY_FREE 349
#define VITALS_MEMORY_64K 0x200u
/* Cobra's lv2 peek (syscall 6): the 8 bytes at a kernel address, as webMAN MOD reads them */
#define COBRA_PEEK 6
#define VITALS_LV2_THREAD_EXIT 41
#define VITALS_LV2_TIMER_SLEEP 142
/* Where the DNS plugin's image says its State is (vitals-dns/kernel/entry.S), and in the State the
 * marker, the rules loaded and plugin_main's status (plugin.c) */
#define DNS_STATE_OFFSET_AT 0x50u
#define DNS_STATE_MARKER 0x766974616c73646eull /* "vitalsdn" */
#define DNS_STATE_RULES 32u
#define DNS_STATE_STATUS 56u
#define DNS_STATUS_OFF 3u
#define DNS_STATUS_NO_RULES 4u
#define DNS_STATUS_HOOKED 6u
/* Cobra's syscall 8: RUN_PAYLOAD_DYNAMIC(payload, size, &residence) copies the payload into kernel
 * memory, calls its first byte, keeps it, and gives where it is */
#define COBRA_SYSCALL8 8
#define COBRA_RUN_PAYLOAD_DYNAMIC 0x6CE1

/* One lv2 call each (PS3DK's lv2syscall macros declare their registers) */
static int fs_open(const char *path, int flags, int *fd)
{
	lv2syscall6(VITALS_LV2_FS_OPEN, (uint64_t)(uintptr_t)path, (uint64_t)flags, (uint64_t)(uintptr_t)fd, 0644, 0, 0);
	return (int)p1;
}

static int fs_read(int fd, void *buffer, uint64_t size, uint64_t *got)
{
	lv2syscall4(VITALS_LV2_FS_READ, fd, (uint64_t)(uintptr_t)buffer, size, (uint64_t)(uintptr_t)got);
	return (int)p1;
}

static int fs_stat(const char *path, void *stat)
{
	lv2syscall2(VITALS_LV2_FS_STAT, (uint64_t)(uintptr_t)path, (uint64_t)(uintptr_t)stat);
	return (int)p1;
}

static int64_t time_now(void)
{
	int64_t seconds = 0, nanoseconds = 0;
	lv2syscall2(VITALS_LV2_TIME_NOW, (uint64_t)(uintptr_t)&seconds, (uint64_t)(uintptr_t)&nanoseconds);
	return seconds;
}

/* lv2 writes the address as a 32-bit sys_addr_t */
static int memory_allocate(uint32_t size, uint32_t *address)
{
	lv2syscall3(VITALS_LV2_MEMORY_ALLOCATE, size, VITALS_MEMORY_64K, (uint64_t)(uintptr_t)address);
	return (int)p1;
}

static void memory_free(uint64_t address)
{
	lv2syscall1(VITALS_LV2_MEMORY_FREE, address);
}

static uint64_t peek(uint64_t address)
{
	lv2syscall1(COBRA_PEEK, address);
	return p1;
}

#if VITALS_DEBUG < 1
static void sleep_seconds(uint32_t seconds)
{
	lv2syscall1(VITALS_LV2_TIMER_SLEEP, seconds);
}
#endif

static void __attribute__((noreturn)) thread_exit(void)
{
	lv2syscall1(VITALS_LV2_THREAD_EXIT, 0);
	__builtin_unreachable();
}

static int run_payload(uint64_t payload, uint64_t size, uint64_t *residence)
{
	lv2syscall4(COBRA_SYSCALL8, COBRA_RUN_PAYLOAD_DYNAMIC, payload, size, (uint64_t)(uintptr_t)residence);
	return (int)p1;
}

/* lv2's stat, packed: mode, uid, gid, then atime, mtime and ctime (64-bit), size and block size */
typedef struct __attribute__((packed)) Lv2Stat {
	uint32_t mode;
	int32_t uid, gid;
	int64_t atime, mtime, ctime;
	uint64_t size, block_size;
} Lv2Stat;

/* 1 when the last boot didn't end properly: the system's turnoff marker is still there, from before */
static int last_boot_cut_short(void)
{
	Lv2Stat stat;
	if (fs_stat(TURNOFF, &stat) != 0)
		return 0;
	int64_t now = time_now();
	VITALS_VERBOSE("turnoff is there, written at" " %08X", (unsigned)((uint32_t)stat.mtime));
	VITALS_VERBOSE("time now:" " %08X", (unsigned)((uint32_t)now));
	return stat.mtime < now - TURNOFF_STALE_SECONDS;
}

/* What this boot did, for the notification */
enum { DNS_NONE, DNS_LEFT_OUT, DNS_SWITCHED_OFF, DNS_FAILED, DNS_LOADED };
static int g_ssl = OFF_MISSING, g_http = OFF_MISSING, g_dns = DNS_NONE;
#ifdef VITALS_XMB
static int g_xmb = XMB_NONE;
#endif
static uint64_t g_dns_at;

/* The DNS plugin into kernel memory, through a buffer of this process's: DNS_LOADED (and where, in
 * g_dns_at), DNS_SWITCHED_OFF or DNS_FAILED */
static int load_dns(void)
{
	if (file_exists(DNS_OFF)) {
		VITALS_LOG("dns: dns.off is there: not loaded");
		return DNS_SWITCHED_OFF;
	}
	uint32_t buffer = 0;
	int rc = memory_allocate(DNS_PLUGIN_MAX, &buffer);
	if (rc != 0) {
		VITALS_LOG("dns: no memory for the plugin:" " %08X", (unsigned)((uint32_t)rc));
		return DNS_FAILED;
	}
	int loaded = DNS_FAILED;
	int fd = -1;
	uint64_t got = 0;
	int64_t size = -1;
	rc = fs_open(DNS_PLUGIN, VITALS_FS_READ_ONLY, &fd);
	if (rc != 0) {
		VITALS_LOG("dns: can't open " DNS_PLUGIN ":" " %08X", (unsigned)((uint32_t)rc));
	} else {
		rc = fs_read(fd, (void *)(uintptr_t)buffer, DNS_PLUGIN_MAX, &got);
		vitals_log_close(fd);
		if (rc != 0)
			VITALS_LOG("dns: can't read " DNS_PLUGIN ":" " %08X", (unsigned)((uint32_t)rc));
		else
			size = (int64_t)got;
	}
	if (size <= 0x230 || size >= (int64_t)DNS_PLUGIN_MAX || (size & 7) != 0) {
		VITALS_LOG("dns: can't use " DNS_PLUGIN ", size" " %08X", (unsigned)((uint32_t)size));
	} else {
		uint64_t residence = 0;
		VITALS_LOG("dns: loading " DNS_PLUGIN);
		rc = run_payload(buffer, (uint64_t)size, &residence);
		VITALS_VERBOSE("dns: loaded:" " %08X", (unsigned)((uint32_t)rc));
		VITALS_VERBOSE("dns: at (low 32 bits)" " %08X", (unsigned)((uint32_t)residence));
		if (rc != 0 && residence != 0) {
			g_dns_at = residence;
			loaded = DNS_LOADED;
		}
	}
	memory_free(buffer);
	return loaded;
}

/* ---- the notification: the XMB's own (vshtask_notify), as webMAN MOD and others show theirs ---- */

#define NOTIFY_LIBRARY "vshtask"
#define NOTIFY_NID 0xA02D46E7u
/* Seconds after start: shown 10 seconds in, the XMB showed nothing (SoundShaper waits 10 before
 * anything, webMAN MOD longer) */
#define NOTIFY_DELAY 30u
#define NOTIFY_MAX 200u

static int same_text(const char *a, const char *b)
{
	while (*a != '\0' && *a == *b)
		++a, ++b;
	return *a == *b;
}

/* The XMB's export of a function by library and NID, from its export table, as webMAN MOD finds it:
 * the address of the function's descriptor, or 0 */
static uint32_t vsh_export(const char *library, uint32_t nid)
{
	uint32_t table = *(volatile uint32_t *)0x1008Cu + 0x984u;
	for (; *(volatile uint32_t *)(uintptr_t)table != 0; table += 4) {
		uint32_t export = *(volatile uint32_t *)(uintptr_t)table;
		const char *name = (const char *)(uintptr_t)*(volatile uint32_t *)(uintptr_t)(export + 0x10);
		if (name == 0 || !same_text(library, name))
			continue;
		uint32_t nids = *(volatile uint32_t *)(uintptr_t)(export + 0x14);
		uint32_t functions = *(volatile uint32_t *)(uintptr_t)(export + 0x18);
		uint16_t count = *(volatile uint16_t *)(uintptr_t)(export + 6);
		for (uint32_t i = 0; i < count; ++i)
			if (*(volatile uint32_t *)(uintptr_t)(nids + 4 * i) == nid)
				return *(volatile uint32_t *)(uintptr_t)(functions + 4 * i);
	}
	return 0;
}

typedef struct Text {
	char text[NOTIFY_MAX + 1];
	uint32_t used;
} Text;

static void add(Text *text, const char *more)
{
	while (*more != '\0' && text->used < NOTIFY_MAX)
		text->text[text->used++] = *more++;
	text->text[text->used] = '\0';
}

static void add_number(Text *text, uint64_t value)
{
	char digits[21];
	int n = 0;
	do
		digits[n++] = (char)('0' + value % 10);
	while ((value /= 10) != 0 && n < 20);
	char one[2] = {0, 0};
	while (n > 0) {
		one[0] = digits[--n];
		add(text, one);
	}
}

/* How the report went, for its icon: all on, something off, something that failed */
enum { ALL_ON, CAUTION, TROUBLE };
static int g_concern = ALL_ON;

static void concern(int level)
{
	if (level > g_concern)
		g_concern = level;
}

/* The DNS line: how many rules the plugin hooked with, read from its State in kernel memory */
static void add_dns(Text *text)
{
	switch (g_dns) {
	case DNS_LEFT_OUT:
		add(text, "\nDNS rules: Off (the console wasn't turned off properly)");
		concern(CAUTION);
		return;
	case DNS_SWITCHED_OFF:
		add(text, "\nDNS rules: Off");
		concern(CAUTION);
		return;
	case DNS_FAILED:
		add(text, "\nDNS rules: Off (not loaded, see vitals.log)");
		concern(TROUBLE);
		return;
	case DNS_LOADED:
		break;
	default:
		return;
	}
	uint64_t state = g_dns_at + peek(g_dns_at + DNS_STATE_OFFSET_AT);
	if (peek(state) != DNS_STATE_MARKER) {
		add(text, "\nDNS rules: On");
		return;
	}
	uint64_t rules = peek(state + DNS_STATE_RULES), status = peek(state + DNS_STATE_STATUS);
	if (status == DNS_STATUS_HOOKED) {
		add(text, "\nDNS rules: ");
		add_number(text, rules);
	} else if (status == DNS_STATUS_NO_RULES) {
		add(text, "\nDNS rules: 0");
	} else if (status == DNS_STATUS_OFF) {
		add(text, "\nDNS rules: Off");
		concern(CAUTION);
	} else {
		add(text, "\nDNS rules: Off (not hooked, see vitals.log)");
		concern(TROUBLE);
	}
}

#define REDIRECTS VITALS_REDIRECTS
/* As vitals-http reads it (redirect.c): 16 KB at most */
#define REDIRECTS_MAX 16384u

/* The redirects line: how many pairs redirects.txt has, parsed as vitals' libhttp parses it
 * (shared/src/host_map.c); only with vitals' libhttp, which applies them */
static void add_redirects(Text *text)
{
	if (g_http != ON)
		return;
	if (file_exists(VITALS_REDIRECTS_OFF)) {
		add(text, "\nRedirects: Off");
		concern(CAUTION);
		return;
	}
	uint32_t buffer = 0;
	if (memory_allocate(0x10000u, &buffer) != 0)
		return;
	char *list = (char *)(uintptr_t)buffer;
	int fd = -1;
	uint64_t got = 0;
	if (fs_open(REDIRECTS, VITALS_FS_READ_ONLY, &fd) == 0) {
		if (fs_read(fd, list, REDIRECTS_MAX, &got) != 0)
			got = 0;
		vitals_log_close(fd);
	}
	VitalsHostMap map;
	size_t count = vitals_host_map_parse(&map, list, (size_t)got);
	memory_free(buffer);
	add(text, "\nRedirects: ");
	add_number(text, count);
}

/* ---- the icon: thanks to aldostools, webMAN MOD's creator, whose show_msg_with_icon
 * (include/notify/vsh_notify.h, itself based on PHTNC's code) showed how. The XMB's
 * vshcommon_A20E43DB (webMAN's NotifyWithTexture, which vshtask_notify calls with
 * "tex_notification_info", the "i") takes an image from one of the XMB's plugins, found with paf's
 * View_Find and loaded with its LoadRCOTexture, and the text in UTF-16 (wchar_t is 16-bit on the
 * PS3). Only the XMB's own images: the names below are from webMAN's table ---- */

#define PAF_VIEW_FIND 0xF21655F3u
#define PAF_LOAD_RCO_TEXTURE 0x3A8454FCu
#define VSHCOMMON_NOTIFY_WITH_TEXTURE 0xA20E43DBu

typedef struct Icon {
	const char *plugin, *texture;
} Icon;

static const Icon k_icons[] = {
	[ALL_ON] = {"explore_plugin", "tex_check_ws"},
	[CAUTION] = {"system_plugin", "tex_notification_caution"},
	[TROUBLE] = {"explore_plugin", "tex_indi_Sign_out"},
};

/* The message with the icon for level: 0 when shown, else -1 (the caller shows it plainly) */
static int notify_with_icon(int level, const char *message)
{
	uint32_t find = vsh_export("paf", PAF_VIEW_FIND), load = vsh_export("paf", PAF_LOAD_RCO_TEXTURE),
	         show = vsh_export("vshcommon", VSHCOMMON_NOTIFY_WITH_TEXTURE);
	if (find == 0 || load == 0 || show == 0) {
		VITALS_LOG("no XMB notification with an icon: shown without");
		return -1;
	}
	const Icon *icon = &k_icons[level];
	uint32_t plugin = ((uint32_t(*)(const char *))(uintptr_t)find)(icon->plugin);
	if (plugin == 0) {
		VITALS_LOG("the icon's XMB plugin isn't there: shown without");
		return -1;
	}
	int32_t texture = 0, dummy = 0;
	(void)((uint32_t(*)(int32_t *, uint32_t, const char *))(uintptr_t)load)(&texture, plugin, icon->texture);
	uint16_t wide[NOTIFY_MAX + 1];
	uint32_t n = 0;
	for (; message[n] != '\0' && n < NOTIFY_MAX; ++n)
		wide[n] = (uint16_t)(unsigned char)message[n];
	wide[n] = 0;
	typedef uint32_t (*NotifyWithTexture)(int32_t, const char *, int32_t, int32_t *, int32_t *, const char *, const char *,
	                                      float, const uint16_t *, int32_t, int32_t, int32_t);
	uint32_t rc = ((NotifyWithTexture)(uintptr_t)show)(0, icon->texture, 0, &texture, &dummy, "", "", 0.0f, wide, 0, 0, 0);
	VITALS_VERBOSE("shown with an icon:" " %08X", (unsigned)(rc));
	return 0;
}

/* The popup's title: "vitals", this build's version, and its debug level by the app's names for them
 * (vitals-app/src/main.c's debug_names: Off, Basic debug, Full debug), as "vitals 2.0 - Basic debug" */
static void add_title(Text *title)
{
	add(title, "vitals");
	if (VITALS_VERSION[0] != '\0') {
		add(title, " ");
		add(title, VITALS_VERSION);
	}
	if (VITALS_DEBUG == 1)
		add(title, " - Basic debug");
	else if (VITALS_DEBUG == 2)
		add(title, " - Full debug");
}

/* Why games' TLS isn't on, after "Off" (or "XMB only"): nothing when Options turned it off */
static void add_games_reason(Text *text)
{
	if (g_ssl == OFF_MISSING)
		add(text, " (not installed)");
	else if (g_ssl == OFF_FAILED)
		add(text, " (not mapped, see vitals.log)");
}

#ifdef VITALS_XMB
/* Why the XMB's TLS isn't on, after "Games only" or "Off": nothing when Options turned it off */
static void add_xmb_reason(Text *text)
{
	switch (g_xmb) {
	case XMB_LEFT_OUT:
		add(text, " (XMB: the console wasn't turned off properly)");
		break;
	case XMB_OTHER:
		add(text, " (XMB: not 4.93's)");
		break;
	case XMB_TOO_LATE:
		add(text, " (XMB: it started its own first)");
		break;
	case XMB_DRY_RUN:
		add(text, " (XMB: dry run, see vitals.log)");
		break;
	case XMB_PENDING:
		add(text, " (XMB: still loading)");
		break;
	case XMB_FAILED:
		add(text, " (XMB failed, see vitals.log)");
		concern(TROUBLE);
		break;
	default:
		break;
	}
}

/* The TLS line: games' (libssl's redirection) and the XMB's own together: On when both are, Games
 * only or XMB only when one is, Off when neither, with why when it wasn't Options */
static void add_tls(Text *text)
{
	if (g_xmb == XMB_PENDING)
		g_xmb = vitals_xmb_state();
	int games = g_ssl == ON, xmb = g_xmb == XMB_ON;
	add(text, "\nTLS: ");
	if (games && xmb) {
		add(text, "On");
		return;
	}
	concern(CAUTION);
	if (games) {
		add(text, "Games only");
		add_xmb_reason(text);
	} else if (xmb) {
		add(text, "XMB only");
		add_games_reason(text);
	} else {
		add(text, "Off");
		/* Not installed says it for both */
		add_games_reason(text);
		if (g_ssl != OFF_MISSING)
			add_xmb_reason(text);
	}
}

/* The HTTP line, as the TLS one: games' (libhttp's redirection) and the XMB's own together */
static void add_http(Text *text)
{
	int xmb_state = vitals_xmb_http_state();
	int games = g_http == ON, xmb = xmb_state == XMB_ON;
	add(text, "\nHTTP: ");
	if (games && xmb) {
		add(text, "On");
		return;
	}
	concern(CAUTION);
	const char *why = xmb_state == XMB_FAILED     ? " (XMB failed, see vitals.log)"
	                  : xmb_state == XMB_TOO_LATE ? " (XMB: it started its own first)"
	                  : xmb_state == XMB_OTHER    ? " (XMB: not 4.93's)"
	                  : xmb_state == XMB_PENDING  ? " (XMB: still loading)"
	                  : xmb_state == XMB_DRY_RUN  ? " (XMB: dry run, see vitals.log)"
	                  : xmb_state == XMB_LEFT_OUT ? " (XMB: the console wasn't turned off properly)"
	                  : xmb_state == XMB_NEEDS_TLS ? " (XMB: its TLS is Sony's)"
	                                              : "";
	if (xmb_state == XMB_FAILED)
		concern(TROUBLE);
	if (games) {
		add(text, "Games only");
		add(text, why);
	} else if (xmb) {
		add(text, "XMB only");
	} else {
		add(text, g_http == OFF_MISSING ? "Off (not installed)" : g_http == OFF_FAILED ? "Off (not mapped, see vitals.log)" : "Off");
		if (g_http != OFF_MISSING && g_http != OFF_FAILED)
			add(text, why);
	}
}
#else
/* The TLS line: On, or Off with why when it wasn't Options */
static void add_tls(Text *text)
{
	add(text, "\nTLS: ");
	if (g_ssl == ON) {
		add(text, "On");
		return;
	}
	concern(CAUTION);
	add(text, "Off");
	add_games_reason(text);
}

/* The HTTP line, as the TLS one */
static void add_http(Text *text)
{
	add(text, "\nHTTP: ");
	if (g_http == ON) {
		add(text, "On");
		return;
	}
	concern(CAUTION);
	add(text, g_http == OFF_MISSING ? "Off (not installed)" : g_http == OFF_FAILED ? "Off (not mapped, see vitals.log)" : "Off");
}
#endif

#if VITALS_DEBUG >= 1
/* Each DNS query in the log (dns_query_log.h), from this thread: four passes a second, and only while
 * the DNS plugin's hooks are in */
#include "dns_query_log.h"
#define VITALS_LV2_TIMER_USLEEP 141
#define DNS_LOG_PASS_MICROSECONDS 250000u
static uint64_t g_dns_state, g_dns_seen;

static void dns_log_line(const char *line)
{
	vitals_log("vitals-dns", line);
}

static void dns_log_begin(void)
{
	if (g_dns != DNS_LOADED)
		return;
	uint64_t state = g_dns_at + peek(g_dns_at + DNS_STATE_OFFSET_AT);
	if (peek(state) == DNS_STATE_MARKER && peek(state + DNS_STATE_STATUS) == DNS_STATUS_HOOKED)
		g_dns_state = state;
}

static void dns_log_wait(void)
{
	lv2syscall1(VITALS_LV2_TIMER_USLEEP, DNS_LOG_PASS_MICROSECONDS);
	if (g_dns_state != 0)
		g_dns_seen = vitals_dns_log_step(g_dns_state, g_dns_seen, peek, dns_log_line, VITALS_DEBUG >= 2);
}
#endif

static void notify_thread(void *arg)
{
	(void)arg;
#if VITALS_DEBUG >= 1
	dns_log_begin();
	for (unsigned i = 0; i < NOTIFY_DELAY * 4; ++i)
		dns_log_wait();
#else
	sleep_seconds(NOTIFY_DELAY);
#endif
	Text text = {{0}, 0};
	/* The name, then an empty line before the report */
	add_title(&text);
	add(&text, "\n");
	add_tls(&text);
	add_http(&text);
	add_redirects(&text);
	add_dns(&text);
	uint32_t notify = notify_with_icon(g_concern, text.text) == 0 ? 0 : vsh_export(NOTIFY_LIBRARY, NOTIFY_NID);
	if (notify != 0) {
		int (*show)(int, const char *) = (int (*)(int, const char *))(uintptr_t)notify;
		uint32_t shown = (uint32_t)show(0, text.text);
		VITALS_VERBOSE("shown:" " %08X", (unsigned)(shown));
	}
	VITALS_LOG("%s", text.text);
#if VITALS_DEBUG >= 1
	while (g_dns_state != 0)
		dns_log_wait();
#endif
	thread_exit();
}

extern int32_t sysThreadCreate(uint32_t *thread, void (*entry)(void *), void *arg, int32_t priority, uint64_t stack,
                               uint64_t flags, char *name);

/* 1 when the notification's thread runs (this module then has to stay, for its code) */
static int start_notify(void)
{
	uint32_t thread = 0;
	int32_t rc = sysThreadCreate(&thread, notify_thread, 0, 3000, 0x4000, 0, (char *)"vitals_notify");
	if (rc != 0) {
		VITALS_LOG("no notification thread:" " %08X", (unsigned)((uint32_t)rc));
		return 0;
	}
	return 1;
}

int module_start(size_t args, void *argp)
{
	(void)args, (void)argp;
	VITALS_LOG("start");
	int cut_short = last_boot_cut_short();
	g_ssl = map_libssl();
	/* vitals' libhttp on whichever libssl games get: it calls libssl through Sony's exports, as Sony's
	 * libhttp does, so its switch is its own (the libhttp probe on Sony's libssl in RPCS3, where it
	 * differs from Sony's libhttp only as on vitals', tools/http_probe.sh) */
	g_http = map_libhttp();
#ifdef VITALS_XMB
	/* The XMB's own TLS has its switch (xmb-tls.off): it needs vitals' libssl there, not games' TLS on */
	if (file_exists(VITALS_LIBSSL))
		g_xmb = vitals_xmb_start(cut_short);
#endif
	if (file_exists(DNS_PLUGIN)) {
		if (cut_short) {
			/* This boot only: the next one after a proper shutdown loads it again */
			VITALS_LOG("dns: the last boot didn't end properly (the system's turnoff marker is "
			                          "still there): not loaded this boot");
			g_dns = DNS_LEFT_OUT;
		} else {
			g_dns = load_dns();
		}
	}
	int notifying = start_notify();
#ifdef VITALS_XMB
	/* The XMB's thread runs this module's code, and once it's done the XMB's SSL calls go through
	 * this module's bridge (xmb_bridge.S): it stays */
	if (g_xmb == XMB_PENDING)
		return SYS_PRX_RESIDENT;
#endif
	return notifying ? SYS_PRX_RESIDENT : VITALS_BOOT_DONE;
}
