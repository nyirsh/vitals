/* vitals' TLS and HTTP for the XMB itself: the browser, PSN, the Store and trophies use the XMB's own
 * copies of Sony's SSL-C and libhttp, built into vsh.elf, not /dev_flash/sys/external's. Everything in the XMB reaches SSL-C through its 114 cellSsl
 * functions only, and libhttp through its 201 cellHttp and cellHttpUtil ones, so they are what
 * changes: SSL first, as below, then libhttp the same way once SSL is vitals' (vitals' libhttp works
 * on vitals' libssl), unless xmb-http.off is there:
 *
 * 1. Checks, writing nothing: xmb-tls.off isn't there and the last boot ended properly; the XMB is 4.93's
 *    as tools/vsh_ssl.py read it (each function's descriptor in its export table, its code, its first
 *    instruction, and the island area's checksum, xmb_493.h); and the XMB hasn't started SSL yet
 *    (_cellSslIsInitd), so no object of SSL-C's is ever handed to vitals'.
 * 2. vitals' libssl (system/libssl.sprx, the one games load) is loaded into the XMB and asked for its
 *    114 functions (common/vitals_xmb.h).
 * 3. Written with Cobra's PS3MAPI (the XMB's code isn't writable from inside it), first the islands,
 *    6 instructions each in an SSL-C function only SSL-C reaches (dead once nothing calls SSL-C):
 *    vitals' descriptor into r11 and a jump to the bridge (xmb_bridge.S); then over each function's
 *    first instruction, a branch to its island. A branch that doesn't take puts the ones before back.
 *
 * 2 and 3 run on a thread of their own: the system's module loader waits while a module's
 * module_start runs, so loading libssl from the boot plugin's own start never returned (the first
 * dry run on a console). The thread checks again that the XMB hasn't started SSL in the meantime.
 *
 * It's all in memory: a boot without it is the XMB as Sony made it. Built with VITALS_XMB_DRY_RUN,
 * it does 1 and 2, logs what it found, unloads libssl again and writes nothing. */

#include "vitals/log.h"
#include <stddef.h>
#include <stdint.h>

#include <lv2/prx.h>

#include "vitals_log.h"
#include "vitals_paths.h"
#include "vitals_xmb.h"
#include "xmb.h"
#include "xmb_493.h"

#ifndef VITALS_DEBUG
#define VITALS_DEBUG 0
#endif


#define XMB_IS_INITD_NID 0x23F0FD4Eu
#define LV2_GET_PID 1
#define LV2_THREAD_EXIT 41
#define LV2_FS_OPEN 801
#define LV2_MEMORY_SIZE 352
/* lv2's debug write of a process's memory: pid, address, size, source (VshFpsCounter's first way) */
#define LV2_DBG_WRITE_PROCESS_MEMORY 905
/* Cobra's PS3MAPI, through syscall 8: a process's memory, written (webMAN MOD's ps3mapi.h) */
#define COBRA_SYSCALL8 8
#define PS3MAPI 0x7777
#define PS3MAPI_SET_PROC_MEM 0x0032
/* What PS3MAPI is given at a time, as VshFpsCounter writes the XMB's code (webMAN MOD's own writes
 * are 256 bytes at most): 2736 bytes in one call answered 0 and wrote nothing */
#define WRITE_PIECE 16u

extern const uint32_t vitals_xmb_bridge[];

static int file_exists(const char *path)
{
	int fd = -1;
	lv2syscall6(LV2_FS_OPEN, (uint64_t)(uintptr_t)path, 0, (uint64_t)(uintptr_t)&fd, 0, 0, 0);
	if (p1 != 0)
		return 0;
	vitals_log_close(fd);
	return 1;
}

static uint32_t process_id(void)
{
	lv2syscall0(LV2_GET_PID);
	return (uint32_t)p1;
}

/* sys_memory_get_user_memory_size: the process's memory, in all and free */
static void memory_size(uint32_t *total, uint32_t *available)
{
	uint32_t info[2] = {0, 0};
	lv2syscall1(LV2_MEMORY_SIZE, (uint64_t)(uintptr_t)info);
	*total = info[0];
	*available = info[1];
}

static uint32_t word_at(uint32_t address)
{
	return *(volatile const uint32_t *)(uintptr_t)address;
}

/* The process id is read before each call: the lv2syscall macros set r3 and on one by one, so a
 * call among their arguments (process_id() is a syscall itself) overwrote the ones before it, and
 * Cobra was handed the process id as its function (it answered 0, doing nothing) */
static int dbg_write(uint32_t address, const void *data, uint32_t size)
{
	uint64_t pid = process_id();
	lv2syscall4(LV2_DBG_WRITE_PROCESS_MEMORY, pid, address, size, (uint64_t)(uintptr_t)data);
	return (int)p1;
}

static int ps3mapi_write_piece(uint32_t address, const void *data, uint32_t size)
{
	uint64_t pid = process_id();
	lv2syscall6(COBRA_SYSCALL8, PS3MAPI, PS3MAPI_SET_PROC_MEM, pid, address, (uint64_t)(uintptr_t)data, size);
	return (int)p1;
}

static int ps3mapi_write(uint32_t address, const void *data, uint32_t size)
{
	for (uint32_t done = 0; done < size; done += WRITE_PIECE) {
		uint32_t piece = size - done < WRITE_PIECE ? size - done : WRITE_PIECE;
		int rc = ps3mapi_write_piece(address + done, (const uint8_t *)data + done, piece);
		if (rc != 0)
			return rc;
	}
	return 0;
}

/* The XMB's code written, as VshFpsCounter writes it: lv2's debug write, else Cobra's PS3MAPI (the
 * first that answers 0 is used from then on); each one's answer logged the first time */
static int g_writer;

static int write_code(uint32_t address, const void *data, uint32_t size)
{
	if (g_writer == 1)
		return dbg_write(address, data, size);
	if (g_writer == 2)
		return ps3mapi_write(address, data, size);
	int rc = dbg_write(address, data, size);
	VITALS_VERBOSE("xmb: lv2's debug write answered" " %08X", (unsigned)((uint32_t)rc));
	if (rc == 0) {
		g_writer = 1;
		return 0;
	}
	rc = ps3mapi_write(address, data, size);
	VITALS_VERBOSE("xmb: PS3MAPI's write answered" " %08X", (unsigned)((uint32_t)rc));
	if (rc == 0)
		g_writer = 2;
	return rc;
}


static int same_text(const char *a, const char *b)
{
	while (*a != '\0' && *a == *b)
		++a, ++b;
	return *a == *b;
}

/* The descriptor the XMB's export table gives for a library's NID, as webMAN MOD finds it, or 0 */
static uint32_t xmb_export(const char *library, uint32_t nid)
{
	uint32_t table = word_at(0x1008Cu) + 0x984u;
	for (; word_at(table) != 0; table += 4) {
		uint32_t export = word_at(table);
		const char *name = (const char *)(uintptr_t)word_at(export + 0x10);
		if (name == 0 || !same_text(library, name))
			continue;
		uint32_t nids = word_at(export + 0x14), functions = word_at(export + 0x18);
		uint16_t count = *(volatile const uint16_t *)(uintptr_t)(export + 6);
		for (uint32_t i = 0; i < count; ++i)
			if (word_at(nids + 4 * i) == nid)
				return word_at(functions + 4 * i);
	}
	return 0;
}

/* One library put in the XMB's place: vitals' module, the XMB's functions it takes over and where
 * their islands go (xmb_493.h) */
typedef struct XmbLibrary {
	/* module: games' file; copy: the XMB's own, loaded instead when it's there */
	const char *name, *module, *copy;
	const XmbFunction *table;
	uint32_t count, area, area_size, area_fnv1a;
	uint32_t *islands;
} XmbLibrary;

static const char *const k_library_names[] = {"cellSsl", "cellHttp", "cellHttpUtil"};

static uint32_t g_ssl_islands[XMB_SSL_COUNT * XMB_ISLAND_WORDS];
static uint32_t g_http_islands[XMB_HTTP_COUNT * XMB_ISLAND_WORDS];

static const XmbLibrary k_ssl = {"SSL", VITALS_LIBSSL, VITALS_LIBSSL_XMB, k_xmb_ssl, XMB_SSL_COUNT, XMB_SSL_ISLAND_AREA,
                                 XMB_SSL_ISLAND_AREA_SIZE, XMB_SSL_ISLAND_AREA_FNV1A, g_ssl_islands};
static const XmbLibrary k_http = {"HTTP", VITALS_LIBHTTP, VITALS_LIBHTTP_XMB, k_xmb_http, XMB_HTTP_COUNT, XMB_HTTP_ISLAND_AREA,
                                  XMB_HTTP_ISLAND_AREA_SIZE, XMB_HTTP_ISLAND_AREA_FNV1A, g_http_islands};

/* 1 when the XMB is the 4.93 one xmb_493.h was made from, at every place this writes for library */
static int xmb_is_493(const XmbLibrary *library)
{
	for (uint32_t i = 0; i < library->count; ++i) {
		const XmbFunction *f = &library->table[i];
		if (xmb_export(k_library_names[f->library], f->nid) != f->descriptor || word_at(f->descriptor) != f->code ||
		    word_at(f->code) != f->first) {
			VITALS_LOG("%s", library->name);
			VITALS_LOG("xmb: not 4.93's XMB, at NID" " %08X", (unsigned)(f->nid));
			return 0;
		}
	}
	uint32_t hash = 0x811C9DC5u;
	for (uint32_t i = 0; i < library->area_size; ++i)
		hash = (hash ^ *(volatile const uint8_t *)(uintptr_t)(library->area + i)) * 0x01000193u;
	if (hash != library->area_fnv1a) {
		VITALS_LOG("%s", library->name);
		VITALS_LOG("xmb: not 4.93's XMB, the island area's checksum is" " %08X", (unsigned)(hash));
		return 0;
	}
	return 1;
}

#ifdef VITALS_XMB_DRY_RUN
/* For where a module's memory goes: what's free now */
static void free_now(const char *when)
{
	uint32_t total = 0, available = 0;
	memory_size(&total, &available);
	VITALS_LOG("%s %08X", when, (unsigned)(available));
}
#endif

static uint32_t vitals_descriptor(const VitalsXmbRequest *request, uint32_t nid)
{
	for (uint32_t i = 0; i < request->count && i < VITALS_XMB_FUNCTIONS; ++i)
		if (request->functions[i].nid == nid)
			return request->functions[i].descriptor;
	return 0;
}

#define LIS(r, value) (0x3C000000u | ((uint32_t)(r) << 21) | ((value) >> 16))
#define ORI(r, value) (0x60000000u | ((uint32_t)(r) << 21) | ((uint32_t)(r) << 16) | ((value) & 0xFFFFu))
#define MTCTR(r) (0x7C0903A6u | ((uint32_t)(r) << 21))
#define BCTR 0x4E800420u
#define BRANCH(from, to) (0x48000000u | (((to) - (from)) & 0x03FFFFFCu))

/* The islands, then the branches; XMB_ON, or XMB_FAILED with the XMB as it was. A dry run makes
 * them, logs the first island and branch, and writes nothing (XMB_DRY_RUN) */
static int patch(const XmbLibrary *library, const VitalsXmbRequest *request, int dry)
{
	uint32_t bridge = (uint32_t)(uintptr_t)vitals_xmb_bridge;
	uint32_t *islands = library->islands;
	for (uint32_t i = 0; i < library->count; ++i) {
		uint32_t target = vitals_descriptor(request, library->table[i].nid);
		if (target == 0) {
			VITALS_LOG("xmb: vitals' module has no function for NID" " %08X", (unsigned)(library->table[i].nid));
			return XMB_FAILED;
		}
		uint32_t *island = &islands[i * XMB_ISLAND_WORDS];
		island[0] = LIS(11, target);
		island[1] = ORI(11, target);
		island[2] = LIS(12, bridge);
		island[3] = ORI(12, bridge);
		island[4] = MTCTR(12);
		island[5] = BCTR;
	}
	if (dry) {
		VITALS_VERBOSE("%s", library->name);
		VITALS_VERBOSE("xmb: dry run: the first function, at" " %08X", (unsigned)(library->table[0].code));
		VITALS_VERBOSE("xmb: dry run: would branch with" " %08X", (unsigned)(BRANCH(library->table[0].code, library->area)));
		for (uint32_t i = 0; i < XMB_ISLAND_WORDS; ++i)
			VITALS_VERBOSE("xmb: dry run: to its island's instruction" " %08X", (unsigned)(islands[i]));
		return XMB_DRY_RUN;
	}
	uint32_t words = library->count * XMB_ISLAND_WORDS;
	int rc = write_code(library->area, islands, words * 4);
	if (rc != 0) {
		/* Nothing calls the island area yet: the XMB's functions are still its own */
		VITALS_LOG("xmb: the islands couldn't be written");
		return XMB_FAILED;
	}
	for (uint32_t i = 0; i < words; ++i)
		if (word_at(library->area + 4 * i) != islands[i]) {
			VITALS_LOG("xmb: written, but the islands read back otherwise, at word" " %08X", (unsigned)(i));
			return XMB_FAILED;
		}
	for (uint32_t i = 0; i < library->count; ++i) {
		uint32_t code = library->table[i].code;
		uint32_t branch = BRANCH(code, library->area + 4 * XMB_ISLAND_WORDS * i);
		rc = write_code(code, &branch, sizeof(branch));
		if (rc == 0 && word_at(code) != branch)
			rc = -1;
		if (rc != 0) {
			VITALS_LOG("xmb: a branch didn't take, at" " %08X", (unsigned)(code));
			for (uint32_t j = 0; j < i; ++j)
				(void)write_code(library->table[j].code, &library->table[j].first, sizeof(library->table[j].first));
			return XMB_FAILED;
		}
	}
	return XMB_ON;
}

/* vitals' module for library, loaded into the XMB and asked for its functions: 0 with its id, or
 * XMB_FAILED */
static int load(const XmbLibrary *library, sysPrxId *id, VitalsXmbRequest *request)
{
	const char *path = file_exists(library->copy) ? library->copy : library->module;
	VITALS_LOG("%s", path);
	*id = sysPrxLoadModule(path, 0, NULL);
	VITALS_VERBOSE("xmb: loaded, id" " %08X", (unsigned)((uint32_t)*id));
	if (*id < 0) {
		VITALS_LOG("xmb: can't load it:" " %08X", (unsigned)((uint32_t)*id));
		return XMB_FAILED;
	}
	request->magic = VITALS_XMB_MAGIC;
	request->count = 0;
	s32 result = 0;
	s32 rc = sysPrxStartModule(*id, sizeof(*request), request, &result, 0, NULL);
	VITALS_VERBOSE("xmb: started:" " %08X", (unsigned)((uint32_t)rc));
	uint32_t total = 0, available = 0;
	memory_size(&total, &available);
	VITALS_LOG("xmb: free with it loaded (bytes):" " %08X", (unsigned)(available));
	if (rc != 0 || request->count < library->count) {
		VITALS_LOG("xmb: it didn't give its functions:" " %08X", (unsigned)((uint32_t)rc));
		VITALS_LOG("xmb: functions given:" " %08X", (unsigned)(request->count));
		return XMB_FAILED;
	}
	for (uint32_t i = 0; i < library->count; ++i)
		if (vitals_descriptor(request, library->table[i].nid) == 0) {
			VITALS_LOG("xmb: it has no function for NID" " %08X", (unsigned)(library->table[i].nid));
			return XMB_FAILED;
		}
	return 0;
}

/* Unloaded again, so no plugin loaded later takes its library over the XMB's */
static void unload(sysPrxId id)
{
	s32 result = 0;
	s32 rc = sysPrxStopModule(id, 0, NULL, &result, 0, NULL);
	VITALS_LOG("xmb: stopped:" " %08X", (unsigned)((uint32_t)rc));
	rc = sysPrxUnloadModule(id, 0, NULL);
	VITALS_LOG("xmb: unloaded:" " %08X", (unsigned)((uint32_t)rc));
}

/* What the thread did, for the popup; XMB_PENDING until it's done */
static volatile int g_state = XMB_NONE, g_http_state = XMB_NONE;

int vitals_xmb_state(void)
{
	return g_state;
}

int vitals_xmb_http_state(void)
{
	return g_http_state;
}

static int load_and_patch(void);
static int load_and_patch_http(void);

#if VITALS_DEBUG >= 1
#define LV2_TIMER_USLEEP 141
#define LV2_PAGE_ATTRIBUTE 351
/* How often the watch looks, and how often it says it still runs (Full debug only) */
#define WATCH_STEP_US 500000u
#define WATCH_HEARTBEAT_STEPS 20u
/* A change in the XMB's free memory worth a line */
#define WATCH_MEMORY_STEP (64u * 1024u)

static int readable(uint32_t address)
{
	/* sys_page_attr_t: 24 bytes (two 64-bit words and the page size), which a 16-byte buffer here
	 * overran by 8 on the caller's stack */
	uint64_t attribute[4] __attribute__((aligned(16)));
	lv2syscall2(LV2_PAGE_ATTRIBUTE, (uint64_t)address, (uint64_t)(uintptr_t)attribute);
	return p1 == 0;
}

/* The descriptor an island hands the bridge (its lis and ori of r11) */
static uint32_t island_target(const uint32_t *island)
{
	return (island[0] & 0xFFFFu) << 16 | (island[1] & 0xFFFFu);
}

/* For the crash and the hang when an app or a game starts with the XMB patched:
 * a line whenever the XMB's free memory moves by WATCH_MEMORY_STEP, its code written here changes
 * (a branch or an island no longer what was written), or vitals' module stops being there (its
 * descriptor's page or its code's); at Full debug, a line every WATCH_HEARTBEAT_STEPS, so the log
 * says when this thread stopped too. Each finding once, until it changes back */
static void __attribute__((noreturn)) watch(const XmbLibrary *const *libraries, unsigned count)
{
	uint32_t total = 0, last = 0, steps = 0;
	memory_size(&total, &last);
	VITALS_LOG("xmb: watching; free now (bytes):" " %08X", (unsigned)(last));
	int code_ok[2] = {1, 1}, module_ok[2] = {1, 1};
	for (;;) {
		lv2syscall1(LV2_TIMER_USLEEP, WATCH_STEP_US);
		uint32_t available = 0;
		memory_size(&total, &available);
		if (available + WATCH_MEMORY_STEP <= last || available >= last + WATCH_MEMORY_STEP) {
			VITALS_LOG("xmb: watch: the XMB's free memory is now (bytes)" " %08X", (unsigned)(available));
			VITALS_LOG("xmb: watch: of (bytes)" " %08X", (unsigned)(total));
			last = available;
		}
		for (unsigned l = 0; l < count && l < 2; ++l) {
			const XmbLibrary *library = libraries[l];
			uint32_t bad = 0;
			for (uint32_t i = 0; i < library->count && bad == 0; ++i) {
				uint32_t code = library->table[i].code, island = library->area + 4 * XMB_ISLAND_WORDS * i;
				if (word_at(code) != BRANCH(code, island))
					bad = code;
				else if (word_at(island) != library->islands[i * XMB_ISLAND_WORDS])
					bad = island;
			}
			if ((bad == 0) != code_ok[l]) {
				VITALS_LOG("%s", library->name);
				VITALS_LOG("%s %08X", bad ? "xmb: watch: the code written here changed, at" : "xmb: watch: the code is ours again", (unsigned)(bad));
				code_ok[l] = bad == 0;
			}
			uint32_t target = island_target(library->islands);
			int present = readable(target) && readable(word_at(target));
			if (present != module_ok[l]) {
				VITALS_LOG("%s", library->name);
				VITALS_LOG("%s %08X", present ? "xmb: watch: vitals' module is back, its first descriptor at"
				                     : "xmb: watch: vitals' module is gone, its first descriptor at", (unsigned)(target));
				module_ok[l] = present;
			}
		}
		if (++steps % WATCH_HEARTBEAT_STEPS == 0)
			VITALS_VERBOSE("xmb: watch: still here; free (bytes)" " %08X", (unsigned)(available));
	}
}
#endif

static void __attribute__((noreturn)) xmb_thread(void *arg)
{
	(void)arg;
	g_state = load_and_patch();
	if (g_http_state == XMB_PENDING)
		g_http_state = g_state == XMB_ON || g_state == XMB_DRY_RUN ? load_and_patch_http() : XMB_NONE;
#if VITALS_DEBUG >= 1
	if (g_state == XMB_ON) {
		const XmbLibrary *libraries[2] = {&k_ssl, &k_http};
		watch(libraries, g_http_state == XMB_ON ? 2u : 1u);
	}
#ifdef VITALS_XMB_KEEP_LOADED
	/* Memory only: no code of the XMB's is ours to check */
	if (g_state == XMB_DRY_RUN) {
		const XmbLibrary *libraries[1] = {&k_ssl};
		watch(libraries, 0u);
	}
#endif
#endif
	lv2syscall1(LV2_THREAD_EXIT, 0);
	__builtin_unreachable();
}

extern int32_t sysThreadCreate(uint32_t *thread, void (*entry)(void *), void *arg, int32_t priority, uint64_t stack,
                               uint64_t flags, char *name);

/* The XMB's libhttp, after its SSL: xmb-http.off leaves it the XMB's own (http.off is games' only),
 * as does a libhttp of vitals' not there, and an XMB other than 4.93's; vitals' libhttp works on
 * vitals' libssl, so it's only tried once the XMB's SSL is vitals' (xmb_thread) */
static int http_wanted(void)
{
	if (file_exists(VITALS_XMB_HTTP_OFF)) {
		VITALS_LOG("xmb: xmb-http.off is there: the XMB keeps its own libhttp");
		return XMB_OFF;
	}
	if (!file_exists(VITALS_LIBHTTP))
		return XMB_NONE;
	return xmb_is_493(&k_http) ? XMB_PENDING : XMB_OTHER;
}

int vitals_xmb_start(int cut_short)
{
	/* xmb.off, an earlier build's, counts as xmb-tls.off until an install renames it */
	if (file_exists(VITALS_XMB_TLS_OFF) || file_exists(VITALS_XMB_OLD_OFF)) {
		VITALS_LOG("xmb: xmb-tls.off is there: the XMB keeps its own SSL and libhttp");
		/* Why the XMB's HTTP is Sony's, unless Options turned that off too */
		g_http_state = file_exists(VITALS_XMB_HTTP_OFF) ? XMB_OFF : XMB_NEEDS_TLS;
		return g_state = XMB_OFF;
	}
	if (cut_short) {
		VITALS_LOG("xmb: the last boot didn't end properly: the XMB keeps its own SSL and libhttp this boot");
		g_http_state = XMB_LEFT_OUT;
		return XMB_LEFT_OUT;
	}
	if (!xmb_is_493(&k_ssl))
		return g_state = XMB_OTHER;
	g_http_state = http_wanted();
	g_state = XMB_PENDING;
	uint32_t thread = 0;
	int32_t rc = sysThreadCreate(&thread, xmb_thread, 0, 1000, 0x10000, 0, (char *)"vitals_xmb");
	if (rc != 0) {
		VITALS_LOG("xmb: no thread:" " %08X", (unsigned)((uint32_t)rc));
		g_http_state = XMB_NONE;
		return g_state = XMB_FAILED;
	}
	return XMB_PENDING;
}

static int load_and_patch(void)
{
	int (*is_initd)(void) = (int (*)(void))(uintptr_t)xmb_export("cellSsl", XMB_IS_INITD_NID);
	if (is_initd() != 0) {
		VITALS_LOG("xmb: the XMB has started its SSL already: it keeps it this boot");
		return XMB_TOO_LATE;
	}
	uint32_t total = 0, available = 0;
	memory_size(&total, &available);
	VITALS_LOG("xmb: the XMB's memory, free before vitals' libssl (bytes):" " %08X", (unsigned)(available));
#ifdef VITALS_XMB_WATCH_ONLY
	VITALS_LOG("xmb: watch only: nothing loaded into the XMB");
	return XMB_DRY_RUN;
#endif
	VITALS_VERBOSE("xmb: of (bytes):" " %08X", (unsigned)(total));
	static VitalsXmbRequest request;
	sysPrxId id = 0;
	if (load(&k_ssl, &id, &request) != 0)
		return XMB_FAILED;
#ifdef VITALS_XMB_DRY_RUN
	(void)patch(&k_ssl, &request, 1);
	VITALS_LOG("xmb: dry run: 4.93's XMB, SSL not started, vitals' libssl loaded with all 114 functions; "
	       "nothing written");
#ifdef VITALS_XMB_KEEP_LOADED
	/* Left loaded, unused: the XMB's SSL is still its own, with vitals' memory taken */
	(void)id;
	VITALS_LOG("xmb: dry run: vitals' libssl stays loaded, unused");
#else
	unload(id);
	free_now("xmb: dry run: free after libssl");
#endif
	return XMB_DRY_RUN;
#else
	/* The XMB may have started SSL while libssl loaded: then no object of SSL-C's may reach vitals' */
	int done = XMB_TOO_LATE;
	if (is_initd() != 0)
		VITALS_LOG("xmb: the XMB started its SSL while vitals' loaded: it keeps it this boot");
	else
		done = patch(&k_ssl, &request, 0);
	if (done == XMB_ON) {
		VITALS_LOG("xmb: the XMB's 114 SSL functions go to vitals' libssl");
		return done;
	}
	unload(id);
	return done;
#endif
}

/* The XMB's cellHttpGetProxy before its cellHttpInit: 0x80710002 (not initialized), as the probe
 * found it; anything else once its libhttp has started */
#define XMB_HTTP_GET_PROXY_NID 0x2A87603Au
#define HTTP_NOT_INITIALIZED ((int)0x80710002)

static int load_and_patch_http(void)
{
	int (*get_proxy)(void *, void *, uint32_t, uint32_t *) =
	    (int (*)(void *, void *, uint32_t, uint32_t *))(uintptr_t)xmb_export("cellHttp", XMB_HTTP_GET_PROXY_NID);
	if (get_proxy(NULL, NULL, 0, NULL) != HTTP_NOT_INITIALIZED) {
		VITALS_LOG("xmb: the XMB has started its libhttp already: it keeps it this boot");
		return XMB_TOO_LATE;
	}
	static VitalsXmbRequest request;
	sysPrxId id = 0;
	if (load(&k_http, &id, &request) != 0)
		return XMB_FAILED;
#ifdef VITALS_XMB_DRY_RUN
	(void)patch(&k_http, &request, 1);
	VITALS_LOG("xmb: dry run: vitals' libhttp loaded with all 201 functions; nothing written");
	unload(id);
	free_now("xmb: dry run: free after libhttp");
	return XMB_DRY_RUN;
#else
	int done = XMB_TOO_LATE;
	if (get_proxy(NULL, NULL, 0, NULL) != HTTP_NOT_INITIALIZED)
		VITALS_LOG("xmb: the XMB started its libhttp while vitals' loaded: it keeps it this boot");
	else
		done = patch(&k_http, &request, 0);
	if (done == XMB_ON) {
		VITALS_LOG("xmb: the XMB's 201 HTTP functions go to vitals' libhttp");
		return done;
	}
	unload(id);
	return done;
#endif
}
