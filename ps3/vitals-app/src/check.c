/* The connection test's worker, as the Vita's vitals-app check.c: each check independent, the
 * report last of the TLS ones so it can't gate the tiles, then badssl.com, then each host redirect
 * in /dev_hdd0/vitals/redirects.txt (read with the parser shared with the Vita, shared/src), then each DNS rule
 * in /dev_hdd0/vitals/dns.txt (the PS3's own: the Vita's app has no DNS test) */

#include "check.h"
#include "check_model.h"
#include "check_report.h"
#include "check_run.h"

#include "app_log.h"
#include "firmware.h"
#include "http.h"
#include "install.h"
#include "vitals/redirect_list.h"

#include <cell/cell_fs.h>
#include <cell/rtc.h>
#include <net/net.h>
#include <netdb.h>
#include <stdarg.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mutex.h>
#include <sys/ppu_thread.h>
#include <sys/sys_time.h>

static sys_mutex_t guard;
static int guard_ready, busy, thread_running;
static volatile int stopping;
static sys_ppu_thread_t worker;
static CheckService service;
static char notice[120];

static void lock(void)
{
	sysMutexLock(guard, 0);
}

static void unlock(void)
{
	sysMutexUnlock(guard);
}

static void copy_result(CheckResult *r, const HttpResult *h)
{
	r->http_code = h->http_code;
	r->error = h->error;
	r->verify_error = h->verify_error;
	r->ssl_version = h->ssl_version;
	r->elapsed_ms = h->elapsed_ms;
	r->attempts = h->attempts;
	snprintf(r->cipher, sizeof(r->cipher), "%s", h->cipher);
}

/* A finished check, in the app's log */
static void log_result(const char *what, const CheckResult *r)
{
	app_log("test %s: state %d, HTTP %d, error 0x%08X, flags 0x%04X, %s %s, %u ms, %s", what, r->state, r->http_code,
	        (unsigned)r->error, (unsigned)r->verify_error, http_protocol_name(r->ssl_version, r->cipher), r->cipher,
	        r->elapsed_ms, r->message);
}

/* ---- the host redirect list, read as vitals' libhttp reads it ---- */

static int redirect_fd = -1;

static int read_redirects(unsigned int offset, void *buffer, unsigned int size)
{
	uint64_t position = 0, got = 0;
	if (cellFsLseek(redirect_fd, (int64_t)offset, CELL_FS_SEEK_SET, &position) != CELL_FS_SUCCEEDED ||
	    cellFsRead(redirect_fd, buffer, size, &got) != CELL_FS_SUCCEEDED)
		return -1;
	return (int)got;
}

/* The host redirects, or the DNS rules: the same "host target" lines, read as vitals reads them
 * (check_run_read_rules); none when the file is missing or can't be read to its end */
static unsigned load_redirects(const char *path, CheckRedirect *list, unsigned max)
{
	if (cellFsOpen(path, CELL_FS_O_RDONLY, &redirect_fd, NULL, 0) != CELL_FS_SUCCEEDED) {
		redirect_fd = -1;
		return 0;
	}
	unsigned count = check_run_read_rules(read_redirects, list, max);
	cellFsClose(redirect_fd);
	redirect_fd = -1;
	app_log("%s: %u rules", path, count);
	return count;
}

/* A name looked up through libnet, as a game would: its query goes out through sendto, where the
 * DNS kernel plugin applies the rules */
static void look_up(const char *name, CheckLookup *out)
{
	memset(out, 0, sizeof(*out));
	struct hostent *host = gethostbyname(name);
	if (host == NULL) {
		out->error = net_h_errno;
		return;
	}
	if (host->h_addrtype == AF_INET && host->h_length == 4)
		while (out->count < CHECK_DNS_ADDRESSES && host->h_addr_list[out->count] != NULL) {
			memcpy(out->addresses[out->count], host->h_addr_list[out->count], 4);
			++out->count;
		}
	out->found = out->count != 0;
	if (!out->found)
		out->error = NO_DATA;
}

/* Whether vitals' libhttp is this boot's: the boot plugin writes libhttp.active on a boot that maps
 * it, so a file older than this boot is a stale one (a boot without the plugin) */
static int libhttp_active(void)
{
	CellFsStat status;
	if (cellFsStat(VITALS_LIBHTTP_ACTIVE, &status) != CELL_FS_SUCCEEDED)
		return 0;
	CellRtcDateTime clock;
	time_t now = 0;
	if (cellRtcGetCurrentClockUtc(&clock) != 0 || cellRtcGetTime_t(&clock, &now) != 0)
		return 1; /* No clock to compare with: the file's word is taken */
	int64_t booted = (int64_t)now - (int64_t)(sys_time_get_system_time() / 1000000);
	/* A minute's slack: the plugin writes it early in the boot, and the clock may move */
	return (int64_t)status.st_mtime >= booted - 60;
}

/* ---- the PS3's side of the shared run (shared/app/check_run.c) ---- */

static int backend_open(char *text, size_t size)
{
	int rc = http_open();
	if (rc < 0)
		snprintf(text, size, rc == (int)0x80130106 ? "No network connection" : "Network set-up failed: 0x%08X",
		         (unsigned)rc);
	return rc;
}

static void backend_parts(CheckParts *parts)
{
	parts->http = libhttp_active();
	/* The boot plugin leaves no word on libssl: the TLS 1.3 tile tells (vitals = -1) */
	parts->tls = -1;
	parts->redirects_off = vitals_switch_is_off(VITALS_REDIRECTS_OFF);
	parts->dns_off = vitals_switch_is_off(VITALS_DNS_OFF);
	parts->vitals = -1;
	/* libhttp's own transaction says which host answered */
	parts->http_outdated = 0;
	app_log("vitals' libhttp %s%s%s", parts->http ? "active" : "not active", parts->redirects_off ? ", redirects off" : "",
	        parts->dns_off ? ", DNS rules off" : "");
}

static void backend_protocol(unsigned test, char *body, CheckResult *r)
{
	/* A fresh URL each time, so no cache answers for the server */
	char url[160];
	const char *endpoint = check_endpoint(test);
	snprintf(url, sizeof(url), "%s%ccheck=%llu", endpoint, strchr(endpoint, '?') != NULL ? '&' : '?',
	         (unsigned long long)sys_time_get_system_time());
	HttpResult h;
	http_get(url, body, CHECK_BODY_MAX + 1, &h);
	copy_result(r, &h);
	check_protocol_judge(test, r);
}

static int backend_fetch(const char *url, int status_only, char *body, size_t *length, char *reached, size_t reached_size,
                         CheckResult *r)
{
	HttpResult h;
	int rc = http_get(url, body, status_only ? 0 : CHECK_BODY_MAX + 1, &h);
	copy_result(r, &h);
	*length = h.length;
	snprintf(reached, reached_size, "%s", h.reached);
	if (rc < 0)
		check_request_failure(r, "");
	return rc;
}


static int backend_stopped(void)
{
	return stopping;
}

static uint64_t backend_now_ms(void)
{
	return http_now_ms();
}

static const CheckBackend backend = {
    .open = backend_open,
    .parts = backend_parts,
    .load = load_redirects,
    .protocol = backend_protocol,
    .fetch = backend_fetch,
    .judge_badssl = check_badssl_judge,
    .lookup = look_up,
    .stopped = backend_stopped,
    .policy_failed = NULL,
    .log = log_result,
    .lock = lock,
    .unlock = unlock,
    .now_ms = backend_now_ms,
};

static void run_checks(uint64_t argument)
{
	(void)argument;
	char text[sizeof(notice)] = "";
	check_run(&backend, &service, text, sizeof(text));
	lock();
	if (text[0] != '\0')
		snprintf(notice, sizeof(notice), "%s", text);
	busy = 0;
	unlock();
	sys_ppu_thread_exit(0);
}

static void join_worker(void)
{
	if (thread_running) {
		uint64_t ignored;
		sys_ppu_thread_join(worker, &ignored);
		thread_running = 0;
	}
}

void vitals_check_start(void)
{
	if (!guard_ready) {
		sys_mutex_attr_t attributes;
		memset(&attributes, 0, sizeof(attributes));
		attributes.attr_protocol = SYS_MUTEX_PROTOCOL_PRIO;
		attributes.attr_recursive = SYS_MUTEX_ATTR_NOT_RECURSIVE;
		attributes.attr_pshared = SYS_MUTEX_ATTR_NOT_PSHARED;
		attributes.attr_adaptive = SYS_MUTEX_ATTR_NOT_ADAPTIVE;
		snprintf(attributes.name, sizeof(attributes.name), "vcheck");
		if (sysMutexCreate(&guard, &attributes) != 0)
			return;
		guard_ready = 1;
	}
	lock();
	int running = busy;
	unlock();
	if (running)
		return;
	join_worker();
	lock();
	memset(&service, 0, sizeof(service));
	service.started = 1;
	service.vitals_enabled = service.libhttp_active = -1;
	notice[0] = '\0';
	busy = 1;
	unlock();
	stopping = 0;
	http_reset_cancel();
	/* The report's parser keeps its tokens static, but the requests nest deep in libhttp */
	if (sys_ppu_thread_create(&worker, run_checks, 0, 1000, 256 * 1024, SYS_PPU_THREAD_CREATE_JOINABLE, "vitals test") != 0) {
		lock();
		busy = 0;
		snprintf(notice, sizeof(notice), "The test's thread couldn't start");
		unlock();
		return;
	}
	thread_running = 1;
}

/* ---- the report (check_report.c), with the PS3's parts ---- */

/* How requests are made, the console, and whether the boot plugin put vitals' libhttp in */
static void report_about(CheckReport *report, const CheckService *s)
{
	check_report_add(report, "Certificate verification=enabled\nTimeouts are retried, up to %u attempts in all.\n",
	                 HTTP_ATTEMPTS);
	const ConsoleInfo *console = console_info();
	check_report_add(report, "console=%s (%s)\n", console->text,
	                 console->supported ? "supported" : "not supported: vitals is made for 4.93 CEX with Cobra");
	check_report_add(report, "parts=libhttp: %s (the boot plugin's libhttp.active, this boot); libssl: TLS 1.3 tells\n",
	                 s->libhttp_active < 0 ? "checking" : s->libhttp_active ? "vitals'" : "Sony's");
}

/* libssl's verify flags, protocol and cipher */
static void report_result(CheckReport *report, const CheckResult *r)
{
	check_report_add(report, "verify_flags=0x%04X\nprotocol=%s (CELL_SSL_VERSION %d)\ncipher=%s\n",
	                 (unsigned)r->verify_error, http_protocol_name(r->ssl_version, r->cipher), r->ssl_version, r->cipher);
}

static const CheckReportFormat report_format = {"PS3", "cellHttp", report_about, report_result, NULL};

/* Room for the whole report, the longest lists included */
#define REPORT_MAX (96 * 1024)

static int save_report(const CheckService *s, char *path, size_t path_size)
{
	CellRtcDateTime now;
	CheckReportTime local = {0};
	int have_time = cellRtcGetCurrentClockLocalTime(&now) == 0;
	if (have_time)
		local = (CheckReportTime){now.year, now.month, now.day, now.hour, now.minute, now.second};
	check_report_path(path, path_size, VITALS_REPORTS_DIRECTORY, "connection-test", have_time ? &local : NULL,
	                  http_now_ms());
	CheckReport report = {malloc(REPORT_MAX), 0, REPORT_MAX};
	if (report.data == NULL)
		return -1;
	check_report_write(&report_format, s, &report);
	cellFsMkdir(VITALS_DIRECTORY, CELL_FS_S_IFDIR | 0777);
	cellFsMkdir(VITALS_REPORTS_DIRECTORY, CELL_FS_S_IFDIR | 0777);
	int fd, rc = cellFsOpen(path, CELL_FS_O_WRONLY | CELL_FS_O_CREAT | CELL_FS_O_TRUNC, &fd, NULL, 0);
	if (rc == CELL_FS_SUCCEEDED) {
		uint64_t written = 0;
		rc = cellFsWrite(fd, report.data, report.used, &written);
		if (rc == CELL_FS_SUCCEEDED && written != report.used)
			rc = -1;
		if (cellFsClose(fd) != CELL_FS_SUCCEEDED && rc == CELL_FS_SUCCEEDED)
			rc = -1;
		/* A partly written report isn't kept */
		if (rc != CELL_FS_SUCCEEDED)
			cellFsUnlink(path);
	}
	free(report.data);
	app_log("report: %s, 0x%08X", path, (unsigned)rc);
	return rc == CELL_FS_SUCCEEDED ? 0 : -1;
}

int vitals_check_save_report(void)
{
	if (!guard_ready)
		return -1;
	lock();
	const int saved = service.report_saved == 1;
	const int ready = !busy && service.started && service.complete && !service.interrupted;
	unlock();
	if (saved)
		return 1;
	if (!ready)
		return -1;
	/* The finished run's results, copied so the report is written without holding the lock */
	CheckService *snapshot = malloc(sizeof(*snapshot));
	if (snapshot == NULL)
		return -1;
	lock();
	*snapshot = service;
	unlock();
	char path[160];
	int result = save_report(snapshot, path, sizeof(path));
	free(snapshot);
	lock();
	service.report_saved = result == 0 ? 1 : -1;
	if (result == 0)
		snprintf(service.report, sizeof(service.report), "%s", path);
	unlock();
	return result;
}

void vitals_check_cancel(void)
{
	stopping = 1;
	http_cancel();
}

int vitals_check_poll(CheckService *view, char *message, size_t size)
{
	if (!guard_ready) {
		memset(view, 0, sizeof(*view));
		view->vitals_enabled = view->libhttp_active = -1;
		if (size != 0)
			message[0] = '\0';
		return 0;
	}
	lock();
	*view = service;
	if (size != 0)
		snprintf(message, size, "%s", notice);
	int running = busy;
	unlock();
	return running;
}

void vitals_check_stop(void)
{
	if (!guard_ready)
		return;
	vitals_check_cancel();
	join_worker();
}
