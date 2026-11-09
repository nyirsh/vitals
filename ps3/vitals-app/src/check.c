/* The PS3's part of the connection test (check.h): its requests through cellHttp (http.c), its
 * judges, its lookups through libnet, which parts of vitals this boot has, and its report's own
 * lines. The run itself, its thread and its results are shared with the Vita (check_run.c,
 * check_service.c) */

#include "check.h"
#include "check_model.h"
#include "check_report.h"
#include "check_run.h"

#include "vitals/log.h"
#include "firmware.h"
#include "http.h"
#include "install.h"
#include "vitals_marker.h"
#include "vitals/redirect_list.h"

#include <cell/cell_fs.h>
#include <cell/rtc.h>
#include <net/net.h>
#include <netdb.h>
#include <stdarg.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prx.h>
#include <sys/sys_time.h>

/* The run was cancelled: http.c ends its request, and the run asks before each check */
static volatile int stopping;

static void lock(void)
{
	check_lock();
}

static void unlock(void)
{
	check_unlock();
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
	VITALS_LOG("test %s: state %d, HTTP %d, error 0x%08X, flags 0x%04X, %s %s, %u ms, %s", what, r->state, r->http_code,
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
	VITALS_VERBOSE("%s: %u rules", path, count);
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

/* Whether the module this process loaded under Sony's name is vitals' (common/vitals_marker.h): 1 with
 * its release in version, 0 for Sony's, -1 when none is loaded. Its segments are only read, as the
 * Vita's app reads its modules' paths: nothing in the module is called */
#define MODULE_SEGMENTS 8
static int vitals_module(const char *name, const char *module, char *version, size_t version_size)
{
	version[0] = '\0';
	sys_prx_id_t id = sys_prx_get_module_id_by_name(name, 0, NULL);
	if (id < 0)
		return -1;
	sys_prx_segment_info_t segments[MODULE_SEGMENTS];
	char filename[128];
	sys_prx_module_info_t info;
	memset(&info, 0, sizeof(info));
	memset(segments, 0, sizeof(segments));
	info.size = sizeof(info);
	info.filename = (__typeof__(info.filename))(uintptr_t)filename;
	info.filename_size = sizeof(filename);
	info.segments = (__typeof__(info.segments))(uintptr_t)segments;
	info.segments_num = MODULE_SEGMENTS;
	if (sys_prx_get_module_info(id, 0, &info) != 0)
		return -1;
	char prefix[48];
	int prefix_length = snprintf(prefix, sizeof(prefix), VITALS_MARKER_PREFIX "%s/", module);
	unsigned count = info.segments_num < MODULE_SEGMENTS ? info.segments_num : MODULE_SEGMENTS;
	for (unsigned i = 0; i < count; ++i) {
		const char *base = (const char *)(uintptr_t)segments[i].base;
		size_t length = (size_t)segments[i].filesz;
		if (base == NULL || length < (size_t)prefix_length)
			continue;
		for (size_t at = 0; at + (size_t)prefix_length <= length; ++at) {
			if (base[at] != prefix[0] || memcmp(base + at, prefix, (size_t)prefix_length) != 0)
				continue;
			size_t used = 0;
			for (size_t c = at + (size_t)prefix_length; c < length && base[c] != '\0' && used + 1 < version_size; ++c)
				version[used++] = base[c];
			version[used] = '\0';
			return 1;
		}
	}
	return 0;
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

/* Which of vitals' modules this process has, and their releases, for the report as the Vita's keeps its
 * own */
static int vitals_http = -1, vitals_tls = -1;
static char http_release[16], tls_release[16];

static void backend_parts(CheckParts *parts)
{
	/* libhttp is loaded by now (backend_open), and libssl with it */
	vitals_http = parts->http = vitals_module("cellHttp_Library", "libhttp", http_release, sizeof(http_release)) == 1;
	vitals_tls = parts->tls = vitals_module("cellSsl_Library", "libssl", tls_release, sizeof(tls_release)) == 1;
	parts->redirects_off = vitals_switch_is_off(VITALS_REDIRECTS_OFF);
	parts->dns_off = vitals_switch_is_off(VITALS_DNS_OFF);
	/* As on the Vita: vitals is running when either of its modules is */
	parts->vitals = parts->http || parts->tls;
	/* libhttp's own transaction says which host answered */
	parts->http_outdated = 0;
	VITALS_LOG("libssl: %s%s, libhttp: %s%s%s%s", parts->tls ? "vitals' " : "Sony's", tls_release,
	        parts->http ? "vitals' " : "Sony's", http_release, parts->redirects_off ? ", redirects off" : "",
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
    .lookup = look_up,
    .stopped = backend_stopped,
    .policy_failed = NULL,
    .log = log_result,
    .lock = lock,
    .unlock = unlock,
    .now_ms = backend_now_ms,
};

/* ---- the report (check_report.c), with the PS3's parts ---- */

/* How requests are made, the console, and whether the boot plugin put vitals' libhttp in */
static void report_about(CheckReport *report, const CheckService *s)
{
	check_report_add(report, "Certificate verification=enabled\nTimeouts are retried, up to %u attempts in all.\n",
	                 HTTP_ATTEMPTS);
	const ConsoleInfo *console = console_info();
	check_report_add(report, "console=%s (%s)\n", console->text,
	                 console->supported ? "supported" : "not supported: vitals is made for 4.93 CEX with Cobra");
	(void)s;
	check_report_add(report, "parts=HTTP: %s%s, TLS: %s%s in this process\n",
	                 vitals_http < 0 ? "?" : vitals_http ? "vitals' libhttp " : "Sony's libhttp", http_release,
	                 vitals_tls < 0 ? "?" : vitals_tls ? "vitals' libssl " : "Sony's libssl", tls_release);
	/* A module from another release than the app's: the app's Install puts its own in place */
	if ((vitals_http == 1 && strcmp(http_release, VITALS_VERSION) != 0) ||
	    (vitals_tls == 1 && strcmp(tls_release, VITALS_VERSION) != 0))
		check_report_add(report, "outdated=vitals' modules aren't this app's release (" VITALS_VERSION "): install it "
		                         "again and reboot\n");
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
	VITALS_LOG("report: %s, 0x%08X", path, (unsigned)rc);
	return rc == CELL_FS_SUCCEEDED ? 0 : -1;
}

/* Before each run: not cancelled */
static void reset(void)
{
	stopping = 0;
	http_reset_cancel();
}

static void cancel(void)
{
	stopping = 1;
	http_cancel();
}

const CheckConsole check_console = {&backend, reset, cancel, NULL, save_report};
