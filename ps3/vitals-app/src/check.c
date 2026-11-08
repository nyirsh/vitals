/* The connection test's worker, as the Vita's vitals-app check.c: each check independent, the
 * report last of the TLS ones so it can't gate the tiles, then badssl.com, then each host redirect
 * in /dev_hdd0/vitals/redirects.txt (read with the parser shared with the Vita, shared/src), then each DNS rule
 * in /dev_hdd0/vitals/dns.txt (the PS3's own: the Vita's app has no DNS test) */

#include "check.h"
#include "check_model.h"

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

static void not_tested(CheckResult *r)
{
	memset(r, 0, sizeof(*r));
	r->state = CHECK_INFO;
	snprintf(r->message, sizeof(r->message), "Cancelled / not tested");
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

typedef struct {
	CheckRedirect *list;
	unsigned count, max;
} RedirectCollection;

static int keep_redirect(void *context, const VitalsHostRule *rule)
{
	RedirectCollection *collection = context;
	CheckRedirect *redirect = &collection->list[collection->count++];
	memset(redirect, 0, sizeof(*redirect));
	memcpy(redirect->from, rule->from, rule->from_length);
	memcpy(redirect->to, rule->to, rule->to_length);
	return collection->count == collection->max;
}

/* The host redirects, or the DNS rules: the same "host target" lines, read by the same parser */
static unsigned load_redirects(const char *path, CheckRedirect *list, unsigned max)
{
	RedirectCollection collection = {list, 0, max};
	char *work = malloc(VITALS_REDIRECT_LIST_WORK_SIZE);
	if (work != NULL && cellFsOpen(path, CELL_FS_O_RDONLY, &redirect_fd, NULL, 0) == CELL_FS_SUCCEEDED) {
		if (vitals_redirect_list_read(read_redirects, work, keep_redirect, &collection) < 0)
			app_log("%s: read failed after %u", path, collection.count);
		cellFsClose(redirect_fd);
	}
	redirect_fd = -1;
	free(work);
	return collection.count;
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

static void run_checks(uint64_t argument)
{
	(void)argument;
	char *body = malloc(CHECK_BODY_MAX + 1);
	CheckHandshake *handshake = calloc(1, sizeof(*handshake));
	int rc = body != NULL && handshake != NULL ? http_open() : (int)0x80710003;
	if (rc < 0) {
		lock();
		snprintf(notice, sizeof(notice), rc == (int)0x80130106 ? "No network connection" : "Network set-up failed: 0x%08X",
		         (unsigned)rc);
		service.connection.state = CHECK_FAIL;
		snprintf(service.connection.message, sizeof(service.connection.message), "%s", notice);
		service.complete = 1;
		busy = 0;
		unlock();
		free(body);
		free(handshake);
		sys_ppu_thread_exit(0);
	}
	/* The redirect rules are listed first, so their page fills in as they're tested */
	CheckRedirect *redirects = calloc(CHECK_REDIRECT_MAX, sizeof(*redirects));
	unsigned redirect_count = redirects != NULL ? load_redirects(CHECK_REDIRECTS_PATH, redirects, CHECK_REDIRECT_MAX) : 0;
	int active = libhttp_active();
	app_log("redirects: %u listed, vitals' libhttp %s", redirect_count, active ? "active" : "not active");
	/* So are the DNS rules, which are left untested while flags/dns.off is there */
	CheckRedirect *dns = calloc(CHECK_DNS_MAX, sizeof(*dns));
	unsigned dns_count = dns != NULL ? load_redirects(CHECK_DNS_PATH, dns, CHECK_DNS_MAX) : 0;
	CellFsStat flag;
	int dns_off = cellFsStat(VITALS_DNS_OFF, &flag) == CELL_FS_SUCCEEDED;
	app_log("DNS rules: %u listed%s", dns_count, dns_off ? ", off (dns.off)" : "");
	lock();
	for (unsigned i = 0; i < redirect_count; ++i)
		service.redirects[i] = redirects[i];
	service.redirect_count = redirect_count;
	service.libhttp_active = active;
	for (unsigned i = 0; i < dns_count; ++i)
		service.dns[i] = dns[i];
	service.dns_count = dns_count;
	service.dns_off = dns_off;
	unlock();
	static const unsigned order[] = {3, 2, 1, 0, CHECK_REPORT};
	for (unsigned step = 0; step < sizeof(order) / sizeof(order[0]); ++step) {
		unsigned test = order[step];
		CheckResult r = {0};
		if (stopping)
			not_tested(&r);
		else {
			r.state = CHECK_RUNNING;
			lock();
			if (test < 4)
				service.protocols[test] = r;
			else
				service.connection = r;
			unlock();
			/* A fresh URL each time, so no cache answers for the server, as the Vita's */
			char url[160];
			const char *endpoint = check_endpoint(test);
			snprintf(url, sizeof(url), "%s%ccheck=%llu", endpoint, strchr(endpoint, '?') != NULL ? '&' : '?',
			         (unsigned long long)sys_time_get_system_time());
			HttpResult h;
			http_get(url, body, CHECK_BODY_MAX + 1, &h);
			copy_result(&r, &h);
			if (stopping && h.http_code == 0)
				not_tested(&r);
			else if (test < 4)
				check_protocol_judge(test, &r);
			else if (h.http_code == 200 && check_parse_browserleaks(body, h.length, handshake) == 0) {
				r.state = CHECK_PASS;
				snprintf(r.message, sizeof(r.message), "Server report received");
			} else {
				r.state = CHECK_FAIL;
				if (h.http_code == 200)
					snprintf(r.message, sizeof(r.message), "Unexpected report format (HTTP 200)");
				else
					snprintf(r.message, sizeof(r.message), "%s", check_error_name(h.error, h.verify_error));
			}
		}
		log_result(check_endpoint(test), &r);
		lock();
		if (test < 4) {
			service.protocols[test] = r;
			/* Sony's libssl has no TLS 1.3: a connection there is vitals' */
			if (test == 3)
				service.vitals_enabled = r.state == CHECK_PASS ? 1 : r.state == CHECK_FAIL ? 0 : -1;
		} else {
			service.connection = r;
			if (r.state == CHECK_PASS)
				service.handshake = *handshake;
		}
		unlock();
	}
	for (unsigned i = 0; i < CHECK_BADSSL_COUNT; ++i) {
		const CheckBadssl *test = check_badssl(i);
		CheckResult r = {0};
		if (stopping)
			not_tested(&r);
		else {
			r.state = CHECK_RUNNING;
			lock();
			service.badssl[i] = r;
			unlock();
			char url[96];
			snprintf(url, sizeof(url), "https://%s/", test->host);
			HttpResult h;
			http_get(url, body, 0, &h);
			copy_result(&r, &h);
			if (stopping && h.http_code == 0)
				not_tested(&r);
			else
				check_badssl_judge(test, &r);
		}
		log_result(test->host, &r);
		lock();
		service.badssl[i] = r;
		unlock();
	}
	/* Each redirect is requested by its old name, as a game would: vitals' libhttp sends it to the
	 * new host and checks the certificate against the new name, so a pass proves the whole path;
	 * any final HTTP status counts, as only the server's reachability is tested */
	for (unsigned i = 0; i < redirect_count; ++i) {
		CheckResult r = {0};
		if (stopping)
			not_tested(&r);
		else if (!active) {
			r.state = CHECK_INFO;
			snprintf(r.message, sizeof(r.message), "Not tested: vitals' libhttp isn't active this boot");
		} else if (vitals_switch_is_off(VITALS_REDIRECTS_OFF)) {
			/* HTTP's Redirects off: vitals' libhttp without them */
			r.state = CHECK_INFO;
			snprintf(r.message, sizeof(r.message), "Not tested: redirects are off (flags/redirects.off)");
		} else {
			r.state = CHECK_RUNNING;
			lock();
			service.redirects[i].result = r;
			unlock();
			char url[CHECK_HOST_MAX + 16];
			snprintf(url, sizeof(url), "https://%s/", redirects[i].from);
			HttpResult h;
			http_get(url, body, 0, &h);
			copy_result(&r, &h);
			if (stopping && h.http_code == 0)
				not_tested(&r);
			else
				check_redirect_judge(&r, h.reached, redirects[i].to);
		}
		log_result(redirects[i].from, &r);
		lock();
		service.redirects[i].result = r;
		unlock();
	}
	/* Each DNS rule's name is looked up, and its answer held against the rule; a host name target
	 * is looked up too, for the addresses the renamed answer should carry */
	for (unsigned i = 0; i < dns_count; ++i) {
		CheckResult r = {0};
		if (stopping)
			not_tested(&r);
		else if (dns_off) {
			r.state = CHECK_INFO;
			snprintf(r.message, sizeof(r.message), "Not tested: DNS rules are off (flags/dns.off)");
		} else {
			r.state = CHECK_RUNNING;
			lock();
			service.dns[i].result = r;
			unlock();
			uint64_t started = sys_time_get_system_time();
			CheckLookup answer, target = {0};
			look_up(dns[i].from, &answer);
			r.elapsed_ms = (unsigned)((sys_time_get_system_time() - started) / 1000);
			unsigned char address[4];
			if (check_dns_target(dns[i].to, address) == CHECK_DNS_NAME && !stopping)
				look_up(dns[i].to, &target);
			if (stopping && !answer.found && answer.error != HOST_NOT_FOUND)
				not_tested(&r);
			else
				check_dns_judge(dns[i].to, &answer, &target, &r);
		}
		app_log("test DNS %s -> %s: state %d, %u ms, %s", dns[i].from, dns[i].to, r.state, r.elapsed_ms, r.message);
		lock();
		service.dns[i].result = r;
		unlock();
	}
	free(dns);
	free(redirects);
	free(body);
	free(handshake);
	lock();
	service.complete = 1;
	service.interrupted = stopping;
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

/* ---- the report, as the Vita's vitals-app writes it ---- */

typedef struct {
	char *data;
	size_t used, capacity;
} Report;

static void add(Report *report, const char *format, ...) __attribute__((format(printf, 2, 3)));
static void add(Report *report, const char *format, ...)
{
	if (report->used >= report->capacity)
		return;
	va_list arguments;
	va_start(arguments, format);
	int n = vsnprintf(report->data + report->used, report->capacity - report->used, format, arguments);
	va_end(arguments);
	if (n > 0)
		report->used += (size_t)n < report->capacity - report->used ? (size_t)n : report->capacity - report->used - 1;
}

static void add_result(Report *report, const CheckResult *r)
{
	add(report, "state=%d\nHTTP=%d\nerror=0x%08X\nverify_flags=0x%04X\nprotocol=%s (CELL_SSL_VERSION %d)\n"
	            "cipher=%s\nelapsed_ms=%u\nattempts=%u\nresult=%s\n",
	    r->state, r->http_code, (unsigned)r->error, (unsigned)r->verify_error, http_protocol_name(r->ssl_version, r->cipher),
	    r->ssl_version, r->cipher, r->elapsed_ms, r->attempts, r->message);
}

static int save_report(const CheckService *s, char *path, size_t path_size)
{
	CellRtcDateTime now;
	if (cellRtcGetCurrentClockLocalTime(&now) == 0)
		snprintf(path, path_size, VITALS_REPORTS_DIRECTORY "/connection-test-%04u-%02u-%02u_%02u-%02u-%02u.txt", now.year,
		         now.month, now.day, now.hour, now.minute, now.second);
	else
		snprintf(path, path_size, VITALS_REPORTS_DIRECTORY "/connection-test-%llu.txt", (unsigned long long)http_now_ms());
	Report report = {malloc(64 * 1024), 0, 64 * 1024};
	if (report.data == NULL)
		return -1;
	add(&report, "vitals " VITALS_VERSION " connection test (PS3)\nAPI=cellHttp\nservice=BrowserLeaks + badssl.com\n"
	             "Certificate verification=enabled\nConnection reuse=disabled\nRedirects=disabled\n"
	             "Timeouts are retried, up to %u attempts in all.\n", HTTP_ATTEMPTS);
	const ConsoleInfo *console = console_info();
	add(&report, "console=%s (%s)\n", console->text,
	    console->supported ? "supported" : "not supported: vitals is made for 4.93 CEX with Cobra");
	add(&report, "vitals=%s (TLS 1.3 connected through this console's libssl)\n",
	    s->vitals_enabled < 0 ? "checking" : s->vitals_enabled ? "enabled" : "not enabled");
	add(&report, "vitals libhttp=%s (the boot plugin's libhttp.active, this boot)\n",
	    s->libhttp_active < 0 ? "checking" : s->libhttp_active ? "active" : "not active");
	for (unsigned i = 0; i < CHECK_TEST_COUNT; ++i) {
		const CheckResult *r = i == CHECK_REPORT ? &s->connection : &s->protocols[i];
		add(&report, "\nURL=%s\n", check_endpoint(i));
		add_result(&report, r);
		if (i < 4) {
			char detail[160];
			check_protocol_detail(i, r, detail, sizeof(detail));
			add(&report, "classification=%s\ndetail=%s\n", check_protocol_display(i, r, s->vitals_enabled).label, detail);
		}
	}
	add(&report, "\nbadssl.com=%u\n", CHECK_BADSSL_COUNT);
	for (unsigned i = 0; i < CHECK_BADSSL_COUNT; ++i) {
		const CheckBadssl *test = check_badssl(i);
		add(&report, "%s (%s, expected %s)\n", test->host, test->label, test->refuse ? "refused" : "loaded");
		add_result(&report, &s->badssl[i]);
	}
	add(&report, "\nHost redirects (" CHECK_REDIRECTS_PATH ")=%u\n", s->redirect_count);
	for (unsigned i = 0; i < s->redirect_count; ++i) {
		add(&report, "%s -> %s\n", s->redirects[i].from, s->redirects[i].to);
		add_result(&report, &s->redirects[i].result);
	}
	add(&report, "\nDNS rules (" CHECK_DNS_PATH ")=%u%s\n", s->dns_count, s->dns_off ? ", off (flags/dns.off)" : "");
	for (unsigned i = 0; i < s->dns_count; ++i) {
		const CheckResult *r = &s->dns[i].result;
		add(&report, "%s -> %s\nstate=%d\nelapsed_ms=%u\nresult=%s\n", s->dns[i].from, s->dns[i].to, r->state,
		    r->elapsed_ms, r->message);
	}
	const CheckHandshake *h = &s->handshake;
	add(&report, "\nSelected protocol=%04X %s\nSelected cipher=%04X %s\nKey exchange=%04X %s\nSignature=%04X %s\n"
	             "ALPN offered=%s\nJA3=%s\nJA4=%s\n",
	    h->version.id, h->version.name, h->cipher.id, h->cipher.name, h->group.id, h->group.name, h->signature.id,
	    h->signature.name, h->alpn, h->ja3, h->ja4);
	const CheckNamed *lists[] = {h->ciphers, h->groups, h->extensions};
	const unsigned counts[] = {h->cipher_count, h->group_count, h->extension_count};
	const char *labels[] = {"Offered ciphers (not individually negotiated)", "Offered groups", "Offered extensions"};
	for (unsigned l = 0; l < 3; ++l) {
		add(&report, "\n%s\n", labels[l]);
		for (unsigned n = 0; n < counts[l]; ++n)
			add(&report, "%04X %s\n", lists[l][n].id, lists[l][n].name);
	}
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
