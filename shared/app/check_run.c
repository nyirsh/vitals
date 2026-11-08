/* The connection test's run, for every console (check_run.h) */

#include "check_run.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* What the run is and how it reaches the service */
typedef struct {
	const CheckBackend *b;
	CheckService *service;
	int policy_failed;
} Run;

static void lock(const Run *run)
{
	run->b->lock();
}

static void unlock(const Run *run)
{
	run->b->unlock();
}

static void set_info(CheckResult *r, const char *message)
{
	memset(r, 0, sizeof(*r));
	r->state = CHECK_INFO;
	snprintf(r->message, sizeof(r->message), "%s", message);
}

/* Before a check: cancelled, or left untested since a certificate policy failed. 1 with r saying
 * so, 0 to go on */
static int skipped(Run *run, CheckResult *r)
{
	if (run->b->stopped()) {
		set_info(r, "Cancelled / not tested");
		return 1;
	}
	if (run->policy_failed) {
		set_info(r, "Not tested: certificate policy error");
		return 1;
	}
	return 0;
}

/* After a check: whether what it left lets the rest go on */
static void after(Run *run, const char *what, const CheckResult *r)
{
	if (run->b->policy_failed != NULL && run->b->policy_failed(r))
		run->policy_failed = 1;
	if (run->b->log != NULL)
		run->b->log(what, r);
}

/* A failed request because the run was cancelled says so, not why it failed */
static void cancelled_request(Run *run, int rc, CheckResult *r)
{
	if (rc < 0 && r->http_code == 0 && run->b->stopped())
		set_info(r, "Cancelled / not tested");
}

static void publish_tile(Run *run, unsigned test, const CheckResult *r)
{
	lock(run);
	if (test == CHECK_REPORT)
		run->service->connection = *r;
	else
		run->service->protocols[test] = *r;
	unlock(run);
}

static void publish_badssl(Run *run, unsigned i, const CheckResult *r)
{
	lock(run);
	run->service->badssl[i] = *r;
	unlock(run);
}

/* With the host that answered, when there is one */
static void publish_rule(Run *run, CheckRedirect *list, unsigned i, const CheckResult *r, const char *reached)
{
	lock(run);
	list[i].result = *r;
	if (reached != NULL)
		snprintf(list[i].reached, sizeof(list[i].reached), "%s", reached);
	unlock(run);
}

/* The TLS report: tls.browserleaks.com's JSON, with a fresh URL so no cache answers for the server */
static void run_report(Run *run, char *body, CheckHandshake *handshake, CheckResult *r)
{
	char url[320], reached[CHECK_HOST_MAX];
	const char *endpoint = check_endpoint(CHECK_REPORT);
	snprintf(url, sizeof(url), "%s%ccheck=%llu", endpoint, strchr(endpoint, '?') != NULL ? '&' : '?',
	         (unsigned long long)run->b->now_ms());
	size_t length = 0;
	int rc = run->b->fetch(url, 0, body, &length, reached, sizeof(reached), r);
	if (rc == 0 && r->http_code == 200 && check_parse_browserleaks(body, length, handshake) == 0) {
		r->state = CHECK_PASS;
		snprintf(r->message, sizeof(r->message), "Server report received");
		lock(run);
		run->service->handshake = *handshake;
		unlock(run);
		return;
	}
	r->state = CHECK_FAIL;
	if (rc == 0 && r->http_code == 200) {
		r->error = -1;
		snprintf(r->message, sizeof(r->message), "Unexpected report format (HTTP 200)");
	} else if (rc == 0 && r->http_code != 0) {
		snprintf(r->message, sizeof(r->message), "HTTP %d", r->http_code);
	} else if (r->message[0] == '\0') {
		snprintf(r->message, sizeof(r->message), "Request failed (0x%08X)", (unsigned)r->error);
	}
	cancelled_request(run, rc, r);
}

static void run_tiles(Run *run, char *body, CheckHandshake *handshake)
{
	static const unsigned order[] = {3, 2, 1, 0, CHECK_REPORT};
	for (unsigned step = 0; step < sizeof(order) / sizeof(order[0]); ++step) {
		unsigned test = order[step];
		CheckResult r = {0};
		if (!skipped(run, &r)) {
			r.state = CHECK_RUNNING;
			publish_tile(run, test, &r);
			memset(&r, 0, sizeof(r));
			if (test < 4) {
				run->b->protocol(test, body, &r);
				if (r.http_code == 0 && run->b->stopped())
					set_info(&r, "Cancelled / not tested");
			} else {
				run_report(run, body, handshake, &r);
			}
			after(run, check_endpoint(test), &r);
		}
		publish_tile(run, test, &r);
		/* Where the console can't tell otherwise: Sony's TLS has no 1.3, so a connection there is
		 * vitals' */
		if (test == 3) {
			lock(run);
			if (run->service->vitals_enabled < 0)
				run->service->vitals_enabled = r.state == CHECK_PASS ? 1 : r.state == CHECK_FAIL ? 0 : -1;
			unlock(run);
		}
	}
}

/* badssl.com: each host with certificate checks on; the good ones must give any final status, the
 * bad ones must be refused */
static void run_badssl(Run *run, char *body)
{
	for (unsigned i = 0; i < CHECK_BADSSL_COUNT; ++i) {
		const CheckBadssl *test = check_badssl(i);
		CheckResult r = {0};
		if (!skipped(run, &r)) {
			r.state = CHECK_RUNNING;
			publish_badssl(run, i, &r);
			memset(&r, 0, sizeof(r));
			char url[96], reached[CHECK_HOST_MAX];
			size_t length = 0;
			snprintf(url, sizeof(url), "https://%s/", test->host);
			int rc = run->b->fetch(url, 1, body, &length, reached, sizeof(reached), &r);
			run->b->judge_badssl(test, &r);
			cancelled_request(run, rc, &r);
			after(run, test->host, &r);
		}
		publish_badssl(run, i, &r);
	}
}

/* Each redirect is requested by its old name, as a game would: vitals' HTTP sends it to the new host
 * and checks the certificate against the new name, and the console says which host the request
 * went to, so a pass proves the whole path; any final status counts, as only the new server's
 * reachability is tested */
static void run_redirects(Run *run, const CheckParts *parts, char *body)
{
	CheckRedirect *list = run->service->redirects;
	for (unsigned i = 0; i < run->service->redirect_count; ++i) {
		CheckResult r = {0};
		if (skipped(run, &r)) {
		} else if (parts->http != 1) {
			set_info(&r, "Not tested: vitals' HTTP isn't active");
		} else if (parts->redirects_off == 1) {
			set_info(&r, "Not tested: redirects are off");
		} else if (parts->http_outdated == 1) {
			set_info(&r, "Couldn't test (outdated vitals)");
			r.state = CHECK_WARNING;
		} else {
			r.state = CHECK_RUNNING;
			publish_rule(run, list, i, &r, "");
			memset(&r, 0, sizeof(r));
			char url[CHECK_HOST_MAX + 16], reached[CHECK_HOST_MAX], host[CHECK_HOST_MAX] = "";
			size_t length = 0;
			snprintf(url, sizeof(url), "https://%s/", list[i].from);
			reached[0] = '\0';
			int rc = run->b->fetch(url, 1, body, &length, reached, sizeof(reached), &r);
			/* Only a host that gave a final status answered */
			if (rc == 0 && r.http_code > 0)
				check_reached_host(reached, host, sizeof(host));
			check_redirect_judge(&r, rc, host, list[i].to);
			cancelled_request(run, rc, &r);
			after(run, list[i].from, &r);
			publish_rule(run, list, i, &r, host);
			continue;
		}
		publish_rule(run, list, i, &r, NULL);
	}
}

/* Each DNS rule's name is looked up as a game would and its answer held against the rule */
static void run_dns(Run *run, const CheckParts *parts)
{
	CheckRedirect *list = run->service->dns;
	for (unsigned i = 0; i < run->service->dns_count; ++i) {
		CheckResult r = {0};
		if (run->b->stopped()) {
			set_info(&r, "Cancelled / not tested");
		} else if (run->b->lookup == NULL) {
			set_info(&r, "Not tested on this console yet");
		} else if (parts->dns_off == 1) {
			set_info(&r, "Not tested: DNS rules are off");
		} else {
			r.state = CHECK_RUNNING;
			publish_rule(run, list, i, &r, NULL);
			memset(&r, 0, sizeof(r));
			/* The name, timed, and a host name target's own addresses to hold its answer against */
			uint64_t started = run->b->now_ms();
			CheckLookup answer = {0}, wanted = {0};
			run->b->lookup(list[i].from, &answer);
			r.elapsed_ms = (unsigned)(run->b->now_ms() - started);
			unsigned char address[4];
			if (check_dns_target(list[i].to, address) == CHECK_DNS_NAME && !run->b->stopped())
				run->b->lookup(list[i].to, &wanted);
			check_dns_judge(list[i].to, &answer, &wanted, &r);
			if (r.state == CHECK_FAIL && run->b->stopped())
				set_info(&r, "Cancelled / not tested");
			if (run->b->log != NULL)
				run->b->log(list[i].from, &r);
		}
		publish_rule(run, list, i, &r, NULL);
	}
}

typedef struct {
	CheckRedirect *list;
	unsigned count, max;
} Rules;

static int keep_rule(void *context, const VitalsHostRule *rule)
{
	Rules *rules = context;
	CheckRedirect *kept = &rules->list[rules->count++];
	memset(kept, 0, sizeof(*kept));
	memcpy(kept->from, rule->from, rule->from_length);
	memcpy(kept->to, rule->to, rule->to_length);
	return rules->count == rules->max;
}

unsigned check_run_read_rules(VitalsRedirectListRead read, CheckRedirect *list, unsigned max)
{
	Rules rules = {list, 0, max};
	char *work = max != 0 ? malloc(VITALS_REDIRECT_LIST_WORK_SIZE) : NULL;
	if (work == NULL || vitals_redirect_list_read(read, work, keep_rule, &rules) < 0)
		rules.count = 0;
	free(work);
	return rules.count;
}

void check_run(const CheckBackend *backend, CheckService *service, char *notice, size_t notice_size)
{
	Run run = {backend, service, 0};
	char *body = malloc(CHECK_BODY_MAX + 1);
	CheckHandshake *handshake = calloc(1, sizeof(*handshake));
	CheckRedirect *rules = calloc(CHECK_REDIRECT_MAX + CHECK_DNS_MAX, sizeof(*rules));
	int rc = body != NULL && handshake != NULL && rules != NULL ? 0 : -1;
	char opened[120] = "Out of memory";
	if (rc == 0) {
		opened[0] = '\0';
		rc = backend->open(opened, sizeof(opened));
	}
	if (rc < 0) {
		/* A run that can't start says why on the TLS report's row (stopped takes the console's lock
		 * itself, so it's asked first) */
		int cancelled = backend->stopped();
		lock(&run);
		snprintf(notice, notice_size, "%s", cancelled ? "Cancelled / not tested" : opened);
		service->connection.state = cancelled ? CHECK_INFO : CHECK_FAIL;
		snprintf(service->connection.message, sizeof(service->connection.message), "%s", notice);
		service->complete = 1;
		service->interrupted = cancelled;
		unlock(&run);
		free(body);
		free(handshake);
		free(rules);
		return;
	}
	CheckParts parts = {-1, -1, -1, -1, -1, -1};
	backend->parts(&parts);
	/* The rules are listed first, so their pages fill in as they're tested */
	unsigned redirect_count = backend->load(CHECK_REDIRECTS_PATH, rules, CHECK_REDIRECT_MAX);
	unsigned dns_count = backend->load(CHECK_DNS_PATH, rules + CHECK_REDIRECT_MAX, CHECK_DNS_MAX);
	lock(&run);
	service->vitals_enabled = parts.vitals;
	service->libhttp_active = parts.http;
	service->tls_active = parts.tls;
	service->redirects_off = parts.redirects_off;
	memcpy(service->redirects, rules, redirect_count * sizeof(*rules));
	service->redirect_count = redirect_count;
	memcpy(service->dns, rules + CHECK_REDIRECT_MAX, dns_count * sizeof(*rules));
	service->dns_count = dns_count;
	service->dns_off = parts.dns_off == 1;
	unlock(&run);
	free(rules);
	run_tiles(&run, body, handshake);
	run_badssl(&run, body);
	run_redirects(&run, &parts, body);
	run_dns(&run, &parts);
	free(body);
	free(handshake);
	int cancelled = backend->stopped();
	lock(&run);
	service->complete = 1;
	service->interrupted = cancelled;
	unlock(&run);
}
