/* The connection test's shared run (shared/app/check_run.c) over a console that answers from a
 * script: the order of the checks, what isn't tested and why, cancelling, a run that can't start,
 * and where vitals' state comes from. Built against each console's check_result.h, so it runs with
 * both consoles' results */

#include "check_run.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static CheckParts parts;
static int open_rc, stop_after = -1, requests, protocol_order[8], protocol_count, policy_after = -1;
static unsigned rule_counts[2];
static const char *reached_host = "new.example";
static char last_reached[64], dns_names[4][64];
static unsigned dns_count;

static int fake_open(char *notice, size_t size)
{
	if (open_rc < 0)
		snprintf(notice, size, "No network connection");
	return open_rc;
}

static void fake_parts(CheckParts *out)
{
	*out = parts;
}

static unsigned fake_load(const char *path, CheckRedirect *list, unsigned max)
{
	unsigned count = strcmp(path, CHECK_REDIRECTS_PATH) == 0 ? rule_counts[0] : rule_counts[1];
	assert(count <= max);
	for (unsigned i = 0; i < count; ++i) {
		snprintf(list[i].from, sizeof(list[i].from), "old%u.example", i);
		snprintf(list[i].to, sizeof(list[i].to), "new.example");
	}
	return count;
}

static int fake_stopped(void)
{
	return stop_after >= 0 && requests >= stop_after;
}

static void fake_protocol(unsigned test, char *body, CheckResult *r)
{
	(void)body;
	++requests;
	protocol_order[protocol_count++] = (int)test;
	r->http_code = 200;
	r->state = CHECK_PASS;
	snprintf(r->message, sizeof(r->message), "TLS 1.%u", test);
}

static const char report[] = "{\"tls\":{\"selected_version\":{\"id\":772,\"name\":\"TLS 1.3\"},"
                              "\"cipher_suite\":{\"id\":4865,\"name\":\"TLS_AES_128_GCM_SHA256\"}}}";

static int fake_fetch(const char *url, int status_only, char *body, size_t *length, char *reached, size_t size,
                      CheckResult *r)
{
	++requests;
	snprintf(reached, size, "%s", reached_host);
	if (strstr(url, "tls.browserleaks.com") != NULL) {
		assert(!status_only && strstr(url, "check=") != NULL);
		memcpy(body, report, sizeof(report));
		*length = sizeof(report) - 1;
		r->http_code = 200;
		return 0;
	}
	assert(status_only);
	r->http_code = 404;
	r->state = CHECK_PASS;
	return 0;
}

static void fake_badssl(const CheckBadssl *test, CheckResult *r)
{
	snprintf(r->message, sizeof(r->message), "judged %s", test->host);
	if (policy_after >= 0 && requests >= policy_after)
		r->error = -77;
}

static void fake_redirect(CheckResult *r, const char *reached, const char *expected)
{
	snprintf(last_reached, sizeof(last_reached), "%s", reached);
	r->state = strcmp(reached, expected) == 0 ? CHECK_PASS : CHECK_FAIL;
	snprintf(r->message, sizeof(r->message), "%s", r->state == CHECK_PASS ? "Reached" : "Answered by another");
}

static void fake_dns(const char *name, const char *target, CheckResult *r)
{
	(void)target;
	snprintf(dns_names[dns_count++ % 4], sizeof(dns_names[0]), "%s", name);
	r->state = CHECK_PASS;
	snprintf(r->message, sizeof(r->message), "Renamed");
}

static int fake_policy(const CheckResult *r)
{
	return r->error == -77;
}

static void fake_lock(void) {}
static void fake_unlock(void) {}
static uint64_t fake_now(void)
{
	return 1234;
}

static CheckBackend backend = {fake_open, fake_parts, fake_load, fake_protocol, fake_fetch, fake_badssl, fake_redirect,
                               fake_dns, fake_stopped, NULL, NULL, fake_lock, fake_unlock, fake_now};

static CheckService service;
static char notice[120];

/* A list file for check_run_read_rules, in memory; reads fail from fail_at on */
static const char *list_text;
static unsigned fail_at = ~0u;
static int read_list(unsigned int offset, void *buffer, unsigned int size)
{
	size_t length = strlen(list_text);
	if (offset >= fail_at)
		return -3;
	if (offset >= length)
		return 0;
	unsigned n = (unsigned)(length - offset) < size ? (unsigned)(length - offset) : size;
	memcpy(buffer, list_text + offset, n);
	return (int)n;
}

static void read_rules(void)
{
	CheckRedirect list[3];
	/* The pairs, with comments and lines vitals ignores left out */
	list_text = "# comment\nold.example new.example\n\nnot-a-pair\nPSN.Example  other.example # why\n";
	assert(check_run_read_rules(read_list, list, 3) == 2);
	assert(strcmp(list[0].from, "old.example") == 0 && strcmp(list[0].to, "new.example") == 0);
	assert(list[1].to[0] != '\0' && list[1].reached[0] == '\0');
	/* At most max */
	assert(check_run_read_rules(read_list, list, 1) == 1);
	assert(check_run_read_rules(read_list, list, 0) == 0);
	/* A list that can't be read to its end gives none, as vitals applies none */
	fail_at = 0;
	assert(check_run_read_rules(read_list, list, 3) == 0);
	fail_at = ~0u;
	list_text = "";
	assert(check_run_read_rules(read_list, list, 3) == 0);
}

static void run(void)
{
	memset(&service, 0, sizeof(service));
	service.started = 1;
	service.vitals_enabled = -1;
	notice[0] = '\0';
	requests = protocol_count = 0;
	dns_count = 0;
	check_run(&backend, &service, notice, sizeof(notice));
	assert(service.complete);
}

int main(void)
{
	read_rules();

	/* Everything on: the tiles TLS 1.3 first, then the report, badssl.com, the redirects (reached
	 * the new host) and the DNS rules */
	parts = (CheckParts){1, 1, 0, 0, 1, 0};
	rule_counts[0] = 2, rule_counts[1] = 1;
	run();
	assert(protocol_count == 4 && protocol_order[0] == 3 && protocol_order[3] == 0);
	for (unsigned i = 0; i < 4; ++i)
		assert(service.protocols[i].state == CHECK_PASS);
	assert(service.connection.state == CHECK_PASS && strcmp(service.connection.message, "Server report received") == 0);
	for (unsigned i = 0; i < CHECK_BADSSL_COUNT; ++i)
		assert(strncmp(service.badssl[i].message, "judged ", 7) == 0);
	assert(service.redirect_count == 2 && service.redirects[1].result.state == CHECK_PASS);
	assert(strcmp(service.redirects[0].from, "old0.example") == 0 && strcmp(last_reached, "new.example") == 0);
	assert(strcmp(service.redirects[1].reached, "new.example") == 0);
	assert(service.dns_count == 1 && service.dns[0].result.state == CHECK_PASS && strcmp(dns_names[0], "old0.example") == 0);
	assert(service.vitals_enabled == 1 && service.libhttp_active == 1 && !service.interrupted);
	assert(requests == 5 + CHECK_BADSSL_COUNT + 2);

	/* Another host answered a redirect: the console's judge says so, and the row shows that host,
	 * from a URL (the Vita's) as from a host (the PS3's) */
	reached_host = "https://old0.example:443/x";
	run();
	assert(service.redirects[0].result.state == CHECK_FAIL && strcmp(service.redirects[0].reached, "old0.example") == 0);
	reached_host = "new.example";

	/* vitals' HTTP not here, or its redirects off, or the DNS rules off: not tested, and no request
	 * made for them */
	parts.http = 0;
	run();
	assert(service.redirects[0].result.state == CHECK_INFO &&
	       strcmp(service.redirects[0].result.message, "Not tested: vitals' HTTP isn't active") == 0);
	assert(requests == 5 + CHECK_BADSSL_COUNT && service.redirects[0].reached[0] == '\0');
	parts.http = 1, parts.redirects_off = 1, parts.dns_off = 1;
	run();
	assert(strcmp(service.redirects[1].result.message, "Not tested: redirects are off") == 0);
	assert(strcmp(service.dns[0].result.message, "Not tested: DNS rules are off") == 0 && service.dns_off == 1);
	parts.redirects_off = parts.dns_off = 0;
	/* vitals' HTTP too old to say which host answered: the redirects can't be tested, without a
	 * request */
	parts.http_outdated = 1;
	run();
	assert(service.redirects[0].result.state == CHECK_WARNING &&
	       strcmp(service.redirects[0].result.message, "Couldn't test (outdated vitals)") == 0);
	assert(requests == 5 + CHECK_BADSSL_COUNT);
	parts.http_outdated = 0;
	/* A console that doesn't look DNS rules up */
	backend.dns = NULL;
	run();
	assert(strcmp(service.dns[0].result.message, "Not tested on this console yet") == 0);
	backend.dns = fake_dns;

	/* Where the console can't tell, vitals is what the TLS 1.3 tile says */
	parts.vitals = -1;
	run();
	assert(service.vitals_enabled == 1);
	parts.vitals = 1;

	/* Cancelled after the first tile: the rest says so, and the run is interrupted */
	stop_after = 1;
	run();
	assert(service.protocols[3].state == CHECK_PASS && service.protocols[2].state == CHECK_INFO);
	assert(strcmp(service.badssl[0].message, "Cancelled / not tested") == 0);
	assert(strcmp(service.redirects[0].result.message, "Cancelled / not tested") == 0);
	assert(strcmp(service.dns[0].result.message, "Cancelled / not tested") == 0);
	assert(service.interrupted && requests == 1);
	stop_after = -1;

	/* A certificate policy failure leaves the rest untested */
	backend.policy_failed = fake_policy;
	policy_after = 7;
	run();
	assert(strcmp(service.badssl[CHECK_BADSSL_COUNT - 1].message, "Not tested: certificate policy error") == 0);
	assert(strcmp(service.redirects[0].result.message, "Not tested: certificate policy error") == 0);
	backend.policy_failed = NULL;
	policy_after = -1;

	/* A run that can't start: the report's row and the notice say why */
	open_rc = -5;
	run();
	assert(service.connection.state == CHECK_FAIL && strcmp(service.connection.message, "No network connection") == 0);
	assert(strcmp(notice, "No network connection") == 0 && requests == 0 && service.protocols[0].state == CHECK_WAIT);
	open_rc = 0;

	puts("connection test's run: order, what isn't tested, redirects' host, cancelling, policy failure, failed start, rule lists PASS");
	return 0;
}
