/* The connection test's saved report (shared/app/check_report.c), with a console's parts from a
 * script: every section in order, the console's own lines and fields where they go, the redirects'
 * host and the DNS rules, a report cut at its capacity, and the file's name. Built against each
 * console's check_model.c, so it runs with both consoles' results */

#include "check_report.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned results, protocols;

static void about(CheckReport *report, const CheckService *s)
{
	check_report_add(report, "console line, %u redirects\n", s->redirect_count);
}

static void result(CheckReport *report, const CheckResult *r)
{
	++results;
	check_report_add(report, "own_field=%d\n", r->http_code);
}

static void protocol(CheckReport *report, unsigned test, const CheckResult *r)
{
	(void)r;
	++protocols;
	check_report_add(report, "tile_field=%u\n", test);
}

static const CheckReportFormat format = {"Test console", "testHttp", about, result, protocol};

/* Where text first appears in report, which must have it */
static const char *at(const char *report, const char *text)
{
	const char *found = strstr(report, text);
	if (found == NULL) {
		fprintf(stderr, "missing \"%s\"\n", text);
		assert(0);
	}
	return found;
}

int main(void)
{
	static CheckService s;
	s.vitals_enabled = 1;
	s.protocols[3].http_code = 200;
	s.protocols[3].state = CHECK_PASS;
	snprintf(s.protocols[3].message, sizeof(s.protocols[3].message), "TLS 1.3");
	s.redirect_count = 2;
	snprintf(s.redirects[0].from, sizeof(s.redirects[0].from), "old.example");
	snprintf(s.redirects[0].to, sizeof(s.redirects[0].to), "new.example");
	snprintf(s.redirects[0].reached, sizeof(s.redirects[0].reached), "new.example");
	s.redirects[0].result.http_code = 404;
	snprintf(s.redirects[1].from, sizeof(s.redirects[1].from), "other.example");
	s.dns_count = 1;
	s.dns_off = 1;
	snprintf(s.dns[0].from, sizeof(s.dns[0].from), "ads.example");
	snprintf(s.dns[0].to, sizeof(s.dns[0].to), "block");
	snprintf(s.dns[0].result.message, sizeof(s.dns[0].result.message), "Not tested: DNS rules are off");
	s.handshake.cipher_count = 1;
	s.handshake.ciphers[0] = (CheckNamed){0x1301, "TLS_AES_128_GCM_SHA256"};

	CheckReport report = {malloc(96 * 1024), 0, 96 * 1024};
	assert(report.data != NULL);
	check_report_write(&format, &s, &report);
	const char *text = report.data;
	assert(strlen(text) == report.used);

	/* Each section, in order */
	const char *header = at(text, "vitals " VITALS_VERSION " connection test (Test console)\nAPI=testHttp\n");
	const char *console = at(text, "console line, 2 redirects\nvitals=enabled\n");
	const char *tile = at(text, "\nURL=");
	const char *badssl = at(text, "\nbadssl.com=12\n");
	const char *redirects = at(text, "\nHost redirects (");
	const char *dns = at(text, "\nDNS rules (");
	const char *handshake = at(text, "\nSelected protocol=");
	const char *ciphers = at(text, "\nOffered ciphers (not individually negotiated)\n1301 TLS_AES_128_GCM_SHA256\n");
	assert(header == text && header < console && console < tile && tile < badssl && badssl < redirects &&
	       redirects < dns && dns < handshake && handshake < ciphers);

	/* The console's fields for every request: 5 tiles, the badssl.com hosts and the redirects; its
	 * tile lines for the TLS tiles only, after their classification */
	assert(results == CHECK_TEST_COUNT + CHECK_BADSSL_COUNT + 2 && protocols == 4);
	at(text, "state=2\nHTTP=200\nerror=0x00000000\nown_field=200\nelapsed_ms=0\nattempts=0\nresult=TLS 1.3\n"
	         "classification=");
	at(text, "tile_field=3\n");

	/* The host that answered each redirect, "-" when none did */
	at(redirects, "old.example -> new.example\nreached=new.example\nstate=0\nHTTP=404\n");
	at(redirects, "other.example -> \nreached=-\n");
	at(dns, "=1, off (flags/dns.off)\nads.example -> block\nstate=0\nelapsed_ms=0\nresult=Not tested: DNS rules are off\n");

	/* A report that doesn't fit stops at its capacity, still a string */
	results = protocols = 0;
	char small[64];
	CheckReport cut = {small, 0, sizeof(small)};
	check_report_write(&format, &s, &cut);
	assert(cut.used == sizeof(small) - 1 && strlen(small) == cut.used && strncmp(small, "vitals ", 7) == 0);
	free(report.data);

	/* The file's name, from the local time or else the fallback */
	char path[96];
	CheckReportTime t = {2026, 11, 7, 9, 5, 3};
	check_report_path(path, sizeof(path), "ux0:data/vitals", "vitals-testresults", &t, 0);
	assert(strcmp(path, "ux0:data/vitals/vitals-testresults-2026-11-07_09-05-03.txt") == 0);
	check_report_path(path, sizeof(path), "/dev_hdd0/vitals/reports", "connection-test", NULL, 12345);
	assert(strcmp(path, "/dev_hdd0/vitals/reports/connection-test-12345.txt") == 0);

	puts("connection test's report: sections, the console's parts, redirects' host, DNS rules, capacity, file name PASS");
	return 0;
}
