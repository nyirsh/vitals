/* The connection test's saved report, for every console (check_report.h) */

#include "check_report.h"

#include <stdarg.h>
#include <stdio.h>

void check_report_add(CheckReport *report, const char *format, ...)
{
	if (report->used + 1 >= report->capacity)
		return;
	va_list arguments;
	va_start(arguments, format);
	int n = vsnprintf(report->data + report->used, report->capacity - report->used, format, arguments);
	va_end(arguments);
	if (n > 0)
		report->used += (size_t)n < report->capacity - report->used ? (size_t)n : report->capacity - report->used - 1;
}

static void add_result(const CheckReportFormat *format, CheckReport *report, const CheckResult *r)
{
	check_report_add(report, "state=%d\nHTTP=%d\nerror=0x%08X\n", r->state, r->http_code, (unsigned)r->error);
	format->result(report, r);
	check_report_add(report, "elapsed_ms=%u\nattempts=%u\nresult=%s\n", r->elapsed_ms, r->attempts, r->message);
}

void check_report_write(const CheckReportFormat *format, const CheckService *s, CheckReport *report)
{
	if (report->capacity != 0)
		report->data[0] = '\0';
	check_report_add(report,
	                 "vitals " VITALS_VERSION " connection test (%s)\nAPI=%s\nservice=BrowserLeaks + badssl.com\n"
	                 "Connection reuse=disabled\nRedirects=disabled\n",
	                 format->console, format->api);
	format->about(report, s);
	check_report_add(report, "vitals=%s\n",
	                 s->vitals_enabled < 0 ? "checking" : s->vitals_enabled ? "enabled" : "not enabled");

	for (unsigned i = 0; i < CHECK_TEST_COUNT; ++i) {
		const CheckResult *r = i == CHECK_REPORT ? &s->connection : &s->protocols[i];
		check_report_add(report, "\nURL=%s\n", check_endpoint(i));
		add_result(format, report, r);
		if (i < 4) {
			char detail[160];
			check_protocol_detail(i, r, detail, sizeof(detail));
			check_report_add(report, "classification=%s\ndetail=%s\n",
			                 check_protocol_display(i, r, s->vitals_enabled).label, detail);
			if (format->protocol != NULL)
				format->protocol(report, i, r);
		}
	}

	check_report_add(report, "\nbadssl.com=%u\n", CHECK_BADSSL_COUNT);
	for (unsigned i = 0; i < CHECK_BADSSL_COUNT; ++i) {
		const CheckBadssl *test = check_badssl(i);
		check_report_add(report, "%s (%s, expected %s)\n", test->host, test->label, test->refuse ? "refused" : "loaded");
		add_result(format, report, &s->badssl[i]);
	}

	check_report_add(report, "\nHost redirects (" CHECK_REDIRECTS_PATH ")=%u\n", s->redirect_count);
	for (unsigned i = 0; i < s->redirect_count && i < CHECK_REDIRECT_MAX; ++i) {
		const CheckRedirect *redirect = &s->redirects[i];
		check_report_add(report, "%s -> %s\nreached=%s\n", redirect->from, redirect->to,
		                 redirect->reached[0] ? redirect->reached : "-");
		add_result(format, report, &redirect->result);
	}

	check_report_add(report, "\nDNS rules (" CHECK_DNS_PATH ")=%u%s\n", s->dns_count,
	                 s->dns_off ? ", off (flags/dns.off)" : "");
	for (unsigned i = 0; i < s->dns_count && i < CHECK_DNS_MAX; ++i) {
		const CheckResult *r = &s->dns[i].result;
		check_report_add(report, "%s -> %s\nstate=%d\nelapsed_ms=%u\nresult=%s\n", s->dns[i].from, s->dns[i].to,
		                 r->state, r->elapsed_ms, r->message);
	}

	const CheckHandshake *h = &s->handshake;
	check_report_add(report,
	                 "\nSelected protocol=%04X %s\nSelected cipher=%04X %s\nKey exchange=%04X %s\nSignature=%04X %s\n"
	                 "ALPN offered=%s\nJA3=%s\nJA4=%s\n",
	                 h->version.id, h->version.name, h->cipher.id, h->cipher.name, h->group.id, h->group.name,
	                 h->signature.id, h->signature.name, h->alpn, h->ja3, h->ja4);
	const CheckNamed *lists[] = {h->ciphers, h->groups, h->extensions};
	const unsigned counts[] = {h->cipher_count, h->group_count, h->extension_count};
	const char *labels[] = {"Offered ciphers (not individually negotiated)", "Offered groups", "Offered extensions"};
	for (unsigned l = 0; l < 3; ++l) {
		check_report_add(report, "\n%s\n", labels[l]);
		for (unsigned n = 0; n < counts[l] && n < CHECK_LIST_MAX; ++n)
			check_report_add(report, "%04X %s\n", lists[l][n].id, lists[l][n].name);
	}
}

void check_report_path(char *path, size_t size, const char *directory, const char *name, const CheckReportTime *t,
                       uint64_t fallback)
{
	if (t != NULL)
		snprintf(path, size, "%s/%s-%04u-%02u-%02u_%02u-%02u-%02u.txt", directory, name, t->year, t->month, t->day,
		         t->hour, t->minute, t->second);
	else
		snprintf(path, size, "%s/%s-%llu.txt", directory, name, (unsigned long long)fallback);
}
