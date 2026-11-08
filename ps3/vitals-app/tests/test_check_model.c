/* The connection test's rules (check_model.c): how each kind of result is judged and shown, which
 * errors are timeouts the test makes again, and the BrowserLeaks TLS report's parser, including
 * what it must refuse */
#include "check_model.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* libhttp's codes and certificate flags the results carry */
#define OK 0
#define RESOLVER ((int)0x80710101)     /* the name not resolved */
#define REFUSED_PORT ((int)0x80710316) /* a refused connection, as RPCS3 shows it */
#define CONNECT ((int)0x8071053d)      /* ECONNREFUSED */
#define TIMEOUT ((int)0x80710093)
#define CERTIFICATE ((int)0x80710a06)
#define HANDSHAKE ((int)0x80710b00)
#define VERIFY_UNKNOWN_CA 0x00000008u
#define VERIFY_COMMON_NAME 0x00000400u
#define VERIFY_EXPIRED 0x00000800u

static CheckResult result(int http_code, int error, uint32_t verify)
{
	CheckResult r;
	memset(&r, 0, sizeof(r));
	r.http_code = http_code;
	r.error = error;
	r.verify_error = verify;
	return r;
}

static void expect_message(const CheckResult *r, enum CheckState state, const char *message)
{
	if (r->state != state || strcmp(r->message, message) != 0) {
		fprintf(stderr, "state %d \"%s\", expected %d \"%s\"\n", r->state, r->message, state, message);
		assert(0);
	}
}

static void judging(void)
{
	/* A protocol endpoint passes on 200 only: redirects aren't followed, as on the Vita */
	CheckResult r = result(200, OK, 0);
	check_protocol_judge(3, &r);
	expect_message(&r, CHECK_PASS, "HTTP 200");
	r = result(301, OK, 0);
	check_protocol_judge(3, &r);
	expect_message(&r, CHECK_FAIL, "HTTP 301 (no redirect followed)");
	r = result(0, HANDSHAKE, 0);
	check_protocol_judge(1, &r);
	expect_message(&r, CHECK_FAIL, "TLS handshake refused (0x80710B00)");

	/* badssl.com: a host that should load must; one that should be refused passes only when it was
	 * reached and refused, and is inconclusive when it wasn't reached */
	const CheckBadssl good = {"badssl.com", "Valid certificate", 0}, bad = {"expired.badssl.com", "Expired", 1};
	r = result(200, OK, 0);
	check_badssl_judge(&good, &r);
	expect_message(&r, CHECK_PASS, "Loaded (HTTP 200)");
	r = result(0, CERTIFICATE, VERIFY_EXPIRED);
	check_badssl_judge(&good, &r);
	expect_message(&r, CHECK_FAIL, "Certificate expired");
	r = result(0, CERTIFICATE, VERIFY_EXPIRED);
	check_badssl_judge(&bad, &r);
	expect_message(&r, CHECK_PASS, "Refused: Certificate expired");
	r = result(200, OK, 0);
	check_badssl_judge(&bad, &r);
	expect_message(&r, CHECK_FAIL, "Loaded (HTTP 200), should be refused");
	r = result(0, RESOLVER, 0);
	check_badssl_judge(&bad, &r);
	expect_message(&r, CHECK_FAIL, "Inconclusive: Name not resolved (0x80710101)");

}

static void display(void)
{
	/* TLS 1.0 and 1.1 refused by vitals are "Blocked", the secure answer, once vitals is known
	 * to answer; a connection there is "insecure" */
	CheckResult r = result(0, HANDSHAKE, 0);
	r.state = CHECK_FAIL;
	CheckProtocolDisplay shown = check_protocol_display(0, &r, 1);
	assert(shown.style == CHECK_PASS && strcmp(shown.label, "Blocked") == 0 && strcmp(shown.qualifier, "secure") == 0);
	shown = check_protocol_display(0, &r, 0);
	assert(shown.style == CHECK_FAIL && strcmp(shown.label, "TLS error") == 0);
	r = result(0, CERTIFICATE, VERIFY_UNKNOWN_CA);
	r.state = CHECK_FAIL;
	assert(strcmp(check_protocol_display(2, &r, 1).label, "Cert error") == 0);
	r = result(0, CONNECT, 0);
	r.state = CHECK_FAIL;
	assert(strcmp(check_protocol_display(1, &r, 1).label, "Unreachable") == 0);
	r = result(200, OK, 0);
	r.state = CHECK_PASS;
	shown = check_protocol_display(1, &r, 1);
	assert(shown.style == CHECK_WARNING && strcmp(shown.qualifier, "insecure") == 0);
	assert(strcmp(check_protocol_display(3, &r, 1).qualifier, "secure") == 0);

	/* The request page's detail: the cipher after a pass */
	char detail[160];
	r.state = CHECK_PASS;
	snprintf(r.message, sizeof(r.message), "HTTP 200");
	snprintf(r.cipher, sizeof(r.cipher), "TLS1-3-AES-256-GCM-SHA384");
	check_protocol_detail(3, &r, detail, sizeof(detail));
	assert(strcmp(detail, "HTTP 200, TLS1-3-AES-256-GCM-SHA384") == 0);
}

static void errors(void)
{
	/* Timeouts, which the test makes again: libhttp's own, and EAGAIN on send or receive */
	assert(check_timed_out(TIMEOUT));
	assert(check_timed_out((int)0x80710623) && check_timed_out((int)0x80710723));
	assert(check_timed_out((int)0x80710c23) && check_timed_out((int)0x80710d23));
	assert(!check_timed_out(OK) && !check_timed_out(RESOLVER) && !check_timed_out(CONNECT));
	assert(!check_timed_out((int)0x80710523) && !check_timed_out(CERTIFICATE) && !check_timed_out((int)0x80710724));

	/* Unreachable: before any TLS */
	assert(check_unreachable(RESOLVER) && check_unreachable(REFUSED_PORT) && check_unreachable(CONNECT));
	assert(check_unreachable(TIMEOUT));
	assert(!check_unreachable(CERTIFICATE) && !check_unreachable(HANDSHAKE) && !check_unreachable(OK));

	/* A certificate's flag says more than the error it came with */
	assert(strcmp(check_error_name(CERTIFICATE, VERIFY_EXPIRED), "Certificate expired") == 0);
	assert(strcmp(check_error_name(CERTIFICATE, VERIFY_COMMON_NAME | VERIFY_UNKNOWN_CA), "Certificate hostname mismatch") == 0);
	assert(strcmp(check_error_name(TIMEOUT, 0), "Timed out") == 0);
	assert(strcmp(check_error_name(RESOLVER, 0), "Name not resolved") == 0);
}

static void report_parser(void)
{
	static const char report[] =
	    "{\"ja3_hash\": \"0123456789abcdef0123456789abcdef\", \"ja4\": \"t13d1516h2_8daaf6152771_02713d6af862\",\n"
	    " \"tls\": {\"selected_version\": {\"id\": 772, \"name\": \"TLS 1.3\"},\n"
	    "  \"cipher_suite\": {\"id\": 4866, \"name\": \"TLS_AES_256_GCM_SHA384\"},\n"
	    "  \"key_exchange\": {\"id\": 29, \"name\": \"x25519\"},\n"
	    "  \"signature_scheme\": {\"id\": 2052, \"name\": \"rsa_pss_rsae_sha256\"},\n"
	    "  \"cipher_suites\": [{\"id\": 4866, \"name\": \"TLS_AES_256_GCM_SHA384\"},\n"
	    "                    {\"id\": 4867, \"name\": \"TLS_CHACHA20_POLY1305_SHA256\"}, {\"id\": \"bad\"}],\n"
	    "  \"extensions\": [{\"id\": 10, \"name\": \"supported_groups\", \"data\": {\"named_group_list\":\n"
	    "                    [{\"id\": 29, \"name\": \"x25519\"}, {\"id\": 23, \"name\": \"secp256r1\"}]}},\n"
	    "                  {\"id\": 16, \"name\": \"application_layer_protocol_negotiation\",\n"
	    "                   \"data\": {\"protocol_name_list\": [\"http/1.1\"]}}]}}";
	CheckHandshake h;
	assert(check_parse_browserleaks(report, strlen(report), &h) == 0 && h.valid);
	assert(h.version.id == 0x304 && strcmp(h.version.name, "TLS 1.3") == 0);
	assert(h.cipher.id == 0x1302 && strcmp(h.cipher.name, "TLS_AES_256_GCM_SHA384") == 0);
	assert(strcmp(h.group.name, "x25519") == 0 && h.signature.id == 0x804);
	/* The cipher list without the entry that isn't one */
	assert(h.cipher_count == 2 && strcmp(h.ciphers[1].name, "TLS_CHACHA20_POLY1305_SHA256") == 0);
	assert(h.extension_count == 2 && h.group_count == 2 && h.groups[1].id == 23);
	assert(strcmp(h.alpn, "http/1.1") == 0);
	assert(strcmp(h.ja3, "0123456789abcdef0123456789abcdef") == 0 && strncmp(h.ja4, "t13d", 4) == 0);

	/* Refused: no report, a broken one, trailing text, a version outside TLS 1.0 to 1.3, a NUL inside,
	 * and no cipher */
	static const char *const refused[] = {
	    "",
	    "[]",
	    "{\"tls\": {\"selected_version\": {\"id\": 772, \"name\": \"TLS 1.3\"}",
	    "{\"tls\": {\"selected_version\": {\"id\": 772, \"name\": \"TLS 1.3\"}, \"cipher_suite\": {\"id\": 1, \"name\": \"x\"}}} x",
	    "{\"tls\": {\"selected_version\": {\"id\": 768, \"name\": \"SSL 3.0\"}, \"cipher_suite\": {\"id\": 1, \"name\": \"x\"}}}",
	    "{\"tls\": {\"selected_version\": {\"id\": 772, \"name\": \"TLS 1.3\"}}}",
	};
	for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); ++i)
		assert(check_parse_browserleaks(refused[i], strlen(refused[i]), &h) != 0);
	static const char with_nul[] = "{\"tls\": {}\0}";
	assert(check_parse_browserleaks(with_nul, sizeof(with_nul) - 1, &h) != 0);
	assert(check_parse_browserleaks(NULL, 4, &h) != 0 && check_parse_browserleaks(report, strlen(report), NULL) != 0);
}

/* The page the test screen follows: how far the run has got, in the order it goes */
static void following(void)
{
	static CheckService s;
	unsigned item = 99;
	assert(check_follow(&s, &item) == -1 && item == 0);
	s.protocols[2].state = CHECK_RUNNING;
	assert(check_follow(&s, &item) == CHECK_FOLLOW_REQUESTS && item == 0);
	s.protocols[2].state = CHECK_PASS;
	s.connection.state = CHECK_RUNNING;
	assert(check_follow(&s, &item) == CHECK_FOLLOW_CIPHERS);
	s.connection.state = CHECK_PASS;
	s.badssl[7].state = CHECK_RUNNING;
	assert(check_follow(&s, &item) == CHECK_FOLLOW_CERTIFICATES && item == 7);
	s.badssl[7].state = CHECK_PASS;
	s.redirect_count = 3;
	s.redirects[2].result.state = CHECK_RUNNING;
	assert(check_follow(&s, &item) == CHECK_FOLLOW_REDIRECTS && item == 2);
	/* A state past the listed redirects isn't one: the run got as far as the badssl.com checks */
	s.redirect_count = 2;
	assert(check_follow(&s, &item) == CHECK_FOLLOW_CERTIFICATES && item == 7);
	s.dns_count = 6;
	s.dns[5].result.state = CHECK_RUNNING;
	assert(check_follow(&s, &item) == CHECK_FOLLOW_DNS && item == 5);
	/* A check too quick to be seen running still moves the page, which stays there once it's done */
	s.dns[5].result.state = CHECK_WAIT;
	s.dns[1].result.state = CHECK_PASS;
	assert(check_follow(&s, &item) == CHECK_FOLLOW_DNS && item == 1);
}

int main(void)
{
	judging();
	display();
	errors();
	report_parser();
	following();
	puts("check_model: protocol, badssl.com judging, display, timeouts, error names, the TLS report, following the run PASS");
	return 0;
}
