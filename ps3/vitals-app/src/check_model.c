/* The connection test's judgements on the PS3, as the Vita's check_model.c makes them, for Sony's
 * libhttp. Its network errors have the system's errno in the low byte: 0x801xx the resolver, 0x803xx
 * a socket option, 0x805xx connect, 0x806xx send, 0x807xx receive, 0x808xx select, and 0x80710093 a
 * wait that timed out (Sony's code); its TLS ones are 0x80710Axx to 0x80710Dxx. What's the same on
 * every console (the endpoints, the badssl.com battery, the TLS report's parser) is shared/app/model.c */

#include "check_model.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#define VERIFY_UNKNOWN_CA 0x00000008u
#define VERIFY_BAD_CHAIN 0x00000010u
#define VERIFY_NOT_VERIFIABLE 0x00000040u
#define VERIFY_INVALID_CERT 0x00000080u
#define VERIFY_VERIFY_FAILED 0x00000200u
#define VERIFY_COMMON_NAME 0x00000400u
#define VERIFY_EXPIRED 0x00000800u
#define VERIFY_NOT_YET_VALID 0x00001000u

int check_unreachable(int error)
{
	uint32_t e = (uint32_t)error;
	/* The resolver, a socket option, connect, select and the wait timing out: before any TLS */
	return (e & 0xffffff00u) == 0x80710100u || (e & 0xffffff00u) == 0x80710300u || (e & 0xffffff00u) == 0x80710500u ||
	       (e & 0xffffff00u) == 0x80710800u || e == 0x80710093u || e == 0x80710012u || e == 0x80710020u;
}

static int tls_refused(const CheckResult *r)
{
	uint32_t e = (uint32_t)r->error;
	return r->verify_error != 0 || (e >= 0x80710a00u && e <= 0x80710dffu);
}

const char *check_error_name(int error, uint32_t verify)
{
	if (verify & VERIFY_EXPIRED)
		return "Certificate expired";
	if (verify & VERIFY_NOT_YET_VALID)
		return "Certificate not yet valid";
	if (verify & VERIFY_COMMON_NAME)
		return "Certificate hostname mismatch";
	if (verify & VERIFY_UNKNOWN_CA)
		return "Unknown certificate authority";
	if (verify & (VERIFY_BAD_CHAIN | VERIFY_NOT_VERIFIABLE))
		return "Certificate chain not verifiable";
	if (verify & (VERIFY_INVALID_CERT | VERIFY_VERIFY_FAILED))
		return "Certificate refused";
	if (verify != 0)
		return "Certificate check failed";
	uint32_t e = (uint32_t)error;
	switch (e & 0xffffff00u) {
	case 0x80710100u:
		return "Name not resolved";
	case 0x80710200u:
		return "Connection aborted";
	case 0x80710300u:
		/* A socket option failing on a dead socket: how a refused connection shows */
		return "Connection failed";
	case 0x80710400u:
		return "Socket error";
	case 0x80710500u:
		return "Connection failed";
	case 0x80710600u:
		return "Send failed";
	case 0x80710700u:
		return "Receive failed";
	case 0x80710800u:
		return "Network error";
	case 0x80710a00u:
		return "Certificate error";
	case 0x80710b00u:
		return "TLS handshake refused";
	case 0x80710c00u:
	case 0x80710d00u:
		return "TLS connection error";
	default:
		break;
	}
	switch (e) {
	case 0:
		return "OK";
	case 0x80710012u:
	case 0x80710020u:
		return "No connection";
	case 0x80710024u:
		return "Cancelled";
	case 0x80710093u:
		return "Timed out";
	case 0x80710003u:
		return "Out of memory";
	default:
		return "Request failed";
	}
}

/* A failure in words, with libhttp's code after it when it isn't the certificate's */
static void failure(CheckResult *r, const char *prefix)
{
	const char *name = check_error_name(r->error, r->verify_error);
	/* A certificate's reason says enough: its flags are on the request page and in the report */
	if (r->verify_error == 0 && r->error != 0)
		snprintf(r->message, sizeof(r->message), "%s%s (0x%08X)", prefix, name, (unsigned)r->error);
	else
		snprintf(r->message, sizeof(r->message), "%s%s", prefix, name);
}

void check_protocol_judge(unsigned version, CheckResult *r)
{
	(void)version;
	if (r->http_code == 200 && r->error == 0) {
		r->state = CHECK_PASS;
		snprintf(r->message, sizeof(r->message), "HTTP %d", r->http_code);
	} else if (r->http_code > 0 && r->error == 0) {
		/* Redirects aren't followed, as on the Vita */
		r->state = CHECK_FAIL;
		snprintf(r->message, sizeof(r->message), "HTTP %d (no redirect followed)", r->http_code);
	} else {
		r->state = CHECK_FAIL;
		failure(r, "");
	}
}

/* TLS 1.0 and 1.1 are refused by vitals on purpose: a refusal there is the secure answer, shown
 * as a block, once TLS 1.3 shows vitals is the one answering */
CheckProtocolDisplay check_protocol_display(unsigned version, const CheckResult *r, int vitals_enabled)
{
	CheckProtocolDisplay display = {r->state, "Waiting", NULL, r->state};
	switch (r->state) {
	case CHECK_PASS:
		if (version < 2) {
			display.style = display.detail_style = CHECK_WARNING;
			display.label = "Connected";
			display.qualifier = "insecure";
		} else {
			display.label = "Connected";
			display.qualifier = "secure";
		}
		break;
	case CHECK_FAIL:
		if (version < 2 && vitals_enabled == 1 && !check_unreachable(r->error)) {
			display.style = display.detail_style = CHECK_PASS;
			display.label = "Blocked";
			display.qualifier = "secure";
		} else if (check_unreachable(r->error)) {
			display.label = "Unreachable";
		} else if (tls_refused(r)) {
			display.label = r->verify_error != 0 ? "Cert error" : "TLS error";
		} else {
			display.label = "Failed";
		}
		break;
	case CHECK_RUNNING:
		display.label = "Checking...";
		break;
	case CHECK_INFO:
		display.label = "Not tested";
		break;
	default:
		break;
	}
	return display;
}

void check_protocol_detail(unsigned version, const CheckResult *r, char *text, size_t capacity)
{
	(void)version;
	if (r->state == CHECK_PASS && r->cipher[0] != '\0')
		snprintf(text, capacity, "%s, %s", r->message, r->cipher);
	else if (r->message[0] != '\0')
		snprintf(text, capacity, "%s", r->message);
	else
		snprintf(text, capacity, "%s", r->state == CHECK_RUNNING ? "Testing..." : "-");
}

void check_request_codes(const CheckResult *r, char *text, size_t capacity)
{
	if (r->error || r->verify_error) {
		if (r->verify_error == 0)
			snprintf(text, capacity, "0x%08X / -", (unsigned)r->error);
		else
			snprintf(text, capacity, "0x%08X / flags 0x%04X", (unsigned)r->error, (unsigned)r->verify_error);
	} else
		snprintf(text, capacity, "%s", r->state == CHECK_PASS ? "OK" : "-");
}

unsigned check_request_ms(const CheckResult *r)
{
	return r->elapsed_ms;
}

void check_badssl_judge(const CheckBadssl *test, CheckResult *r)
{
	if (!test->refuse) {
		if (r->http_code > 0 && r->error == 0) {
			r->state = CHECK_PASS;
			snprintf(r->message, sizeof(r->message), "Loaded (HTTP %d)", r->http_code);
		} else {
			r->state = CHECK_FAIL;
			failure(r, "");
		}
	} else if (r->http_code > 0 && r->error == 0) {
		r->state = CHECK_FAIL;
		snprintf(r->message, sizeof(r->message), "Loaded (HTTP %d), should be refused", r->http_code);
	} else if (check_unreachable(r->error)) {
		r->state = CHECK_FAIL;
		failure(r, "Inconclusive: ");
	} else {
		r->state = CHECK_PASS;
		failure(r, "Refused: ");
	}
}

int check_timed_out(int error)
{
	unsigned e = (unsigned)error, kind = e & 0xffffff00u;
	return e == 0x80710093u || ((e & 0xffu) == 35 && (kind == 0x80710600u || kind == 0x80710700u ||
	                                                  kind == 0x80710c00u || kind == 0x80710d00u));
}

static int same_host(const char *a, const char *b)
{
	for (; *a != '\0' && *b != '\0'; ++a, ++b)
		if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
			return 0;
	return *a == *b;
}

void check_redirect_judge(CheckResult *r, const char *reached, const char *expected)
{
	if (r->http_code >= 200 && r->http_code <= 599 && r->error == 0) {
		r->state = CHECK_PASS;
		if (reached == NULL || reached[0] == '\0' || expected == NULL)
			snprintf(r->message, sizeof(r->message), "Connected (HTTP %d); the host reached isn't known", r->http_code);
		else if (same_host(reached, expected))
			snprintf(r->message, sizeof(r->message), "Reached %.96s (HTTP %d)", expected, r->http_code);
		else {
			r->state = CHECK_FAIL;
			snprintf(r->message, sizeof(r->message), "Answered by %.50s, not %.50s", reached, expected);
		}
	} else {
		r->state = CHECK_FAIL;
		failure(r, "");
	}
}

enum CheckDnsTarget check_dns_target(const char *target, unsigned char address[4])
{
	static const char block[] = "block";
	size_t length = strlen(target);
	if (length == sizeof(block) - 1) {
		size_t i = 0;
		while (i < length && tolower((unsigned char)target[i]) == block[i])
			++i;
		if (i == length)
			return CHECK_DNS_BLOCK;
	}
	/* Four decimal parts of at most 255, as the kernel plugin reads them */
	unsigned part = 0, parts = 0, digits = 0;
	for (size_t i = 0;; ++i) {
		char c = target[i];
		if (c >= '0' && c <= '9') {
			part = part * 10 + (unsigned)(c - '0');
			if (++digits > 3 || part > 255)
				return CHECK_DNS_NAME;
		} else if ((c == '.' || c == '\0') && digits) {
			if (parts == 4)
				return CHECK_DNS_NAME;
			address[parts++] = (unsigned char)part;
			part = digits = 0;
			if (c == '\0')
				return parts == 4 ? CHECK_DNS_ADDRESS : CHECK_DNS_NAME;
		} else
			return CHECK_DNS_NAME;
	}
}

static void print_addresses(const CheckLookup *lookup, char *text, size_t capacity)
{
	size_t used = 0;
	text[0] = '\0';
	for (unsigned i = 0; i < lookup->count && i < CHECK_DNS_ADDRESSES && used < capacity; ++i) {
		const unsigned char *a = lookup->addresses[i];
		int n = snprintf(text + used, capacity - used, "%s%u.%u.%u.%u", i ? ", " : "", a[0], a[1], a[2], a[3]);
		if (n < 0)
			break;
		used += (size_t)n;
	}
}

static int has_address(const CheckLookup *lookup, const unsigned char address[4])
{
	for (unsigned i = 0; i < lookup->count && i < CHECK_DNS_ADDRESSES; ++i)
		if (memcmp(lookup->addresses[i], address, 4) == 0)
			return 1;
	return 0;
}

static const char *lookup_error(int error)
{
	switch (error) {
	case 1: return "no such host";
	case 2: return "no answer, try again";
	case 3: return "the resolver failed";
	case 4: return "no address";
	default: return "the lookup failed";
	}
}

void check_dns_judge(const char *rule_target, const CheckLookup *answer, const CheckLookup *target, CheckResult *r)
{
	unsigned char address[4];
	char got[96];
	print_addresses(answer, got, sizeof(got));
	switch (check_dns_target(rule_target, address)) {
	case CHECK_DNS_BLOCK:
		/* The plugin answers "no such name"; a resolver may call that no address */
		if (!answer->found && (answer->error == 1 || answer->error == 4)) {
			r->state = CHECK_PASS;
			snprintf(r->message, sizeof(r->message), "Blocked (no such host)");
		} else if (answer->found) {
			r->state = CHECK_FAIL;
			snprintf(r->message, sizeof(r->message), "Not blocked: %s", got);
		} else {
			r->state = CHECK_FAIL;
			snprintf(r->message, sizeof(r->message), "Not blocked: %s", lookup_error(answer->error));
		}
		return;
	case CHECK_DNS_ADDRESS:
		if (answer->found && has_address(answer, address)) {
			r->state = CHECK_PASS;
			snprintf(r->message, sizeof(r->message), "Resolved to %s", got);
		} else {
			r->state = CHECK_FAIL;
			if (answer->found)
				snprintf(r->message, sizeof(r->message), "Resolved to %s instead", got);
			else
				snprintf(r->message, sizeof(r->message), "Not resolved: %s", lookup_error(answer->error));
		}
		return;
	case CHECK_DNS_NAME:
		break;
	}
	if (!target->found) {
		/* Renamed, the name gets the target's answer: none to compare with */
		r->state = CHECK_INFO;
		snprintf(r->message, sizeof(r->message), "Can't tell: the target doesn't resolve (%s)", lookup_error(target->error));
		return;
	}
	if (!answer->found) {
		r->state = CHECK_FAIL;
		snprintf(r->message, sizeof(r->message), "Not resolved: %s", lookup_error(answer->error));
		return;
	}
	/* Any address the two share: a server that rotates its addresses may give each lookup a
	 * different few */
	for (unsigned i = 0; i < answer->count && i < CHECK_DNS_ADDRESSES; ++i)
		if (has_address(target, answer->addresses[i])) {
			r->state = CHECK_PASS;
			snprintf(r->message, sizeof(r->message), "Resolved: %s", got);
			return;
		}
	r->state = CHECK_FAIL;
	snprintf(r->message, sizeof(r->message), "Resolved to %s, not the target's", got);
}
