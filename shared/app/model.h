#ifndef VITALS_APP_MODEL_H
#define VITALS_APP_MODEL_H

#include <stddef.h>
#include <stdint.h>

#include "check_result.h"
#include "vitals_paths.h"

/* The connection test's results, which ui.c draws. The same on every console, but for what each
 * console's requests add (check_result.h's CHECK_RESULT_CONSOLE): its HTTP library's errors are its
 * own, which its check_model.c judges and names. vitals_paths.h is the console's: where its redirect and
 * DNS lists are (VITALS_REDIRECTS, VITALS_DNS) */

#define CHECK_BODY_MAX (96u * 1024u)
#define CHECK_LIST_MAX 64
#define CHECK_NAME_MAX 96

/* The four protocol tiles are tests 0 to 3 (TLS 1.0 to 1.3); the TLS report is test 4 */
enum CheckTest { CHECK_REPORT = 4, CHECK_TEST_COUNT };

enum CheckState { CHECK_WAIT, CHECK_RUNNING, CHECK_PASS, CHECK_FAIL, CHECK_INFO, CHECK_WARNING };

typedef struct {
	enum CheckState style;
	const char *label, *qualifier;
	enum CheckState detail_style;
} CheckProtocolDisplay;

typedef struct {
	enum CheckState state;
	/* The response's status (0 without one) and the request's error (the console's HTTP library's, 0
	 * when it worked) */
	int http_code, error;
	/* What else the console's requests record (check_result.h) */
	CHECK_RESULT_CONSOLE
	unsigned elapsed_ms;
	/* Requests made, timeouts retried included */
	unsigned attempts;
	char message[128];
} CheckResult;

typedef struct {
	unsigned id;
	char name[CHECK_NAME_MAX];
} CheckNamed;

typedef struct {
	int valid;
	CheckNamed version, cipher, group, signature;
	CheckNamed ciphers[CHECK_LIST_MAX], groups[CHECK_LIST_MAX], extensions[CHECK_LIST_MAX];
	unsigned cipher_count, group_count, extension_count;
	char ja3[65], ja4[129], alpn[96];
} CheckHandshake;

/* Host redirects as the console's redirects.txt lists them, at most as many as vitals applies */
#define CHECK_REDIRECTS_PATH VITALS_REDIRECTS
#define CHECK_REDIRECT_MAX 32
/* The DNS rules, tested by looking each name up as a game would: the kernel plugin sees the
 * app's own queries */
#define CHECK_DNS_PATH VITALS_DNS
#define CHECK_DNS_MAX 32
#define CHECK_HOST_MAX 254
typedef struct {
	char from[CHECK_HOST_MAX], to[CHECK_HOST_MAX];
	/* A redirect's: the host that answered its request, "" until one did or when the console can't
	 * tell */
	char reached[CHECK_HOST_MAX];
	CheckResult result;
} CheckRedirect;

/* The badssl.com battery: hosts that must load, and hosts whose certificate or ciphers must be
 * refused */
#define CHECK_BADSSL_COUNT 12
typedef struct {
	const char *host; /* With its port when not 443 */
	const char *label;
	int refuse;
} CheckBadssl;

typedef struct {
	CheckResult protocols[4], connection;
	CheckResult badssl[CHECK_BADSSL_COUNT];
	CheckRedirect redirects[CHECK_REDIRECT_MAX];
	unsigned redirect_count;
	/* The DNS rules (dns.txt), as host -> target pairs; dns_off while they're turned off. None on a
	 * console whose test doesn't look them up */
	CheckRedirect dns[CHECK_DNS_MAX];
	unsigned dns_count;
	int dns_off;
	CheckHandshake handshake;
	int started, complete;
	/* The run was cancelled (Triangle, or leaving the test) before it finished */
	int interrupted;
	/* Whether vitals is running here, -1 until known: on the PS3 whether the TLS 1.3 tile connected
	 * (Sony's libssl has no TLS 1.3, so a connection there is vitals'), on the Vita whether vitals'
	 * libhttp is the one loaded */
	int vitals_enabled;
	/* Whether vitals' libhttp and libssl are the ones answering (the Vita's process, the PS3's boot
	 * markers), and whether HTTP's redirects are off (redirects.off): the parts the screen shows, as
	 * the Options name them. -1 until known; the redirects are tested only while libhttp is vitals' */
	int libhttp_active, tls_active, redirects_off;
	/* The run's report: 0 not saved, 1 saved (as report), -1 the last attempt failed */
	int report_saved;
	char report[160];
} CheckService;

/* ---- shared/app/model.c ---- */

/* The BrowserLeaks endpoints: tests 0 to 3, then the TLS report */
const char *check_endpoint(unsigned test);
const CheckBadssl *check_badssl(unsigned index);
/* Which detail page shows how far the run has got, for the test screen to follow it: the TLS tiles'
 * request details, the TLS report's ciphers, the badssl.com checks, the redirects, the DNS rules;
 * -1 before any check has started. item is the latest host's place in its list (0 for the others) */
enum {
	CHECK_FOLLOW_REQUESTS = 0,
	CHECK_FOLLOW_CIPHERS = 1,
	CHECK_FOLLOW_CERTIFICATES = 3,
	CHECK_FOLLOW_REDIRECTS = 4,
	CHECK_FOLLOW_DNS = 5
};
int check_follow(const CheckService *s, unsigned *item);
/* The TLS report's JSON (tls.browserleaks.com); 0, or -1 when it isn't one */
int check_parse_browserleaks(const char *body, size_t size, CheckHandshake *out);
/* The host alone from what a console says a request reached: a URL (the Vita's) or a host, with or
 * without its port (the PS3's); "" when it names none or doesn't fit */
void check_reached_host(const char *reached, char *host, size_t size);
/* A finished request to a redirect's old host, rc its fetch's: any final status passes when the
 * host that answered (host, check_reached_host's) is the rule's new one, case aside, and fails when
 * it's another; host "" when the console can't tell. A failed request keeps the fetch's words */
void check_redirect_judge(CheckResult *result, int rc, const char *host, const char *expected);

/* A name looked up as a game would: found, else why (the resolver's h_errno on the PS3, the
 * Vita's resolver errors in the same words), and its IPv4 addresses */
#define CHECK_DNS_ADDRESSES 8
enum {
	CHECK_LOOKUP_NO_HOST = 1,
	CHECK_LOOKUP_TRY_AGAIN = 2,
	CHECK_LOOKUP_FAILED = 3,
	CHECK_LOOKUP_NO_ADDRESS = 4
};
typedef struct {
	int found, error;
	unsigned count;
	unsigned char addresses[CHECK_DNS_ADDRESSES][4];
} CheckLookup;
/* What a DNS rule's target is: another host name, an IPv4 address, or block */
enum CheckDnsTarget { CHECK_DNS_NAME, CHECK_DNS_ADDRESS, CHECK_DNS_BLOCK };
enum CheckDnsTarget check_dns_target(const char *target, unsigned char address[4]);
/* A rule's lookup against what the rule says: block passes when the name doesn't exist, an address
 * when it's among the answers, a host name when an answer is among the target's own (target is the
 * target's lookup, for a host name only) */
void check_dns_judge(const char *rule_target, const CheckLookup *answer, const CheckLookup *target, CheckResult *result);
/* A finished badssl.com request: a host that must load passes on any status; one that must be refused
 * passes when it was reached and refused, fails when it loaded or nothing refused it, and is
 * inconclusive when it wasn't reached (check_request_unreachable) */
void check_badssl_judge(const CheckBadssl *test, CheckResult *result);

/* ---- each console's check_model.c: what ui.c shows of a request ---- */

/* A protocol tile (TLS 1.<version>): its mark, words and colours */
CheckProtocolDisplay check_protocol_display(unsigned version, const CheckResult *result, int vitals_enabled);
/* The tile's request in a line, on the request details page */
void check_protocol_detail(unsigned version, const CheckResult *result, char *text, size_t capacity);
/* The request's error codes, or "OK" or "-", for that page's codes column */
void check_request_codes(const CheckResult *result, char *text, size_t capacity);
/* How long the request took in all, retries included, for its time column */
unsigned check_request_ms(const CheckResult *result);
/* A failed request in words after prefix, as the console's HTTP library names its error */
void check_request_failure(CheckResult *result, const char *prefix);
/* 1 when a failed request never reached the server's TLS (the resolver, the connection, a timeout),
 * or the console can't trust its result: it proves nothing about the certificate */
int check_request_unreachable(const CheckResult *result);

#endif
