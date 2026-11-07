#ifndef VITALS_APP_MODEL_H
#define VITALS_APP_MODEL_H

#include <stddef.h>
#include <stdint.h>

#include "vitals_paths.h"

/* The connection test's results, which ui.c draws. A request's error and a refused certificate's flags
 * are the console's HTTP library's (on the PS3, libhttp's 0x8071xxxx and CELL_HTTPS_VERIFY_ERROR_*),
 * which the console's check_model.c judges and names. vitals_paths.h is the console's: where its
 * redirect and DNS lists are (VITALS_REDIRECTS, VITALS_DNS) */

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
	/* The response's status (0 without one), the request's error (libhttp's, 0 when it worked),
	 * and the certificate check's flags when libhttp's check refused the server */
	int http_code, error;
	uint32_t verify_error;
	/* What the connection used: Sony's CELL_SSL_VERSION (0 TLS, 1 SSL 3.0, -1 none) and the cipher's
	 * name; http_protocol_name names them */
	int ssl_version;
	char cipher[64];
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

/* Host redirects as /dev_hdd0/vitals/redirects.txt lists them, at most as many as vitals applies */
#define CHECK_REDIRECTS_PATH VITALS_REDIRECTS
#define CHECK_REDIRECT_MAX 32
/* The DNS rules, tested by looking each name up as a game would: the kernel plugin sees the
 * app's own queries */
#define CHECK_DNS_PATH VITALS_DNS
#define CHECK_DNS_MAX 32
#define CHECK_DNS_ADDRESSES 8
#define CHECK_HOST_MAX 254
typedef struct {
	char from[CHECK_HOST_MAX], to[CHECK_HOST_MAX];
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
	/* The DNS rules (dns.txt), as host -> target pairs; dns_off while flags/dns.off is there */
	CheckRedirect dns[CHECK_DNS_MAX];
	unsigned dns_count;
	int dns_off;
	CheckHandshake handshake;
	int started, complete;
	/* The run was cancelled (Triangle, or leaving the test) before it finished */
	int interrupted;
	/* -1 until the TLS 1.3 tile is done, then whether it connected: Sony's libssl has no TLS 1.3,
	 * so a connection there is vitals' */
	int vitals_enabled;
	/* Whether vitals' libhttp is the one this boot loads (the boot plugin's libhttp.active, written
	 * this boot): the redirects are tested only then. -1 until known */
	int libhttp_active;
	/* The run's report: 0 not saved, 1 saved (as report), -1 the last attempt failed */
	int report_saved;
	char report[160];
} CheckService;

const char *check_endpoint(unsigned test);
const CheckBadssl *check_badssl(unsigned index);
/* A finished request to a protocol endpoint: which state the tile shows */
void check_protocol_judge(unsigned version, CheckResult *result);
CheckProtocolDisplay check_protocol_display(unsigned version, const CheckResult *result, int vitals_enabled);
void check_protocol_detail(const CheckResult *result, char *text, size_t capacity);
/* A finished badssl.com request against what the case expects: a refusal passes only when the
 * host was reached and the TLS or its certificate was refused */
void check_badssl_judge(const CheckBadssl *test, CheckResult *result);
/* A finished request to a redirect's old host: any final HTTP status passes, as on the Vita, since
 * only the new server's reachability through vitals is tested */
void check_redirect_judge(CheckResult *result);
/* A name's lookup through libnet: found, else the resolver's h_errno, and the IPv4 addresses */
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
/* libhttp's error, or the certificate check's first flag, in words */
const char *check_error_name(int error, uint32_t verify_error);
/* 1 when a request ran out of time, which the test makes again (http.c): libhttp's own timeout, or a
 * socket's EAGAIN (35) on send or receive, plain or TLS */
int check_timed_out(int error);
/* 1 when the request failed before any TLS: the name, the network or the connection */
int check_unreachable(int error);
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

#endif
