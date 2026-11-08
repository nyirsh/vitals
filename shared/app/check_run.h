#ifndef VITALS_APP_CHECK_RUN_H
#define VITALS_APP_CHECK_RUN_H

#include <stddef.h>
#include <stdint.h>

#include "model.h"
#include "vitals/redirect_list.h"

/* The connection test's run, the same on every console (check_run.c): the TLS tiles, TLS 1.3 first,
 * then the TLS report, last of those so it can't gate the tiles; the badssl.com battery; each host
 * redirect; each DNS rule. It decides what isn't tested, stops where the run is cancelled, and puts
 * each result in the service as it goes. What it asks of the console is below: its HTTP library,
 * how it judges and names that library's results, and its system's calls. */

/* Which parts of vitals are on here, as the console finds out: 1, 0, or -1 when it can't tell */
typedef struct {
	/* vitals' HTTP and TLS libraries are the ones answering this run's requests */
	int http, tls;
	/* HTTP's Redirects off (redirects.off), and the DNS rules off (dns.off) */
	int redirects_off, dns_off;
	/* Whether vitals is running, as the screen and the tiles show it: either of its modules is (the
	 * Vita's process, the PS3's boot markers); -1 for a console that can't tell, to take it from the
	 * TLS 1.3 tile (Sony's TLS has no 1.3, so a connection there is vitals') */
	int vitals;
	/* 1 when vitals' HTTP is too old to say which host answered a request (the Vita's before
	 * vitalsHttpGetUrl): the redirects can't be tested then */
	int http_outdated;
} CheckParts;

typedef struct {
	/* The network and the console's HTTP libraries, once at the start: 0, or the error, with what
	 * the TLS report's row says of it in notice */
	int (*open)(char *notice, size_t size);
	/* After open */
	void (*parts)(CheckParts *parts);
	/* A list of "host target" rules (the redirects, the DNS rules), at most max; none when the file
	 * isn't there */
	unsigned (*load)(const char *path, CheckRedirect *list, unsigned max);
	/* A TLS tile (test 0 to 3) from request to its state and message, as the console judges it (its
	 * retries and blocks included): body has room for CHECK_BODY_MAX + 1 */
	void (*protocol)(unsigned test, char *body, CheckResult *result);
	/* A request to url with certificate checks on, timeouts retried: with status_only any final
	 * status, else the body of an HTTP 200 into body (CHECK_BODY_MAX + 1) and its size into *length.
	 * The result holds the status, the error and the console's details, and a failure's words in
	 * its message; reached the host the request went to ("" when the console can't tell). 0, or
	 * the error */
	int (*fetch)(const char *url, int status_only, char *body, size_t *length, char *reached, size_t reached_size,
	             CheckResult *result);
	/* The console's judge of a finished badssl.com request (its check_model.c); a redirect's is
	 * shared (check_redirect_judge) */
	void (*judge_badssl)(const CheckBadssl *test, CheckResult *result);
	/* A name looked up as a game would, where the DNS rules apply (the PS3's libnet, the Vita's
	 * sceNetResolver); NULL on a console whose test doesn't look them up */
	void (*lookup)(const char *name, CheckLookup *answer);
	/* 1 once the run was cancelled */
	int (*stopped)(void);
	/* A result that leaves the rest untested (the Vita's certificate checks that couldn't be turned
	 * back on); NULL when none does */
	int (*policy_failed)(const CheckResult *result);
	/* A finished check, for the console's log; NULL for none */
	void (*log)(const char *what, const CheckResult *result);
	/* The lock the service is read under, and a clock in milliseconds */
	void (*lock)(void);
	void (*unlock)(void);
	uint64_t (*now_ms)(void);
} CheckBackend;

/* A list of "host target" rules (the redirects, the DNS rules) through read, the console's file read
 * as vitals' own reader takes it, with the parser vitals applies them with: at most max, and none
 * when the list can't be read to its end, as vitals applies none then. A console's load */
unsigned check_run_read_rules(VitalsRedirectListRead read, CheckRedirect *list, unsigned max);

/* The whole run, into service (cleared by the caller, started set), with what stopped it early in
 * notice; complete and interrupted are set when it ends */
void check_run(const CheckBackend *backend, CheckService *service, char *notice, size_t notice_size);

#endif
