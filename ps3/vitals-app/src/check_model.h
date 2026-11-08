#ifndef VITALS_PS3_CHECK_MODEL_H
#define VITALS_PS3_CHECK_MODEL_H

#include "model.h"

/* The PS3's judgements of the connection test's requests (check_model.c), for libhttp's errors; what
 * every console shares is in model.h */

/* A finished request to a protocol endpoint: which state the tile shows */
void check_protocol_judge(unsigned version, CheckResult *result);
/* A finished badssl.com request against what the case expects: a refusal passes only when the
 * host was reached and the TLS or its certificate was refused */
void check_badssl_judge(const CheckBadssl *test, CheckResult *result);
/* A finished request to a redirect's old host: any final HTTP status passes, as on the Vita, since
 * only the new server's reachability through vitals is tested */
/* A failed request in words, after prefix: its error's name, with its code unless a certificate's
 * reason says enough */
void check_request_failure(CheckResult *result, const char *prefix);
/* A name's lookup through libnet: found, else the resolver's h_errno, and the IPv4 addresses */
#define CHECK_DNS_ADDRESSES 8
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

#endif
