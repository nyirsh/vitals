#ifndef VITALS_VITA_CHECK_MODEL_H
#define VITALS_VITA_CHECK_MODEL_H

#include "model.h"

/* The Vita's judgements of the connection test's requests (check_model.c), for sceHttp's and sceSsl's
 * errors; what every console shares is in model.h */

/* TLS 1.0 or 1.1 refused by vitals itself, which the tile shows as a deliberate block */
int check_expected_legacy_block(unsigned version, const CheckResult *result);
/* A protocol tile's TLS failure that may hide a trust failure, worth a retry without certificate
 * checks */
int check_should_retry_unverified(unsigned test, const CheckResult *result);
/* A protocol endpoint's answer: whether it names the protocol the tile tests */
void check_protocol_response(unsigned version, const char *body, size_t size, CheckResult *result);
void check_record_retry(CheckResult *result, const CheckResult *retry);
/* Whether a loaded module is vitals' libhttp, from vitals' folder */
int check_http_module_active(const char *name, const char *path, unsigned state);
/* The same for vitals-ssl: SceLibSsl started from ux0:data/vitals/system (the Options' tls.off
 * keeps Sony's) */
int check_ssl_module_active(const char *name, const char *path, unsigned state);
int check_protocol_body(unsigned version, const char *body, size_t size);
/* sceHttp's error with sceSsl's error and detail, in words */
const char *check_error_name(int error, int ssl_error, unsigned detail);
/* Judges a finished badssl.com request (made with certificate checks on, any final HTTP status
 * accepted) against what the case expects: a refusal passes only when no response came and the
 * host was reachable */
void check_badssl_judge(const CheckBadssl *test, CheckResult *result);

#endif
