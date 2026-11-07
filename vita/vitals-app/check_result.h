#ifndef VITALS_VITA_CHECK_RESULT_H
#define VITALS_VITA_CHECK_RESULT_H

/* What a Vita request records besides the shared CheckResult's fields (shared/app/model.h): sceSsl's
 * error and detail, whether the TLS endpoint's answer confirmed the protocol, whether certificate
 * checks were turned off for it (and couldn't be turned back on: restore_error), whether vitals'
 * libhttp was loaded when it started, and the protocol tiles' retry without certificate checks */
typedef struct {
    int attempted, verification_disabled, protocol_confirmed;
    int http_code, error, ssl_error, restore_error;
    unsigned ssl_detail, elapsed_ms;
} CheckRetry;

#define CHECK_RESULT_CONSOLE \
    int ssl_error; \
    unsigned ssl_detail; \
    int protocol_confirmed, restore_error, verification_disabled; \
    int vitals_active; \
    CheckRetry retry;

#endif
