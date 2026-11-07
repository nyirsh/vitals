#ifndef VITA_TLS_CHECK_MODEL_H
#define VITA_TLS_CHECK_MODEL_H
#include <stddef.h>
#include <stdint.h>
#define CHECK_BODY_MAX (96u * 1024u)
#define CHECK_LIST_MAX 64
#define CHECK_NAME_MAX 96
enum CheckTest
{
    CHECK_REPORT = 4,
    CHECK_TEST_COUNT
};

enum CheckState
{
    CHECK_WAIT,
    CHECK_RUNNING,
    CHECK_PASS,
    CHECK_FAIL,
    CHECK_INFO,
    CHECK_WARNING
};
typedef struct
{
    enum CheckState style;
    const char *label, *qualifier;
    enum CheckState detail_style;
} CheckProtocolDisplay;
typedef struct
{
    int attempted, verification_disabled, protocol_confirmed;
    int http_code, error, ssl_error, restore_error;
    unsigned ssl_detail, elapsed_ms;
} CheckRetry;
typedef struct
{
    enum CheckState state;
    int http_code, error, ssl_error;
    unsigned ssl_detail, elapsed_ms;
    int protocol_confirmed, restore_error, verification_disabled;
    int vitals_active; /* Runtime module detection at the start of this attempt */
    unsigned attempts; /* Requests made, timeouts retried included */
    CheckRetry retry;
    char message[128];
} CheckResult;
typedef struct
{
    unsigned id;
    char name[CHECK_NAME_MAX];
} CheckNamed;
typedef struct
{
    int valid;
    CheckNamed version, cipher, group, signature;
    CheckNamed ciphers[CHECK_LIST_MAX], groups[CHECK_LIST_MAX], extensions[CHECK_LIST_MAX];
    unsigned cipher_count, group_count, extension_count;
    char ja3[65], ja4[129], alpn[96];
} CheckHandshake;
/* Host redirects as ux0:data/vitals/redirects.txt lists them, at most as many as vitals applies */
#define CHECK_REDIRECT_MAX 32
#define CHECK_HOST_MAX 254
typedef struct
{
    char from[CHECK_HOST_MAX], to[CHECK_HOST_MAX];
    CheckResult result;
} CheckRedirect;
/* The badssl.com battery: hosts that must load, and hosts whose certificate or ciphers must be
 * refused */
#define CHECK_BADSSL_COUNT 12
typedef struct
{
    const char *host; /* With its port when not 443 */
    const char *label;
    int refuse;
} CheckBadssl;
typedef struct
{
    CheckResult protocols[4], connection;
    CheckResult badssl[CHECK_BADSSL_COUNT];
    CheckRedirect redirects[CHECK_REDIRECT_MAX];
    unsigned redirect_count;
    CheckHandshake handshake;
    int started, complete;
    /* The run was cancelled (Triangle, or leaving the test) before it finished */
    int interrupted;
    int vitals_enabled; /* -1 before runtime detection, then 0 or 1 */
    /* The run's log: 0 not saved, 1 saved (at report), -1 the last attempt failed */
    int report_saved;
    char report[160];
} CheckService;
const char *check_endpoint(unsigned test);
CheckProtocolDisplay check_protocol_display(unsigned version, const CheckResult *result);
void check_protocol_detail(unsigned version, const CheckResult *result, char *text, size_t capacity);
int check_expected_legacy_block(unsigned version, const CheckResult *result);
int check_should_retry_unverified(unsigned test, const CheckResult *result);
void check_protocol_response(unsigned version, const char *body, size_t size, CheckResult *result);
void check_record_retry(CheckResult *result, const CheckResult *retry);
int check_http_module_active(const char *name, const char *path, unsigned state);
int check_protocol_body(unsigned version, const char *body, size_t size);
int check_parse_browserleaks(const char *body, size_t size, CheckHandshake *out);
const char *check_error_name(int error, int ssl_error, unsigned detail);
const CheckBadssl *check_badssl(unsigned index);
/* Judges a finished badssl.com request (made with certificate checks on, any final HTTP status
 * accepted) against what the case expects: a refusal passes only when no response came and the
 * host was reachable */
void check_badssl_judge(const CheckBadssl *test, CheckResult *result);
#endif
