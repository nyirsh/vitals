/* The connection test's judgements on the Vita, for sceHttp's and sceSsl's errors: 0x80431075 a TLS
 * failure, whose sceSsl error and detail say which, 0x80431068 a timeout, 0x804360xx the resolver. What's
 * the same on every console (the endpoints, the badssl.com battery, the TLS report's parser) is
 * shared/app/model.c */

#include "check_model.h"
#include "vitals/path.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int certificate_error(const CheckResult *r) {
    return (uint32_t)r->error == 0x80431075 && (uint32_t)r->ssl_error == 0x80435060;
}
static int unreachable(const CheckResult *r) {
    return (uint32_t)r->error == 0x80431068 || (uint32_t)r->error == 0x80431063 ||
           ((uint32_t)r->error >= 0x80436000 && (uint32_t)r->error <= 0x804360ff);
}
void check_badssl_judge(const CheckBadssl *test, CheckResult *r) {
    if (!test->refuse)
        return;
    if (r->http_code != 0) {
        r->state = CHECK_FAIL;
        snprintf(r->message, sizeof(r->message), "Loaded (HTTP %d), should be refused", r->http_code);
    } else if (r->error >= 0) {
        r->state = CHECK_FAIL;
        snprintf(r->message, sizeof(r->message), "Not refused");
    } else if (unreachable(r) || r->restore_error) {
        r->state = CHECK_FAIL;
        snprintf(r->message, sizeof(r->message), "Inconclusive: %s",
                 check_error_name(r->error, r->ssl_error, r->ssl_detail));
    } else {
        r->state = CHECK_PASS;
        snprintf(r->message, sizeof(r->message), "Refused: %s",
                 check_error_name(r->error, r->ssl_error, r->ssl_detail));
    }
}
int check_expected_legacy_block(unsigned version, const CheckResult *r) {
    /* vitals blocks TLS 1.0 and 1.1, and reports this through sceHttpsGetSslError's detail value
     * Only that case is shown as a deliberate block (green tick); a missing detail, or a network
     * or certificate failure, is not, even when vitals is loaded */
    int refused = version < 2 && r->state == CHECK_FAIL && !r->http_code && !r->protocol_confirmed &&
                  !r->restore_error && !r->verification_disabled && !r->retry.protocol_confirmed &&
                  !r->retry.http_code && (uint32_t)r->retry.ssl_error != 0x80435060 &&
                  (uint32_t)r->error == 0x80431075 && (uint32_t)r->ssl_error == 0x80435061;
    /* vitals-http says why: Mbed TLS's protocol version error, in the detail */
    if (refused && r->vitals_active == 1)
        return r->ssl_detail == 0xffff8880u || r->ssl_detail == 0xffff9180u;
    /* Sony's libhttp on vitals-ssl (the Options' http.off) gives no detail: the handshake failing
     * again with certificate checks off says it's the protocol, which vitals-ssl never offers */
    return refused && r->vitals_tls == 1 && r->vitals_active != 1 && r->ssl_detail == 0 && r->retry.attempted &&
           r->retry.verification_disabled && (uint32_t)r->retry.error == 0x80431075 &&
           (uint32_t)r->retry.ssl_error == 0x80435061;
}
CheckProtocolDisplay check_protocol_display(unsigned version, const CheckResult *r, int vitals_enabled) {
    (void)vitals_enabled;
    if (check_expected_legacy_block(version, r))
        return (CheckProtocolDisplay){CHECK_PASS, "Blocked", "secure", CHECK_PASS};
    enum CheckState state = r->state;
    CheckProtocolDisplay display = {state, "Waiting", NULL, state};
    switch (state) {
    case CHECK_PASS: display.label = "Connected"; display.qualifier = "secure"; break;
    case CHECK_FAIL: display.label = "Failed"; break;
    case CHECK_RUNNING: display.label = "Checking..."; break;
    case CHECK_INFO: display.label = "Not tested"; break;
    default: break;
    }
    if (version < 2 && state == CHECK_PASS) {
        display.style = CHECK_WARNING;
        display.detail_style = CHECK_FAIL;
        display.label = "Insecure";
        display.qualifier = "vulnerable";
    }
    if (state == CHECK_FAIL || state == CHECK_WARNING) {
        display.qualifier = NULL;
        if (r->restore_error) {
            display.style = display.detail_style = CHECK_FAIL;
            display.label = "Check error";
        } else if (certificate_error(r)) {
            display.style = display.detail_style = CHECK_WARNING;
            display.label = "Cert error";
        } else if (r->retry.protocol_confirmed) {
            display.style = display.detail_style = CHECK_WARNING;
            display.label = "Unverified";
        } else if (unreachable(r)) {
            display.style = display.detail_style = CHECK_INFO;
            display.label = "Unreachable";
        } else if ((uint32_t)r->error == 0x80431075) {
            display.style = display.detail_style = CHECK_FAIL;
            display.label = "TLS error";
        }
    }
    return display;
}
void check_protocol_detail(unsigned version, const CheckResult *result, char *text, size_t capacity) {
    if (check_expected_legacy_block(version, result))
        snprintf(text, capacity, "Disabled by vitals (secure)");
    else if (result->restore_error)
        snprintf(text, capacity, "Could not restore certificate checks");
    else if (result->retry.attempted && !result->retry.verification_disabled)
        snprintf(text, capacity, "%s; cert retry unavailable", certificate_error(result)
                 ? "Certificate rejected" : "TLS failed");
    else if (result->retry.protocol_confirmed)
        snprintf(text, capacity, "%s", certificate_error(result)
                 ? "TLS works; certificate rejected" : "Connected with certificate checks off");
    else if (certificate_error(result))
        snprintf(text, capacity, "%s%s", check_error_name(result->error, result->ssl_error,
                 result->ssl_detail), result->retry.attempted ? "; retry failed" : "");
    else if (version < 2 && result->state == CHECK_PASS)
        snprintf(text, capacity, "Connected to TLS 1.%u endpoint (vulnerable)", version);
    else
        snprintf(text, capacity, "%s", result->message[0] ? result->message : "Waiting");
}
void check_request_codes(const CheckResult *r, char *text, size_t capacity) {
    if (r->error || r->ssl_error)
        snprintf(text, capacity, "0x%08X / 0x%08X", (unsigned)r->error, (unsigned)r->ssl_error);
    else
        snprintf(text, capacity, "%s", r->state == CHECK_PASS ? "OK" : "-");
}
unsigned check_request_ms(const CheckResult *r) {
    /* The retry without certificate checks is part of the same tile's test */
    return r->elapsed_ms + r->retry.elapsed_ms;
}
int check_should_retry_unverified(unsigned test, const CheckResult *r) {
    /* A TLS failure may hide a trust failure in the native stack
     * Never retry network/HTTP/body failures, cancellation or the detailed TLS report */
    return test < 4 && r->state == CHECK_FAIL && r->http_code == 0 &&
           (uint32_t)r->error == 0x80431075 && !r->restore_error && !r->retry.attempted &&
           !check_expected_legacy_block(test, r);
}
void check_protocol_response(unsigned version, const char *body, size_t size, CheckResult *r) {
    if (version >= 4 || r->state != CHECK_PASS)
        return;
    if (check_protocol_body(version, body, size)) {
        r->protocol_confirmed = 1;
        snprintf(r->message, sizeof(r->message), "Connected to TLS 1.%u endpoint", version);
    } else {
        r->state = CHECK_FAIL;
        r->error = -1;
        snprintf(r->message, sizeof(r->message), "Unexpected response; protocol not confirmed");
    }
}
void check_record_retry(CheckResult *r, const CheckResult *retry) {
    r->retry = (CheckRetry){.attempted = 1, .verification_disabled = retry->verification_disabled,
        .protocol_confirmed = retry->verification_disabled && retry->protocol_confirmed,
        .http_code = retry->http_code, .error = retry->error, .ssl_error = retry->ssl_error,
        .restore_error = retry->restore_error, .ssl_detail = retry->ssl_detail,
        .elapsed_ms = retry->elapsed_ms};
    r->restore_error = retry->restore_error;
    if (r->retry.protocol_confirmed && !retry->restore_error)
        r->state = CHECK_WARNING;
    /* Keep the verified attempt's errors, HTTP result and message intact */
}
/* "dev:x" and "dev:/x" name the same file */
static int same_file(const char *a, const char *b) {
    const char *colon_a = strchr(a, ':'), *colon_b = strchr(b, ':');
    if (colon_a == NULL || colon_b == NULL || colon_a - a != colon_b - b || strncmp(a, b, (size_t)(colon_a - a)) != 0)
        return 0;
    a = colon_a + 1 + (colon_a[1] == '/');
    b = colon_b + 1 + (colon_b[1] == '/');
    return strcmp(a, b) == 0;
}
int check_http_module_active(const char *name, const char *path, unsigned state) {
    /* vitals-http keeps libhttp's name; the kernel plugin's swap is what loads it from vitals'
     * folder (ux0:data/vitals/system). Sony reports STARTED=6; presence alone does not establish
     * activation */
    static const char module[] = "SceLibHttp";
    if (name == NULL || path == NULL || state != 6 || strncmp(name, module, sizeof(module)) != 0)
        return 0;
    return same_file(path, VITALS_LIBHTTP_PATH);
}
int check_ssl_module_active(const char *name, const char *path, unsigned state) {
    static const char module[] = "SceLibSsl";
    if (name == NULL || path == NULL || state != 6 || strncmp(name, module, sizeof(module)) != 0)
        return 0;
    return same_file(path, VITALS_LIBSSL_PATH);
}
int check_protocol_body(unsigned version, const char *b, size_t n) {
    char expected[16];
    if (b == NULL || version > 3)
        return 0;
    while (n && isspace((unsigned char)b[n - 1]))
        --n;
    snprintf(expected, sizeof(expected), "TLS 1.%u", version);
    return n == strlen(expected) && memcmp(b, expected, n) == 0;
}
const char *check_error_name(int e, int ssl, unsigned detail) {
    /* Detail bits alone are not a certificate diagnosis (I/O/abort can carry them too) */
    if ((uint32_t)e == 0x80431075 && (uint32_t)ssl == 0x80435060) {
        if (detail & 0x08) return "Certificate expired";
        if (detail & 0x10) return "Certificate not yet valid";
        if (detail & 0x04) return "Certificate hostname mismatch";
        if (detail & 0x20) return "Untrusted certificate chain";
        return "Certificate rejected";
    }
    if ((uint32_t)e == 0x80431075 && (uint32_t)ssl == 0x80435061)
        return "TLS handshake failed";
    if ((uint32_t)e >= 0x80436000 && (uint32_t)e <= 0x804360ff)
        return "DNS lookup failed";
    switch ((uint32_t)e) {
    case 0x80431068:
        return "Request timed out";
    case 0x80431080:
        return "Request cancelled";
    case 0x80431075:
        return "TLS request failed";
    case 0x80431063:
        return "Network failure";
    case 0x8043506b:
        return "Certificate override denied by system";
    default:
        return "Request failed";
    }
}
