#include "check_model.h"
#include <assert.h>
#include <string.h>

static CheckResult outcome(int error, int ssl_error, int http_code) {
    CheckResult r = {0};
    r.state = http_code ? CHECK_PASS : CHECK_FAIL;
    r.error = error;
    r.ssl_error = ssl_error;
    r.http_code = http_code;
    return r;
}

int main(void) {
    unsigned good = 0, bad = 0;
    for (unsigned i = 0; i < CHECK_BADSSL_COUNT; ++i) {
        const CheckBadssl *test = check_badssl(i);
        assert(test != NULL && test->host != NULL && test->label != NULL);
        assert(strstr(test->host, "badssl.com") != NULL);
        good += !test->refuse;
        bad += test->refuse != 0;
    }
    assert(check_badssl(CHECK_BADSSL_COUNT) == NULL);
    assert(good == 5 && bad == 7);
    /* The battery has no PlayStation endpoint any more */
    for (unsigned i = 0; i < CHECK_TEST_COUNT; ++i) assert(strstr(check_endpoint(i), "playstation") == NULL);
    assert(check_endpoint(CHECK_TEST_COUNT) == NULL);

    /* vitals' libhttp is the one loaded when SceLibHttp has started from ux0:data/vitals/system,
     * named with or without the slash; not from an earlier version's place, nor Sony's */
    assert(check_http_module_active("SceLibHttp", "ux0:data/vitals/system/libhttp.suprx", 6));
    assert(check_http_module_active("SceLibHttp", "ux0:/data/vitals/system/libhttp.suprx", 6));
    assert(!check_http_module_active("SceLibHttp", "ux0:data/vitals/system/libhttp.suprx", 5));
    assert(!check_http_module_active("SceLibSsl", "ux0:data/vitals/system/libhttp.suprx", 6));
    assert(!check_http_module_active("SceLibHttp", "vs0:/data/external/vitals/libhttp.suprx", 6));
    assert(!check_http_module_active("SceLibHttp", "vs0:sys/external/libhttp.suprx", 6));
    assert(!check_http_module_active("SceLibHttp", "uma0:data/vitals/system/libhttp.suprx", 6));
    assert(!check_http_module_active("SceLibHttp", NULL, 6));

    const CheckBadssl *valid = check_badssl(0), *expired = check_badssl(5);
    assert(!valid->refuse && strcmp(expired->host, "expired.badssl.com") == 0 && expired->refuse);

    /* A host that must load keeps what the request gave */
    CheckResult r = outcome(0, 0, 200);
    check_badssl_judge(valid, &r);
    assert(r.state == CHECK_PASS && strcmp(r.message, "Loaded (HTTP 200)") == 0);
    r = outcome((int)0x80431075, (int)0x80435060, 0);
    check_badssl_judge(valid, &r);
    assert(r.state == CHECK_FAIL);

    /* A host that must be refused: a certificate or handshake refusal passes */
    r = outcome((int)0x80431075, (int)0x80435060, 0);
    r.ssl_detail = 0x08;
    check_badssl_judge(expired, &r);
    assert(r.state == CHECK_PASS && strcmp(r.message, "Refused: Certificate expired") == 0);
    r = outcome((int)0x80431075, (int)0x80435061, 0);
    check_badssl_judge(expired, &r);
    assert(r.state == CHECK_PASS && strcmp(r.message, "Refused: TLS handshake failed") == 0);
    /* Any response fails it */
    r = outcome(0, 0, 200);
    check_badssl_judge(expired, &r);
    assert(r.state == CHECK_FAIL && strcmp(r.message, "Loaded (HTTP 200), should be refused") == 0);
    r = outcome(0, 0, 404);
    check_badssl_judge(expired, &r);
    assert(r.state == CHECK_FAIL);
    /* An unreachable host proves nothing */
    r = outcome((int)0x80436007, 0, 0);
    check_badssl_judge(expired, &r);
    assert(r.state == CHECK_FAIL && strcmp(r.message, "Inconclusive: DNS lookup failed") == 0);
    r = outcome((int)0x80431068, 0, 0);
    check_badssl_judge(expired, &r);
    assert(r.state == CHECK_FAIL && strncmp(r.message, "Inconclusive", 12) == 0);
    r = outcome((int)0x80431063, 0, 0);
    check_badssl_judge(expired, &r);
    assert(r.state == CHECK_FAIL && strncmp(r.message, "Inconclusive", 12) == 0);
    /* vitals-ssl is the loaded libssl when SceLibSsl started from ux0:data/vitals/system */
    assert(check_ssl_module_active("SceLibSsl", "ux0:data/vitals/system/libssl.suprx", 6));
    assert(!check_ssl_module_active("SceLibSsl", "vs0:sys/external/libssl.suprx", 6));
    assert(!check_ssl_module_active("SceLibHttp", "ux0:data/vitals/system/libssl.suprx", 6));
    assert(!check_ssl_module_active("SceLibSsl", "ux0:data/vitals/system/libssl.suprx", 5));

    /* TLS 1.0 and 1.1 refused by vitals: with vitals-http, by its detail */
    r = outcome((int)0x80431075, (int)0x80435061, 0);
    r.vitals_active = r.vitals_tls = 1;
    r.ssl_detail = 0xffff8880u;
    assert(check_expected_legacy_block(0, &r) && check_expected_legacy_block(1, &r));
    assert(!check_expected_legacy_block(2, &r));
    assert(!check_should_retry_unverified(0, &r));
    /* With Sony's libhttp on vitals-ssl there's no detail: the retry with checks off failing the
     * same way says so; before the retry it isn't decided, so the retry runs */
    r = outcome((int)0x80431075, (int)0x80435061, 0);
    r.vitals_tls = 1;
    assert(!check_expected_legacy_block(0, &r) && check_should_retry_unverified(0, &r));
    r.retry = (CheckRetry){.attempted = 1, .verification_disabled = 1, .error = (int)0x80431075,
                           .ssl_error = (int)0x80435061};
    assert(check_expected_legacy_block(0, &r) && check_expected_legacy_block(1, &r));
    char detail[96];
    check_protocol_detail(1, &r, detail, sizeof(detail));
    assert(strcmp(detail, "Disabled by vitals (secure)") == 0);
    assert(check_protocol_display(1, &r, 1).style == CHECK_PASS && strcmp(check_protocol_display(1, &r, 1).label, "Blocked") == 0);
    /* Not when the retry couldn't turn checks off, connected, or hit a certificate */
    r.retry.verification_disabled = 0;
    assert(!check_expected_legacy_block(0, &r));
    r.retry.verification_disabled = 1;
    r.retry.protocol_confirmed = 1;
    assert(!check_expected_legacy_block(0, &r));
    r.retry.protocol_confirmed = 0;
    r.retry.ssl_error = (int)0x80435060;
    assert(!check_expected_legacy_block(0, &r));
    /* Nor with Sony's libssl: that's Sony's TLS failing, not vitals blocking */
    r.retry.ssl_error = (int)0x80435061;
    r.vitals_tls = 0;
    assert(!check_expected_legacy_block(0, &r));

    /* Nor does a run whose certificate checks couldn't be restored */
    r = outcome((int)0x80431075, (int)0x80435060, 0);
    r.restore_error = -1;
    check_badssl_judge(expired, &r);
    assert(r.state == CHECK_FAIL && strcmp(r.message, "Inconclusive: Could not restore certificate checks") == 0);
    /* Neither a response nor an error: nothing refused it */
    r = outcome(0, 0, 0);
    check_badssl_judge(expired, &r);
    assert(r.state == CHECK_FAIL && strcmp(r.message, "Not refused") == 0);
    return 0;
}
