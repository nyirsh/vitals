#include "model.h"
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

    const CheckBadssl *valid = check_badssl(0), *expired = check_badssl(5);
    assert(!valid->refuse && strcmp(expired->host, "expired.badssl.com") == 0 && expired->refuse);

    /* A host that must load keeps what the request gave */
    CheckResult r = outcome(0, 0, 200);
    check_badssl_judge(valid, &r);
    assert(r.state == CHECK_PASS);
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
    /* Nor does a run whose certificate checks couldn't be restored */
    r = outcome((int)0x80431075, (int)0x80435060, 0);
    r.restore_error = -1;
    check_badssl_judge(expired, &r);
    assert(r.state == CHECK_FAIL);
    return 0;
}
