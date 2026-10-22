#define _GNU_SOURCE
#include "vitals/browser_abi.h"
#include "vitals/sony_abi.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

static void expect_diagnostic(size_t offset, int32_t value) { (void)offset; (void)value; }
static void expect_diagnostic_quiet(void) {}

static void expect_legacy(size_t offset, int32_t value) { expect_diagnostic(offset, value); }
static void expect_callback_policy(int32_t value) { (void)value; }
static void expect_quiet(void) { expect_diagnostic_quiet(); }

static const void *accepted_callback;
static const void *accepted_userdata;
static unsigned int validator_calls;

static int validate_default_callback(const void *callback, const void *userdata) {
    ++validator_calls;
    return callback == accepted_callback && userdata == accepted_userdata;
}

int main(void) {
    unsigned char *arena = mmap((void *)(uintptr_t)0x23000000, 65536,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    unsigned char *connection = arena;
    unsigned char *easy = arena + 4096;
    char *host = (char *)arena + 49152;
    char *cipher = host + 1024;
    char *ca_file = cipher + 2048;
    VitalsBrowserOptions options;
    const size_t legacy_offsets[] = {816, 820, 824, 828, 896, 920, 924};
    size_t i;

    assert(arena != MAP_FAILED);
    strcpy(host, "example.test");
    strcpy(cipher, "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384");
    vitals_write_u32(connection, 0, (uint32_t)(uintptr_t)easy);
    vitals_write_u32(connection, 136, (uint32_t)(uintptr_t)host);
    vitals_write_u32(connection, 320, 99);
    vitals_write_u32(connection, 324, 101);
    vitals_write_u32(easy, 636, 1);
    easy[644] = 1;
    easy[645] = 1;
    assert(vitals_browser_read_options(connection, 0, "known default",
        validate_default_callback, &options) == 0);
    assert(options.easy == easy && options.socket == 99 && options.hostname == host);
    assert(options.verify_peer && options.verify_host && options.tls12_suites == 15);
    assert(validator_calls == 0);
    assert(vitals_browser_read_options(connection, 1, "known default",
        validate_default_callback, &options) == 0);
    assert(options.socket == 101);
    assert(vitals_browser_read_options(connection, 2, "known default",
        validate_default_callback, &options) < 0);
    assert(vitals_browser_read_options(NULL, 0, "known default",
        validate_default_callback, &options) < 0);
    expect_quiet();
    for (i = 0; i < sizeof(legacy_offsets)/sizeof(legacy_offsets[0]); ++i) {
        vitals_write_u32(easy, legacy_offsets[i], UINT32_C(0xdeadbeef));
        assert(vitals_browser_read_options(connection, 0, "known default",
            validate_default_callback, &options) == 1);
        expect_legacy(legacy_offsets[i], 1);
        assert(vitals_read_u32(easy, legacy_offsets[i]) == UINT32_C(0xdeadbeef));
        vitals_write_u32(easy, legacy_offsets[i], 0);
    }
    easy[689] = 1;
    assert(vitals_browser_read_options(connection, 0, "known default",
        validate_default_callback, &options) == 1);
    expect_legacy(689, 1);
    easy[689] = 0;
    vitals_write_u32(easy, 636, 6);
    assert(vitals_browser_read_options(connection, 0, "known default",
        validate_default_callback, &options) == 1);
    expect_legacy(636, 6);
    vitals_write_u32(easy, 636, UINT32_MAX);
    vitals_write_u32(easy, 680, 1);
    assert(vitals_browser_read_options(connection, 0, "known default",
        validate_default_callback, &options) == 1);
    expect_legacy(636, -1);
    vitals_write_u32(easy, 680, 0);
    vitals_write_u32(easy, 636, 1);
    accepted_callback = easy + 2048;
    accepted_userdata = easy + 3072;
    vitals_write_u32(easy, VITALS_CURL_CTX_CALLBACK_OFFSET,
        (uint32_t)(uintptr_t)accepted_callback);
    vitals_write_u32(easy, VITALS_CURL_CTX_CALLBACK_DATA_OFFSET,
        (uint32_t)(uintptr_t)accepted_userdata);
    assert(vitals_browser_read_options(connection, 0, "known default",
        validate_default_callback, &options) == 0);
    assert(validator_calls == 1);
    easy[VITALS_CURL_VERIFY_PEER_OFFSET] = 0;
    assert(vitals_browser_read_options(connection, 0, "known default",
        validate_default_callback, &options) == 1);
    expect_legacy(VITALS_CURL_CTX_CALLBACK_OFFSET, 1);
    expect_callback_policy(4);
    easy[VITALS_CURL_VERIFY_PEER_OFFSET] = 1;
    easy[VITALS_CURL_VERIFY_HOST_OFFSET] = 0;
    assert(vitals_browser_read_options(connection, 0, "known default",
        validate_default_callback, &options) == 1);
    expect_legacy(VITALS_CURL_CTX_CALLBACK_OFFSET, 1);
    expect_callback_policy(8);
    easy[VITALS_CURL_VERIFY_HOST_OFFSET] = 1;
    strcpy(ca_file, "/custom/ca.pem");
    vitals_write_u32(easy, VITALS_CURL_CAFILE_OFFSET, (uint32_t)(uintptr_t)ca_file);
    assert(vitals_browser_read_options(connection, 0, "known default",
        validate_default_callback, &options) == 1);
    expect_legacy(VITALS_CURL_CTX_CALLBACK_OFFSET, 1);
    expect_callback_policy(16);
    vitals_write_u32(easy, VITALS_CURL_CAFILE_OFFSET, 0);
    vitals_write_u32(easy, VITALS_CURL_CTX_CALLBACK_DATA_OFFSET, 0);
    assert(vitals_browser_read_options(connection, 0, "known default",
        validate_default_callback, &options) == 1);
    expect_legacy(VITALS_CURL_CTX_CALLBACK_OFFSET, 1);
    expect_callback_policy(1);
    assert(validator_calls == 1);
    vitals_write_u32(easy, VITALS_CURL_CTX_CALLBACK_DATA_OFFSET,
        (uint32_t)(uintptr_t)accepted_userdata);
    vitals_write_u32(easy, VITALS_CURL_CTX_CALLBACK_OFFSET,
        (uint32_t)(uintptr_t)accepted_callback + 2);
    assert(vitals_browser_read_options(connection, 0, "known default",
        validate_default_callback, &options) == 1);
    expect_legacy(VITALS_CURL_CTX_CALLBACK_OFFSET, 1);
    assert(validator_calls == 2);
    vitals_write_u32(easy, VITALS_CURL_CTX_CALLBACK_OFFSET,
        (uint32_t)(uintptr_t)accepted_callback);
    assert(vitals_browser_read_options(connection, 0, "known default", NULL, &options) == 1);
    expect_legacy(VITALS_CURL_CTX_CALLBACK_OFFSET, 1);
    expect_callback_policy(2);
    assert(validator_calls == 2);
    vitals_write_u32(easy, VITALS_CURL_CTX_CALLBACK_OFFSET, 0);
    assert(vitals_browser_read_options(connection, 0, "known default",
        validate_default_callback, &options) == 1);
    expect_legacy(VITALS_CURL_CTX_CALLBACK_DATA_OFFSET, 1);
    assert(validator_calls == 2);
    vitals_write_u32(easy, VITALS_CURL_CTX_CALLBACK_DATA_OFFSET, 0);
    vitals_write_u32(easy, 904, (uint32_t)(uintptr_t)cipher);
    assert(vitals_browser_read_options(connection, 0, "known default",
        validate_default_callback, &options) == 0);
    assert(options.tls12_suites == (VITALS_BROWSER_RSA_GCM128 | VITALS_BROWSER_ECDSA_GCM256));
    strcpy(cipher, "known default");
    assert(vitals_browser_read_options(connection, 0, "known default",
        validate_default_callback, &options) == 0);
    assert(options.tls12_suites == (VITALS_BROWSER_RSA_GCM128 | VITALS_BROWSER_ECDSA_GCM128));
    expect_quiet();
    strcpy(cipher, "ECDHE-RSA-AES128-GCM-SHA256:!ECDHE-RSA");
    assert(vitals_browser_read_options(connection, 0, "known default",
        validate_default_callback, &options) == 1);
    expect_legacy(904, 1);
    memset(cipher, 'x', 1024);
    assert(vitals_browser_read_options(connection, 0, "known default",
        validate_default_callback, &options) < 0);
    expect_quiet();
    assert(munmap(arena, 65536) == 0);
    puts("browser configuration contract: PASS");
    return 0;
}
