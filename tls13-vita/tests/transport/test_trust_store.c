#define _POSIX_C_SOURCE 200809L
#include <vita_mock.h>
#include "provider.h"
#include "ca_file.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

VitalsProviderGlobal g_vitals_http;

static void require_clean(void) {
    assert(!g_vitals_http.ca_index_initialized);
    assert(!g_vitals_http.crypto_initialized);
}

int main(int argc, char **argv) {
    char temporary[] = "/tmp/vitals-ca-XXXXXX";
    int descriptor;
    size_t count = 0;
    assert(argc == 2);
    mock_ca_file = argv[1];
    mock_ca_namespace_error = 1;
    assert(vitals_trust_store_init() != 0);
    require_clean();
    mock_ca_namespace_error = 0;
    mock_ca_namespace_unterminated = 1;
    assert(vitals_trust_store_init() != 0);
    require_clean();
    mock_ca_namespace_unterminated = 0;
    assert(vitals_trust_store_init() == 0);
    {
        /* Every self-signed root of the bundle must be found again through the index */
        mbedtls_x509_crt all;
        mbedtls_x509_crt_init(&all);
        assert(vitals_load_ca_file(&all, argv[1]) == 0);
        for (const mbedtls_x509_crt *root = &all; root != NULL; root = root->next) {
            mbedtls_x509_crt *candidates = (mbedtls_x509_crt *)0x1;
            int found = 0;
            if (root->raw.p == NULL || root->issuer_raw.len != root->subject_raw.len ||
                memcmp(root->issuer_raw.p, root->subject_raw.p, root->subject_raw.len) != 0) continue;
            ++count;
            assert(vitals_ca_index_find(&g_vitals_http.ca_index, root, &candidates) == 0);
            for (const mbedtls_x509_crt *c = candidates; c != NULL; c = c->next) {
                if (c->raw.len == root->raw.len && memcmp(c->raw.p, root->raw.p, root->raw.len) == 0) found = 1;
            }
            assert(found);
            mbedtls_x509_crt_free(candidates);
            free(candidates);
        }
        mbedtls_x509_crt_free(&all);
        assert(count != 0);
        assert(g_vitals_http.ca_index.count >= count);
    }
    {
        mbedtls_x509_crt unknown;
        mbedtls_x509_crt *candidates = (mbedtls_x509_crt *)0x1;
        mbedtls_x509_crt_init(&unknown);
        assert(vitals_ca_index_find(&g_vitals_http.ca_index, &unknown, &candidates) == 0);
        assert(candidates == NULL);
    }
    vitals_trust_store_free();
    require_clean();

    mock_entropy_calls = 0;
    mock_entropy_fail_after = 0;
    assert(vitals_trust_store_init() != 0);
    require_clean();
    mock_entropy_fail_after = -1;
    mock_clock_failure = 1;
    assert(vitals_trust_store_init() != 0);
    require_clean();
    mock_clock_failure = 0;

    descriptor = mkstemp(temporary);
    assert(descriptor >= 0);
    mock_ca_file = temporary;
    assert(vitals_trust_store_init() != 0);
    require_clean();
    assert(write(descriptor, "malformed", 9) == 9);
    assert(vitals_trust_store_init() != 0);
    require_clean();
    assert(ftruncate(descriptor, 0) == 0 && lseek(descriptor, 0, SEEK_SET) == 0);
    assert(write(descriptor, "malformed\0certificate", 21) == 21);
    assert(vitals_trust_store_init() != 0);
    require_clean();
    assert(ftruncate(descriptor, 4 * 1024 * 1024 + 1) == 0);
    assert(vitals_trust_store_init() != 0);
    require_clean();
    close(descriptor);
    unlink(temporary);
    assert(vitals_trust_store_init() != 0);
    require_clean();

    mock_ca_file = argv[1];
    assert(vitals_trust_store_init() == 0);
    vitals_trust_store_free();
    require_clean();
    printf("trust store: %zu roots; entropy/RTC/empty/NUL/oversize/missing failures and reinit PASS\n", count);
    return 0;
}
