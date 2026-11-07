#include "vitals/path.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* A process's request for Sony's browser engine gives the certificate store as that process names
 * it: the same device and folders, then cert/CA_LIST.cer (the kernel passes it to the provider, as
 * vitals' engine loads from ux0:data/vitals/system) */
int main(void) {
    char output[256], short_buffer[4] = "abc";
    const char *requests[] = {
        "vs0:/data/external/webcore/ScePsp2Compat.suprx",
        "vs0:data/external/webcore/ScePsp2Compat.suprx",
        "wb0:/webcore/ScePsp2Compat.suprx",
        "wb0:webcore/ScePsp2Compat.suprx",
        "sd062e8855c978:/webcore/ScePsp2Compat.suprx",
    };
    const char *expected[] = {
        "vs0:/data/external/cert/CA_LIST.cer",
        "vs0:data/external/cert/CA_LIST.cer",
        "wb0:/cert/CA_LIST.cer",
        "wb0:cert/CA_LIST.cer",
        "sd062e8855c978:/cert/CA_LIST.cer",
    };
    for (size_t i = 0; i < sizeof(requests) / sizeof(requests[0]); ++i) {
        assert(vitals_browser_engine_ca_path(requests[i], output, sizeof(output)) == 1);
        assert(strcmp(output, expected[i]) == 0);
    }
    const char *others[] = {NULL, "x", "/webcore/ScePsp2Compat.suprx", ":/webcore/ScePsp2Compat.suprx",
        ":webcore/ScePsp2Compat.suprx", "wb0:/notwebcore/ScePsp2Compat.suprx",
        "wb0:notwebcore/ScePsp2Compat.suprx", "vs0:sys/external/libhttp.suprx",
        "ux0:data/vitals/system/ScePsp2Compat.suprx"};
    for (size_t i = 0; i < sizeof(others) / sizeof(others[0]); ++i)
        assert(vitals_browser_engine_ca_path(others[i], output, sizeof(output)) == 0);
    assert(vitals_browser_engine_ca_path(requests[0], NULL, 0) == 0);
    /* Too small a buffer leaves it as it was */
    assert(vitals_browser_engine_ca_path(requests[0], short_buffer, sizeof(short_buffer)) == 0);
    assert(strcmp(short_buffer, "abc") == 0);
    assert(vitals_browser_engine_ca_path("wb0:/webcore/ScePsp2Compat.suprx", output,
        strlen("wb0:/cert/CA_LIST.cer") + 1) == 1);
    assert(vitals_browser_engine_ca_path("wb0:/webcore/ScePsp2Compat.suprx", output,
        strlen("wb0:/cert/CA_LIST.cer")) == 0);
    puts("browser engine requests: the certificate store in the process's own names PASS");
    return 0;
}
