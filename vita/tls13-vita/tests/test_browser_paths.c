#include "vitals/path.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    char output[256], provider[256], short_buffer[4] = "abc";
    const char *paths[] = {
        "vs0:/data/external/webcore/ScePsp2Compat.suprx",
        "vs0:data/external/webcore/ScePsp2Compat.suprx",
        "wb0:/webcore/ScePsp2Compat.suprx",
        "wb0:webcore/ScePsp2Compat.suprx",
        "opaque:webcore/ScePsp2Compat.suprx"
    };
    const char *expected[] = {
        "vs0:/data/external/vitals/ScePsp2Compat.suprx",
        "vs0:data/external/vitals/ScePsp2Compat.suprx",
        "wb0:/vitals/ScePsp2Compat.suprx",
        "wb0:vitals/ScePsp2Compat.suprx",
        "opaque:vitals/ScePsp2Compat.suprx"
    };
    for (size_t i = 0; i < sizeof(paths)/sizeof(paths[0]); ++i) {
        assert(vitals_browser_replacement_path(paths[i], output, sizeof(output)) == 1);
        assert(strcmp(output, expected[i]) == 0);
        assert(vitals_browser_provider_path(output, provider, sizeof(provider)) == 1);
        assert(strstr(provider, "vitals/vitals.suprx") != NULL);
        assert(strncmp(provider, paths[i], (size_t)(strchr(paths[i], ':') - paths[i]) + 1) == 0);
        assert(vitals_browser_module_path(provider, output, sizeof(output)) == 1);
        assert(strcmp(output, expected[i]) == 0);
        assert(vitals_browser_ca_path(output, provider, sizeof(provider)) == 1);
        assert(strstr(provider, "cert/CA_LIST.cer") != NULL);
        assert(strncmp(provider, paths[i], (size_t)(strchr(paths[i], ':') - paths[i]) + 1) == 0);
    }
    assert(vitals_browser_replacement_path(paths[0], short_buffer, sizeof(short_buffer)) == 0);
    assert(strcmp(short_buffer, "abc") == 0);
    assert(vitals_browser_replacement_path("/webcore/ScePsp2Compat.suprx", output, sizeof(output)) == 0);
    assert(vitals_browser_replacement_path(":/webcore/ScePsp2Compat.suprx", output, sizeof(output)) == 0);
    assert(vitals_browser_replacement_path(":webcore/ScePsp2Compat.suprx", output, sizeof(output)) == 0);
    assert(vitals_browser_replacement_path("wb0:/notwebcore/ScePsp2Compat.suprx", output, sizeof(output)) == 0);
    assert(vitals_browser_replacement_path("wb0:notwebcore/ScePsp2Compat.suprx", output, sizeof(output)) == 0);
    assert(vitals_browser_provider_path("wb0:vitals/ScePsp2Compat.suprx", provider, sizeof(provider)) == 1);
    assert(strcmp(provider, "wb0:vitals/vitals.suprx") == 0);
    assert(vitals_browser_ca_path("wb0:vitals/ScePsp2Compat.suprx", provider, sizeof(provider)) == 1);
    assert(strcmp(provider, "wb0:cert/CA_LIST.cer") == 0);
    assert(vitals_browser_replacement_path("x", output, sizeof(output)) == 0);
    assert(vitals_browser_replacement_path(NULL, output, sizeof(output)) == 0);
    assert(vitals_browser_replacement_path(paths[0], NULL, 0) == 0);
    assert(vitals_browser_provider_path("wb0:/vitals/not-compat.suprx", output, sizeof(output)) == 0);
    assert(vitals_browser_module_path("sd062e8855c978:/vitals/vitals.suprx", output, sizeof(output)) == 1);
    assert(strcmp(output, "sd062e8855c978:/vitals/ScePsp2Compat.suprx") == 0);
    assert(vitals_browser_module_path("wb0:/vitals/vitals.suprx", output, strlen("wb0:/vitals/ScePsp2Compat.suprx") + 1) == 1);
    const char *invalid[] = {NULL, "x", ":vitals/vitals.suprx", "/vitals/vitals.suprx",
        "wb0:/notvitals/vitals.suprx", "wb0:/vitals/other.suprx"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
        assert(vitals_browser_module_path(invalid[i], output, sizeof(output)) == 0);
    assert(vitals_browser_module_path("wb0:/vitals/vitals.suprx", short_buffer, sizeof(short_buffer)) == 0);
    assert(strcmp(short_buffer, "abc") == 0);
    assert(vitals_browser_module_path("wb0:/vitals/vitals.suprx", output, strlen("wb0:/vitals/ScePsp2Compat.suprx")) == 0);
    puts("browser mount-preserving paths: PASS");
    return 0;
}
