#include "vitals/path.h"
#include <assert.h>
#include <stdio.h>

/* A process's request for Sony's browser engine, under whichever device it sees vs0:data/external
 * as (the kernel loads vitals' engine from ux0:data/vitals/system in its place) */
int main(void) {
    const char *requests[] = {
        "vs0:/data/external/webcore/ScePsp2Compat.suprx",
        "vs0:data/external/webcore/ScePsp2Compat.suprx",
        "wb0:/webcore/ScePsp2Compat.suprx",
        "wb0:webcore/ScePsp2Compat.suprx",
        "sd062e8855c978:/webcore/ScePsp2Compat.suprx",
    };
    for (size_t i = 0; i < sizeof(requests) / sizeof(requests[0]); ++i)
        assert(vitals_browser_engine_request(requests[i]) == 1);
    const char *others[] = {NULL, "x", "/webcore/ScePsp2Compat.suprx", ":/webcore/ScePsp2Compat.suprx",
        ":webcore/ScePsp2Compat.suprx", "wb0:/notwebcore/ScePsp2Compat.suprx",
        "wb0:notwebcore/ScePsp2Compat.suprx", "vs0:sys/external/libhttp.suprx",
        "ux0:data/vitals/system/ScePsp2Compat.suprx", "webcore/ScePsp2Compat.suprx"};
    for (size_t i = 0; i < sizeof(others) / sizeof(others[0]); ++i)
        assert(vitals_browser_engine_request(others[i]) == 0);
    puts("browser engine requests: Sony's engine under any device PASS");
    return 0;
}
