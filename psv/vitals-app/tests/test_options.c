#include "options.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
typedef struct { unsigned present, calls[4], count, fail; } State;
static int apply(void *context, unsigned component, int removing) {
    State *s = context;
    assert(s->count < 4);
    s->calls[s->count++] = component;
    if (component == s->fail) return -71;
    if (removing) s->present &= ~component;
    else s->present |= component;
    return 0;
}
static State run(enum VitalsOption option, int removing, unsigned present) {
    VitalsInstallPlan p;
    assert(vitals_plan_option(option, removing, &p) == 0);
    State s = {.present = present};
    assert(vitals_execute_plan(&p, apply, &s) == 0);
    return s;
}
int main(void) {
    const unsigned k = VITALS_COMPONENT_COORDINATOR, b = VITALS_COMPONENT_BROWSER,
                   h = VITALS_COMPONENT_SYSTEM, c = VITALS_COMPONENT_CERTIFICATES;
    /* Install, reinstall and uninstall cover everything; the coordinator goes last */
    State full = run(VITALS_OPTION_FULL, 0, 0);
    assert(full.present == (k|b|h|c) && full.calls[full.count - 1] == k);
    assert(run(VITALS_OPTION_FULL, 0, k|b|h|c).present == (k|b|h|c));
    assert(run(VITALS_OPTION_FULL, 1, k|b|h|c).present == 0);
    /* Updating certificates touches nothing else */
    assert(run(VITALS_OPTION_CERTIFICATES, 0, 0).present == c);
    assert(run(VITALS_OPTION_CERTIFICATES, 0, k|b|h|c).present == (k|b|h|c));
    /* A failure stops the plan before the coordinator is enabled or removed */
    VitalsInstallPlan p;
    assert(vitals_plan_option(VITALS_OPTION_FULL, 0, &p) == 0);
    State failed = {.fail = c};
    assert(vitals_execute_plan(&p, apply, &failed) == -71);
    assert(failed.present == (b|h) && !(failed.present & k));
    assert(vitals_plan_option(VITALS_OPTION_FULL, 1, &p) == 0);
    failed = (State){.present = k|b|h|c, .fail = h};
    assert(vitals_execute_plan(&p, apply, &failed) == -71);
    assert(failed.present == (k|h|c));
    assert(vitals_plan_option(VITALS_OPTION_EXIT, 0, &p) < 0);
    assert(vitals_plan_option((enum VitalsOption)-1, 0, &p) < 0);
    assert(vitals_plan_option(VITALS_OPTION_FULL, 0, NULL) < 0);
    puts("Installer plans: full install/uninstall, certificate update and failure ordering: PASS");
}
