#include "options.h"
#include <stddef.h>
int vitals_plan_option(enum VitalsOption option, int removing, VitalsInstallPlan *plan) {
    if (!plan) return -1;
    plan->components = 0;
    plan->removing = !!removing;
    switch (option) {
    case VITALS_OPTION_FULL:
        plan->components = VITALS_COMPONENT_COORDINATOR | VITALS_COMPONENT_BROWSER |
            VITALS_COMPONENT_SYSTEM | VITALS_COMPONENT_CERTIFICATES;
        break;
    case VITALS_OPTION_CERTIFICATES:
        plan->components = VITALS_COMPONENT_CERTIFICATES;
        break;
    default: return -1;
    }
    return 0;
}
int vitals_execute_plan(const VitalsInstallPlan *plan, VitalsInstallAction action, void *context) {
    if (!plan || !action) return -1;
    /* Install/enable the shared coordinator only after its payloads are ready
     * Remove it only after selected payload removals have succeeded */
    static const unsigned order[] = {VITALS_COMPONENT_BROWSER, VITALS_COMPONENT_SYSTEM,
        VITALS_COMPONENT_CERTIFICATES, VITALS_COMPONENT_COORDINATOR};
    for (unsigned i = 0; i < sizeof(order) / sizeof(order[0]); ++i) {
        if (!(plan->components & order[i])) continue;
        int result = action(context, order[i], plan->removing);
        if (result < 0) return result;
    }
    return 0;
}
