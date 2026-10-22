#ifndef VITALS_APP_OPTIONS_H
#define VITALS_APP_OPTIONS_H
/* The build passes the release version from ../VERSION */
#ifndef VITALS_VERSION
#error "VITALS_VERSION is not defined; build through CMake, which reads it from ../VERSION"
#endif
enum VitalsOption {
    VITALS_OPTION_FULL,
    VITALS_OPTION_CERTIFICATES,
    VITALS_OPTION_EXIT,
    VITALS_OPTION_COUNT
};
enum VitalsComponent {
    VITALS_COMPONENT_COORDINATOR = 1u,
    VITALS_COMPONENT_BROWSER = 2u,
    VITALS_COMPONENT_SYSTEM = 4u,
    VITALS_COMPONENT_CERTIFICATES = 8u
};
typedef struct { unsigned components; int removing; } VitalsInstallPlan;
/* FULL installs or removes everything; CERTIFICATES installs or refreshes the certificate store */
int vitals_plan_option(enum VitalsOption option, int removing, VitalsInstallPlan *plan);
typedef int (*VitalsInstallAction)(void *context, unsigned component, int removing);
int vitals_execute_plan(const VitalsInstallPlan *plan, VitalsInstallAction action, void *context);
#endif
