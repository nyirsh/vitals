#ifndef VITALS_APP_INSTALL_H
#define VITALS_APP_INSTALL_H

#include <stddef.h>

#include "options.h"

/* Installs, reinstalls or removes vitals and its certificates
 * The code comes from the vitals installer; progress messages are reported one line at a
 * time through a callback */
typedef void (*VitalsInstallNote)(const char *line);

/* The certificate store the system's TLS and vitals use, which a certificate update rewrites */
#define VITALS_CERTIFICATE_STORE "vs0:/data/external/cert/CA_LIST.cer"

/* 1 on firmware 3.60 or 3.65; otherwise 0, with the detected firmware described in description */
int vitals_install_firmware_supported(char *description, size_t size);
/* 1 when the plugin, every module and the certificates are installed */
int vitals_install_detect(void);
/* 1 when the installed kernel plugin is the one this app carries, 0 when it differs (another
 * version), negative when either cannot be read (not installed) */
int vitals_install_plugin_current(void);
/* The release number the installed kernel plugin carries ("1.2"), or a negative error */
int vitals_install_plugin_version(char *version, size_t size);
/* Debug output on the console: 0 off, 1 summaries and failures, 2 everything; each level has its
 * own build of the providers and vitals-reauth, all carried by the app */
#define VITALS_DEBUG_LEVEL_COUNT 3
/* The level of the installed modules, or -1 when they match none of the app's builds */
int vitals_install_debug_level(void);
/* Replaces the providers and vitals-reauth with the given level's builds
 * The caller reboots the Vita after a success */
int vitals_install_set_debug_level(int level, VitalsInstallNote note);
/* Where an install, reinstall or update lists the kernel plugin in config.txt */
typedef enum
{
    /* vitals' own *KERNEL block, at the top of the file */
    VITALS_PLACEMENT_BLOCK,
    /* The first line of the first *KERNEL section, so it loads before the other kernel plugins */
    VITALS_PLACEMENT_FIRST,
    /* The last line of the last *KERNEL section, so it loads after them */
    VITALS_PLACEMENT_LAST,
    /* Wherever it is listed already; a config that doesn't list it gets vitals' own block */
    VITALS_PLACEMENT_KEEP,
} VitalsPlacement;
/* Where config.txt lists the plugin now: VITALS_PLACEMENT_KEEP when it is somewhere other than
 * the three places, negative when it isn't listed (or config.txt can't be read) */
int vitals_install_placement(void);
/* Where the next install, reinstall or update lists the plugin; VITALS_PLACEMENT_KEEP until set
 * Another place than the current one moves the plugin's line there, so it is listed only once */
void vitals_install_set_placement(VitalsPlacement placement);
/* Runs option (FULL or CERTIFICATES)
 * The caller reboots the Vita after a success */
int vitals_install_run(enum VitalsOption option, int removing, VitalsInstallNote note);
/* Implemented by the app: 1 when the network is up for the certificate download */
int vitals_install_network_ready(void);

#endif
