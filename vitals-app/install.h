#ifndef VITALS_APP_INSTALL_H
#define VITALS_APP_INSTALL_H

#include <stddef.h>

#include "options.h"

/* Installs, reinstalls or removes vitals and its certificates
 * The code comes from the vitals installer; progress messages are reported one line at a
 * time through a callback */
typedef void (*VitalsInstallNote)(const char *line);

/* 1 on firmware 3.65; otherwise 0, with the detected firmware described in description */
int vitals_install_firmware_supported(char *description, size_t size);
/* 1 when the plugin, every module and the certificates are installed */
int vitals_install_detect(void);
/* Runs option (FULL or CERTIFICATES)
 * The caller reboots the Vita after a success */
int vitals_install_run(enum VitalsOption option, int removing, VitalsInstallNote note);
/* Implemented by the app: 1 when the network is up for the certificate download */
int vitals_install_network_ready(void);

#endif
