#ifndef VITALS_APP_INSTALL_H
#define VITALS_APP_INSTALL_H

#include <stddef.h>

/* What the app puts on the console, as tools/ps3_comms.py does: vitals' libssl and libhttp (the
 * builds of the chosen debug level), the boot plugin, the DNS kernel plugin (which the boot plugin
 * loads; not listed in boot_plugins_kernel.txt), Mozilla's CA bundle, the example redirects.txt
 * and dns.txt (only where there are none: they're the user's, and uninstalling leaves them, as on
 * the Vita) and boot_plugins.txt's line, with installed.txt saying which version and level are
 * there */

/* Where each file goes (common/vitals_paths.h): the user's lists in /dev_hdd0/vitals, the modules
 * and what the installer keeps in system/, the switches in flags/, the logs in logs/, the connection
 * test's reports in reports/ */
#include "vitals_paths.h"

/* What the shared app calls (console.h): vitals_install_detect, _read, _run, vitals_uninstall_run,
 * vitals_install_set_debug_level, vitals_update_certificates, vitals_certificates_date and
 * vitals_reboot, all here in install.c */
#include "console.h"

#define VITALS_BOOT_PLUGINS "/dev_hdd0/boot_plugins.txt"
/* The DNS kernel plugin's line is taken out of the kernel list, never put in */
#define VITALS_BOOT_PLUGINS_KERNEL "/dev_hdd0/boot_plugins_kernel.txt"

/* Where the app's files are (its USRDIR), from argv[0] */
void vitals_install_set_source(const char *eboot_path);
/* That folder, "/dev_hdd0/game/VTLS00001/USRDIR" */
const char *vitals_install_source(void);
/* Here, vitals_install_detect is 1 when boot_plugins.txt lists the plugin and its files are there;
 * vitals_install_read reads installed.txt; vitals_install_set_debug_level changes only libssl's and
 * libhttp's builds; vitals_update_certificates downloads Mozilla's bundle again (curl.se), checks it
 * and writes it into VITALS_BUNDLE without Sony's CAs, then closes libhttp; vitals_certificates_date is in UTC; and
 * vitals_reboot is a hard reboot (lv2's sys_sm_shutdown), which Cobra needs to load its boot plugins
 * again, with the system's "turned off" marker deleted first so the next start doesn't warn */
/* A component's switch in flags/ (VITALS_TLS_OFF and the others): 1 when it's off, its .off there */
int vitals_switch_is_off(const char *path);
/* Writes its .off (off) or deletes it: 0, or cellFs's error. It applies from the next boot */
int vitals_switch_set(const char *path, int off);

#endif
