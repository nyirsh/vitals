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

#define VITALS_BOOT_PLUGINS "/dev_hdd0/boot_plugins.txt"
/* The DNS kernel plugin's line is taken out of the kernel list, never put in */
#define VITALS_BOOT_PLUGINS_KERNEL "/dev_hdd0/boot_plugins_kernel.txt"

#define VITALS_DEBUG_LEVEL_COUNT 3

/* A line of an operation's progress */
typedef void (*VitalsNote)(const char *line);

/* Where the app's files are (its USRDIR), from argv[0] */
void vitals_install_set_source(const char *eboot_path);
/* 1 when boot_plugins.txt lists the plugin and its files are there */
int vitals_install_detect(void);
/* The installed version ("2.0") and debug level (0 to 2) from installed.txt: 0, or -1 */
int vitals_install_read(char *version, size_t size, int *debug_level);
/* Install (or reinstall) with that debug level, or uninstall: 0, or a negative error */
int vitals_install_run(int debug_level, VitalsNote note);
int vitals_uninstall_run(VitalsNote note);
/* Only libssl's and libhttp's builds change */
int vitals_install_set_debug_level(int debug_level, VitalsNote note);
/* Mozilla's bundle downloaded again (curl.se) and checked, into VITALS_BUNDLE: 0, or the error */
int vitals_update_certificates(VitalsNote note);
/* When VITALS_BUNDLE was last written, "2026-11-03 21:40" (UTC), or empty */
void vitals_certificates_date(char *text, size_t size, int *stale);
/* A hard reboot (lv2's sys_sm_shutdown), which Cobra needs to load its boot plugins again, with the
 * system's "turned off" marker deleted first so the next start doesn't warn about it */
void vitals_reboot(void);
/* A component's switch in flags/ (VITALS_TLS_OFF and the others): 1 when it's off, its .off there */
int vitals_switch_is_off(const char *path);
/* Writes its .off (off) or deletes it: 0, or cellFs's error. It applies from the next boot */
int vitals_switch_set(const char *path, int off);

#endif
