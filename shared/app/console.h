#ifndef VITALS_APP_CONSOLE_H
#define VITALS_APP_CONSOLE_H

#include <stddef.h>

/* What each console's app implements for the shared one (app.c): what the system is, vitals'
 * operations on it, its switches, and the words that differ between consoles. The screens, the
 * menus and their logic are shared; this is what's under them. Each console also provides
 * vitals_paths.h (VITALS_REDIRECTS and VITALS_DNS, the lists' places), platform.h's functions and
 * check.h's connection test */

/* Debug output: 0 off, 1 basic, 2 full; each level has its own builds of vitals' modules */
#define VITALS_DEBUG_LEVEL_COUNT 3

/* A line of an operation's progress */
typedef void (*VitalsNote)(const char *line);

/* ---- the system ---- */

/* What the console runs, as the header shows it after the app's version ("4.93 CEX, Cobra 8.5") */
const char *console_system_text(void);
/* 1 on a system vitals is made and tested for; elsewhere the app installs nothing */
int console_supported(void);
/* 1 when the user asked to install on an unsupported system anyway (for testers) */
int console_unsupported_allowed(void);

/* The words that differ between consoles */
typedef struct {
	/* The console's name in a sentence: "PS3" */
	const char *name;
	/* What vitals is made for, after "vitals is made for ": "4.93 CEX with Cobra" */
	const char *made_for;
	/* The Install item's description */
	const char *install_description;
	/* What each debug output level does, on the Options screen */
	const char *debug_purposes[VITALS_DEBUG_LEVEL_COUNT];
} ConsoleWords;

const ConsoleWords *console_words(void);

/* ---- vitals on the console ---- */

/* 1 when vitals is installed */
int vitals_install_detect(void);
/* The installed version ("2.0") and debug level (0 to 2): 0, or -1 when they can't be read */
int vitals_install_read(char *version, size_t size, int *debug_level);
/* Install (or reinstall, or update) with that debug level, or uninstall: 0, or a negative error.
 * The console reboots afterwards for it to apply */
int vitals_install_run(int debug_level, VitalsNote note);
int vitals_uninstall_run(VitalsNote note);
/* Only the debug output's builds change */
int vitals_install_set_debug_level(int debug_level, VitalsNote note);
/* The trusted certificates downloaded again (Mozilla's, from curl.se) and installed: 0, or the
 * error. No reboot is needed */
int vitals_update_certificates(VitalsNote note);
/* When the certificates were last written, "2026-11-03 21:40", or empty; *stale when they're more
 * than three months old */
void vitals_certificates_date(char *text, size_t size, int *stale);
/* Reboots the console, for an install, an uninstall or the options to apply */
void vitals_reboot(void);

/* ---- the switches the Options screen turns on and off, which apply from the next boot ---- */

typedef struct {
	/* "TLS", and what each state means: "vitals TLS enabled", "Sony TLS enabled" */
	const char *label, *on, *off;
	/* The file that turns it off, named in the Options' progress */
	const char *file;
} ConsoleSwitch;

/* How many there are (none on a console without them) */
unsigned console_switch_count(void);
const ConsoleSwitch *console_switch(unsigned index);
/* 1 when it's off */
int console_switch_is_off(unsigned index);
/* Turns it off or on: 0, or the error */
int console_switch_set(unsigned index, int off);

/* ---- the rest ---- */

/* Where the app's own file name (CHANGELOG.md, CREDITS.md) is, for platform_read_file */
void console_app_file(const char *name, char *path, size_t size);
/* What the console's app keeps open (its network libraries), closed as the app exits */
void console_close(void);

#endif
