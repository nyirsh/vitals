#ifndef VITALS_APP_UI_H
#define VITALS_APP_UI_H

#include "changelog.h"
#include "model.h"

/* The app's screens, the same on every console: drawn in a 1280x720 layout (0xAARRGGBB, alpha
 * ignored), which ui.c scales to the console's canvas (check_canvas_set) */

#define CHECK_WIDTH 1280
#define CHECK_HEIGHT 720
#define CHECK_VISIBLE_CIPHERS 5
#define CHECK_VISIBLE_BADSSL 5
#define CHECK_VISIBLE_REDIRECTS 5
#define CHECK_VISIBLE_DNS 5
/* The test's detail pages, which Square cycles in the order the tests run */
#define CHECK_PAGE_REQUESTS CHECK_FOLLOW_REQUESTS
#define CHECK_PAGE_CIPHERS CHECK_FOLLOW_CIPHERS
#define CHECK_PAGE_HANDSHAKE 2
#define CHECK_PAGE_CERTIFICATES CHECK_FOLLOW_CERTIFICATES
#define CHECK_PAGE_REDIRECTS CHECK_FOLLOW_REDIRECTS
#define CHECK_PAGE_DNS CHECK_FOLLOW_DNS
#define CHECK_PAGE_COUNT 6
#define APP_TASK_VISIBLE_LINES 12
#define APP_CHANGELOG_VISIBLE_LINES 14
/* How wide the changelog's lines may be: plain text, and a change after its bullet */
#define APP_CHANGELOG_WIDTH 1152
#define APP_CHANGELOG_ITEM_WIDTH 1120
#define APP_CHANGELOG_TEXT_SIZE 22

typedef struct {
	const char *label;
	const char *description;
	/* What Left and Right choose on this item ("Basic"), drawn apart from the label; NULL when
	 * there is nothing to choose */
	const char *choice;
	/* The choice is the one in use now */
	int choice_current;
	/* The choice is the first or the last there is: no arrow on that side, as Left or Right goes
	 * no further */
	int choice_first, choice_last;
	/* The choice's colour: blue as usual, or orange or red for one that takes something away
	 * (Uninstall, a debug build) or turns a part of vitals off */
	enum { APP_TONE_USUAL, APP_TONE_ORANGE, APP_TONE_RED } choice_tone;
	/* A date shown small after the label, as "Last update: 2026-11-04" (the certificates'); in red
	 * when alert is set (they're old) */
	const char *value;
	int value_alert;
} AppMenuItem;

/* A control shown in the bar at the bottom: up to two button symbols, then what they do. Confirm
 * and back are Cross and Circle, or swapped where the system setting makes Circle confirm */
typedef enum {
	APP_GLYPH_NONE,
	APP_GLYPH_CONFIRM,
	APP_GLYPH_BACK,
	APP_GLYPH_TRIANGLE,
	APP_GLYPH_SQUARE,
	APP_GLYPH_DPAD,
	APP_GLYPH_STICK,
	APP_GLYPH_START
} AppGlyph;

typedef struct {
	AppGlyph glyph, also;
	const char *label;
} AppHint;

/* What the header's status card says about the installed vitals */
typedef struct {
	int installed;
	/* Another version than the one this app carries is installed */
	int outdated;
	/* The installed version ("2.0"), empty or NULL when unknown */
	const char *installed_version;
	/* The installed debug output level's name ("Basic", "Full"); NULL when it is off */
	const char *debug_output;
	/* What the console runs ("4.93 CEX, Cobra 8.5"), after the version; NULL when unknown */
	const char *console;
} AppStatus;

typedef struct {
	AppStatus status;
	/* A warning card above the menu (an unsupported system), or NULL */
	const char *warning_title, *warning_text;
	const AppMenuItem *items;
	unsigned count, selected;
	/* The controls shown at the bottom; NULL for the usual ones */
	const AppHint *hints;
	unsigned hint_count;
} AppHome;

/* The Options screen: the four switches (On or Off) and the debug output, with the note that a
 * reboot applies them */
typedef struct {
	AppStatus status;
	const AppMenuItem *items;
	unsigned count, selected;
	const AppHint *hints;
	unsigned hint_count;
} AppOptions;

/* An install, uninstall or certificate update in progress or finished */
typedef struct {
	AppStatus status;
	const char *title;
	const char *const *lines;
	unsigned count;
	enum CheckState state;
	const char *status_line;
	/* The controls once it's done: NULL for Back alone */
	const AppHint *hints;
	unsigned hint_count;
} AppTask;

/* The changelog or the credits, from line scroll on */
typedef struct {
	AppStatus status;
	/* "Changelog", "Credits": the screen shows either, laid out the same way */
	const char *title;
	const ChangelogLine *lines;
	unsigned count, scroll;
} AppChangelog;

/* Which symbols confirm and back show: Cross and Circle, or swapped where the system setting makes
 * Circle confirm (as on Japanese consoles) */
void app_set_circle_confirms(int circle_confirms);
/* How wide text is at a font size of px layout pixels, in layout pixels */
int app_text_width(const char *text, unsigned px);
void app_draw_home(uint32_t *pixels, const AppHome *home);
void app_draw_options(uint32_t *pixels, const AppOptions *options);
void app_draw_task(uint32_t *pixels, const AppTask *task);
void app_draw_changelog(uint32_t *pixels, const AppChangelog *changelog);
/* The connection test */
void check_draw(uint32_t *pixels, const CheckService *service, int page, unsigned scroll, int busy,
                const char *notice);

#endif
