#ifndef VITALS_APP_UI_H
#define VITALS_APP_UI_H
#include "changelog.h"
#include "model.h"
#define CHECK_WIDTH 960
#define CHECK_HEIGHT 544
#define CHECK_VISIBLE_CIPHERS 4
#define CHECK_VISIBLE_REDIRECTS 5
/* The test's detail pages, which Square cycles: ciphers, request details, handshake details, the
 * badssl.com certificate checks and host redirects */
#define CHECK_PAGE_COUNT 5
#define APP_TASK_VISIBLE_LINES 12
#define APP_CHANGELOG_VISIBLE_LINES 14
/* How wide the changelog's lines may be: plain text, and a change after its bullet */
#define APP_CHANGELOG_WIDTH 864
#define APP_CHANGELOG_ITEM_WIDTH 840
#define APP_CHANGELOG_TEXT_SIZE 17
typedef struct {
    const char *label;
    const char *description;
    /* What Left and Right choose on this item ("Basic"), drawn apart from the label; NULL when
     * there is nothing to choose */
    const char *choice;
    /* The choice is the one in use now */
    int choice_current;
} AppMenuItem;
/* A control shown in the bar at the bottom: up to two button symbols, then what they do
 * Confirm and back are Cross and Circle, or swapped where the system setting makes Circle
 * confirm */
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
typedef struct {
    int installed;
    int outdated;
    const char *installed_version;
    /* The installed debug output level's name ("Basic", "Full"); NULL when it is off or unknown */
    const char *debug_output;
    int firmware_supported;
    const char *firmware;
    const AppMenuItem *items;
    unsigned count, selected;
    /* The controls shown at the bottom; NULL for the usual ones */
    const AppHint *hints;
    unsigned hint_count;
    /* A newer published release than this app ("1.3"), or NULL */
    const char *latest_release;
} AppHome;
/* An install, uninstall or certificate update in progress or finished */
typedef struct {
    int installed;
    int outdated;
    const char *installed_version;
    /* The installed debug output level's name ("Basic", "Full"); NULL when it is off or unknown */
    const char *debug_output;
    /* A newer published release than this app ("1.3"), or NULL */
    const char *latest_release;
    const char *title;
    const char *const *lines;
    unsigned count;
    enum CheckState state;
    const char *status;
} AppTask;
/* The changelog, from line scroll on */
typedef struct {
    int installed;
    int outdated;
    const char *installed_version;
    /* The installed debug output level's name ("Basic", "Full"); NULL when it is off or unknown */
    const char *debug_output;
    /* A newer published release than this app ("1.3"), or NULL */
    const char *latest_release;
    const ChangelogLine *lines;
    unsigned count, scroll;
} AppChangelog;
/* Which symbols confirm and back show: Cross and Circle, or swapped where the system setting
 * makes Circle confirm (as on Japanese consoles) */
void app_set_circle_confirms(int circle_confirms);
void app_draw_home(uint32_t *pixels, const AppHome *home);
void app_draw_task(uint32_t *pixels, const AppTask *task);
void app_draw_changelog(uint32_t *pixels, const AppChangelog *changelog);
/* The connection test, as drawn by Vital Signs */
void check_draw(uint32_t *pixels, const CheckService *service, int page,
                unsigned scroll, int busy, const char *notice);
#endif
