#ifndef VITALS_APP_UI_H
#define VITALS_APP_UI_H
#include "model.h"
#define CHECK_WIDTH 960
#define CHECK_HEIGHT 544
#define CHECK_VISIBLE_CIPHERS 4
#define APP_TASK_VISIBLE_LINES 12
typedef struct {
    const char *label;
    const char *description;
} AppMenuItem;
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
    const char *hints;
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
void app_draw_home(uint32_t *pixels, const AppHome *home);
void app_draw_task(uint32_t *pixels, const AppTask *task);
/* The connection test, as drawn by Vital Signs */
void check_draw(uint32_t *pixels, const CheckService *service, int page,
                unsigned scroll, int busy, const char *notice);
#endif
