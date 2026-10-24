#include "changelog.h"
#include "check.h"
#include "font.h"
#include "input.h"
#include "install.h"
#include "release_version.h"
#include "ui.h"
#include "version_check.h"
#include <psp2/apputil.h>
#include <psp2/ctrl.h>
#include <psp2/display.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/sysmem.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/net/net.h>
#include <psp2/net/netctl.h>
#include <psp2/power.h>
#include <psp2/sysmodule.h>
#include <psp2/system_param.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* vitals: installs, reinstalls or removes vitals, updates its certificates and runs the
 * connection test from Vital Signs, all from one menu */
unsigned int _newlib_heap_size_user = 16u * 1024u * 1024u;

enum Action
{
    ACTION_INSTALL,
    ACTION_UPDATE,
    ACTION_REINSTALL,
    ACTION_UNINSTALL,
    ACTION_CERTIFICATES,
    ACTION_TEST,
    ACTION_DEBUG,
    ACTION_CHANGELOG,
    ACTION_EXIT
};
static const AppMenuItem action_items[] = {
    [ACTION_INSTALL] = {"Install",
                        "Lets the browser, apps and games connect to modern secure (TLS 1.2 and 1.3) sites"},
    [ACTION_UPDATE] = {"Update", "Replaces the installed vitals with the version this app carries"},
    [ACTION_REINSTALL] = {"Reinstall", "Use this to either update versions or fix a broken installation"},
    [ACTION_UNINSTALL] = {"Uninstall", "Removes all of the installed files"},
    [ACTION_CERTIFICATES] = {"Update certificates",
                             "Downloads the latest trusted websites certificates"},
    [ACTION_TEST] = {"Test connections",
                     "Checks that everything is working as expected"},
    [ACTION_DEBUG] = {"Debug output", ""},
    [ACTION_CHANGELOG] = {"Changelog", "What changed in each version of vitals"},
    [ACTION_EXIT] = {"Exit", ""},
};

static uint32_t *canvas;
static void *pixels;
static unsigned held = ~0u;
static int installed;
/* A different kernel plugin is installed than the one this app carries */
static int outdated;
/* The installed plugin's release number, empty when it is unknown */
static char installed_version[16];
/* Debug output: the installed modules' level (-1 when unknown) and the one chosen in the menu */
static int debug_level = -1, debug_choice;
static const char *const debug_names[VITALS_DEBUG_LEVEL_COUNT] = {"Off", "Basic", "Full"};
/* Where config.txt lists the plugin: now (-1 when it doesn't), and as chosen on the install item */
static int placement_current = -1;
static VitalsPlacement placement_choice = VITALS_PLACEMENT_BLOCK;
static const char *const placement_names[] = {
    [VITALS_PLACEMENT_BLOCK] = "Own block",
    [VITALS_PLACEMENT_FIRST] = "First in *KERNEL",
    [VITALS_PLACEMENT_LAST] = "Last in *KERNEL",
    [VITALS_PLACEMENT_KEEP] = "Where it is now",
};
static const char *const placement_purposes[] = {
    [VITALS_PLACEMENT_BLOCK] = "Lists vitals in its own *KERNEL block, at the top of config.txt",
    [VITALS_PLACEMENT_FIRST] = "Lists vitals first in your *KERNEL section, so it loads before your other plugins",
    [VITALS_PLACEMENT_LAST] = "Lists vitals last in your *KERNEL section, so it loads after your other plugins",
    [VITALS_PLACEMENT_KEEP] = "Leaves vitals' line in config.txt where you put it",
};
/* The placements Left and Right go through; where it is now comes first when it is none of the
 * other three */
static unsigned placement_options(VitalsPlacement options[4])
{
    unsigned count = 0;
    if (placement_current == VITALS_PLACEMENT_KEEP)
        options[count++] = VITALS_PLACEMENT_KEEP;
    options[count++] = VITALS_PLACEMENT_BLOCK;
    options[count++] = VITALS_PLACEMENT_FIRST;
    options[count++] = VITALS_PLACEMENT_LAST;
    return count;
}
static int installs_plugin(int action)
{
    return action == ACTION_INSTALL || action == ACTION_UPDATE || action == ACTION_REINSTALL;
}

static uint64_t now_ms(void) { return sceKernelGetSystemTimeWide() / 1000; }

/* Cross confirms and Circle goes back, unless the system setting swaps them (as on Japanese
 * consoles); read once at start-up */
static unsigned confirm_button = SCE_CTRL_CROSS, back_button = SCE_CTRL_CIRCLE;
static int app_util_ready;
static void read_button_setting(void)
{
    SceAppUtilInitParam init;
    SceAppUtilBootParam boot;
    int enter = SCE_SYSTEM_PARAM_ENTER_BUTTON_CROSS;
    memset(&init, 0, sizeof(init));
    memset(&boot, 0, sizeof(boot));
    app_util_ready = sceAppUtilInit(&init, &boot) >= 0;
    if (app_util_ready && sceAppUtilSystemParamGetInt(SCE_SYSTEM_PARAM_ID_ENTER_BUTTON, &enter) >= 0 &&
        enter == SCE_SYSTEM_PARAM_ENTER_BUTTON_CIRCLE)
    {
        confirm_button = SCE_CTRL_CIRCLE;
        back_button = SCE_CTRL_CROSS;
        app_set_circle_confirms(1);
    }
}

/* Shows the finished canvas at the next vblank; the screen has only one buffer */
static void present(void)
{
    sceDisplayWaitVblankStart();
    memcpy(pixels, canvas, CHECK_WIDTH * CHECK_HEIGHT * sizeof(*canvas));
}

/* Buttons newly pressed since the last call
 * Queued samples are drained so short presses are not lost while the screen is drawn */
static unsigned read_presses(void)
{
    SceCtrlData pads[64];
    int count = sceCtrlReadBufferPositive(0, pads, 64);
    unsigned pressed = 0;
    for (int i = 0; i < count && i < 64; ++i)
    {
        pressed |= pads[i].buttons & ~held;
        held = pads[i].buttons;
    }
    return pressed;
}

/* The network is started once and shared by the certificate download, the test and the
 * new-version check */
static void *net_memory;
static int net_loaded, net_ready, ctl_ready, net_result = 1;
/* Waits up to 10 seconds for a connection; *cancel set by another thread ends the wait early
 * without recording a result, so the next caller waits again */
static int network_start_until(const volatile int *cancel)
{
    if (net_result <= 0)
        return net_result;
    int rc = 0;
    if (!ctl_ready)
    {
        if (!net_loaded && sceSysmoduleIsLoaded(SCE_SYSMODULE_NET) != SCE_SYSMODULE_LOADED)
        {
            rc = sceSysmoduleLoadModule(SCE_SYSMODULE_NET);
            if (rc < 0)
                goto done;
            net_loaded = 1;
        }
        if (!net_ready)
        {
            net_memory = malloc(1024 * 1024);
            if (!net_memory)
            {
                rc = -1;
                goto done;
            }
            SceNetInitParam net = {net_memory, 1024 * 1024, 0};
            rc = sceNetInit(&net);
            if (rc < 0)
                goto done;
            net_ready = 1;
        }
        rc = sceNetCtlInit();
        if (rc < 0)
            goto done;
        ctl_ready = 1;
    }
    uint64_t deadline = now_ms() + 10000;
    for (;;)
    {
        int state = 0;
        rc = sceNetCtlInetGetState(&state);
        if (rc < 0 || state == SCE_NETCTL_STATE_CONNECTED)
            break;
        if (cancel != NULL && *cancel)
            return -1;
        if (now_ms() > deadline)
        {
            rc = (int)0x80431068;
            break;
        }
        sceKernelDelayThread(50000);
    }
done:
    net_result = rc < 0 ? rc : 0;
    return net_result;
}
static int network_start(void) { return network_start_until(NULL); }

/* The new-version check: a background thread asks GitHub, then GitLab, for the latest release
 * when the app opens; only a newer release than this app is shown, and nothing is downloaded */
static SceUID release_thread = -1;
static volatile int release_cancel, release_done;
static char latest_release[16];
static int check_release(SceSize size, void *arguments)
{
    static const char *const urls[] = {VITALS_RELEASE_URL_GITHUB, VITALS_RELEASE_URL_GITLAB};
    char version[16];
    (void)size;
    (void)arguments;
    if (network_start_until(&release_cancel) == 0 &&
        vitals_fetch_latest_release(urls, sizeof(urls) / sizeof(urls[0]), "app0:mozilla-certs.pem",
                                    "vitals/" VITALS_VERSION, 6, &release_cancel, version, sizeof(version)) == 0 &&
        vitals_release_newer(version, VITALS_VERSION) == 1)
        memcpy(latest_release, version, sizeof(latest_release));
    __atomic_store_n(&release_done, 1, __ATOMIC_RELEASE);
    return sceKernelExitThread(0);
}
static void start_release_check(void)
{
    release_thread = sceKernelCreateThread("vitals release check", check_release, 0x10000100, 256 * 1024, 0, 0, NULL);
    if (release_thread >= 0 && sceKernelStartThread(release_thread, 0, NULL) < 0)
    {
        sceKernelDeleteThread(release_thread);
        release_thread = -1;
    }
}
/* Ends the check before anything else uses the network or curl: the transfer stops at once */
static void stop_release_check(void)
{
    if (release_thread < 0)
        return;
    release_cancel = 1;
    sceKernelWaitThreadEnd(release_thread, NULL, NULL);
    sceKernelDeleteThread(release_thread);
    release_thread = -1;
}
/* The newer release, once the check found one; NULL until then and otherwise */
static const char *newer_release(void)
{
    return __atomic_load_n(&release_done, __ATOMIC_ACQUIRE) && latest_release[0] != '\0' ? latest_release : NULL;
}
static void network_stop(void)
{
    if (ctl_ready)
        sceNetCtlTerm();
    if (net_ready)
        sceNetTerm();
    if (net_loaded)
        sceSysmoduleUnloadModule(SCE_SYSMODULE_NET);
    free(net_memory);
}
int vitals_install_network_ready(void) { return network_start() == 0; }

/* Progress of the running installer operation, shown one line at a time */
#define TASK_MAX_LINES 64
static char task_lines[TASK_MAX_LINES][160];
static const char *task_line_pointers[TASK_MAX_LINES];
static AppTask task;
static void draw_task(void)
{
    task.installed = installed;
    task.outdated = outdated;
    task.installed_version = installed_version;
    task.latest_release = newer_release();
    task.debug_output = debug_level > 0 ? debug_names[debug_level] : NULL;
    app_draw_task(canvas, &task);
    present();
}
static void task_note(const char *line)
{
    if (task.count == TASK_MAX_LINES)
    {
        memmove(task_lines[0], task_lines[1], sizeof(task_lines[0]) * (TASK_MAX_LINES - 1));
        --task.count;
    }
    snprintf(task_lines[task.count++], sizeof(task_lines[0]), "%s", line);
    draw_task();
}

static void run_operation(enum Action action)
{
    static const char *const titles[] = {
        [ACTION_INSTALL] = "Installing vitals",
        [ACTION_UPDATE] = "Updating vitals",
        [ACTION_REINSTALL] = "Reinstalling vitals",
        [ACTION_UNINSTALL] = "Uninstalling vitals",
        [ACTION_CERTIFICATES] = "Updating certificates",
        [ACTION_DEBUG] = "Switching debug output",
    };
    char status[96];
    for (unsigned i = 0; i < TASK_MAX_LINES; ++i)
        task_line_pointers[i] = task_lines[i];
    task = (AppTask){.title = titles[action], .lines = task_line_pointers, .state = CHECK_RUNNING, .status = "Working..."};
    draw_task();
    /* The test's HTTP libraries are released first, so no vitals module is in use */
    vitals_check_close();
    int result = action == ACTION_DEBUG
                     ? vitals_install_set_debug_level(debug_choice, task_note)
                     : vitals_install_run(action == ACTION_CERTIFICATES ? VITALS_OPTION_CERTIFICATES
                                                                        : VITALS_OPTION_FULL,
                                          action == ACTION_UNINSTALL, task_note);
    if (result >= 0)
    {
        task.state = CHECK_PASS;
        task.status = "Done. Rebooting in 3 seconds...";
        draw_task();
        sceKernelDelayThread(3 * 1000 * 1000);
        scePowerRequestColdReset();
        for (;;)
            sceKernelDelayThread(1000 * 1000);
    }
    snprintf(status, sizeof(status), "Failed (0x%08X). No reboot was requested.", (unsigned)result);
    task.state = CHECK_FAIL;
    task.status = status;
    draw_task();
    while (!(read_presses() & back_button))
        sceKernelDelayThread(30000);
}

static void run_test(void)
{
    static CheckService view, last_view;
    char notice[120] = "", last_notice[120] = "";
    memset(&view, 0, sizeof(view));
    view.vitals_enabled = -1;
    check_draw(canvas, &view, 0, 0, 1, "Connecting to the network...");
    present();
    int rc = network_start(), ready = 0;
    if (rc < 0)
        snprintf(notice, sizeof(notice), "No network connection (0x%08X)", (unsigned)rc);
    else if ((rc = vitals_check_open()) < 0)
        snprintf(notice, sizeof(notice), "Sony network initialization failed: 0x%08X", (unsigned)rc);
    else
    {
        ready = 1;
        vitals_check_start();
    }
    int page = 0, leaving = 0, last_page = -1, last_busy = -1, busy = 0;
    unsigned scroll = 0, last_scroll = ~0u;
    CheckScrollRepeat repeat = {0};
    for (;;)
    {
        SceCtrlData pads[64];
        int pad_count = sceCtrlReadBufferPositive(0, pads, 64);
        unsigned pressed = 0, page_presses = 0;
        int scroll_steps = 0;
        uint64_t sample_ms = now_ms();
        for (int i = 0; i < pad_count && i < 64; ++i)
        {
            unsigned edges = pads[i].buttons & ~held;
            held = pads[i].buttons;
            pressed |= edges;
            int direction = check_scroll_direction(
                pads[i].buttons & SCE_CTRL_UP, pads[i].buttons & SCE_CTRL_DOWN,
                pads[i].ly, pads[i].ry);
            scroll_steps += check_scroll_repeat(&repeat, direction, sample_ms);
            page_presses += (edges & SCE_CTRL_SQUARE) != 0;
        }
        if (ready)
            busy = vitals_check_poll(&view, notice, sizeof(notice));
        if (pressed & back_button)
        {
            leaving = 1;
            if (busy)
                vitals_check_cancel();
        }
        if (leaving && !busy)
            break;
        if (pressed & SCE_CTRL_TRIANGLE)
            vitals_check_cancel();
        if (page_presses)
        {
            page = (int)((page + page_presses) % CHECK_PAGE_COUNT);
            scroll = 0;
        }
        /* The cipher list and the redirect list scroll */
        if (page == 3)
            scroll = check_scroll_move(scroll, scroll_steps, view.redirect_count, CHECK_VISIBLE_REDIRECTS);
        else
            scroll = check_scroll_move(scroll, page == 0 ? scroll_steps : 0,
                                       view.handshake.cipher_count, CHECK_VISIBLE_CIPHERS);
        if (ready && !busy && !leaving && (pressed & confirm_button))
        {
            vitals_check_start();
            busy = 1;
        }
        if (last_page != page || last_scroll != scroll || last_busy != busy ||
            strcmp(last_notice, notice) != 0 || memcmp(&last_view, &view, sizeof(view)) != 0)
        {
            check_draw(canvas, &view, page, scroll, busy, notice);
            present();
            last_view = view;
            last_page = page;
            last_scroll = scroll;
            last_busy = busy;
            snprintf(last_notice, sizeof(last_notice), "%s", notice);
        }
        sceDisplayWaitVblankStart();
        sceKernelDelayThread(30000);
    }
    /* The libraries stay loaded for the next test; operations and exiting release them */
    vitals_check_stop();
}

/* The changelog the app carries, laid out once and kept for the next visit */
#define CHANGELOG_PATH "app0:CHANGELOG.md"
#define CHANGELOG_MAX_SIZE (64u * 1024u)
#define CHANGELOG_MAX_LINES 512u
static ChangelogLine changelog_lines[CHANGELOG_MAX_LINES];
static unsigned changelog_count;
static int changelog_width(const char *text) { return check_font_width(text, APP_CHANGELOG_TEXT_SIZE); }
static void load_changelog(void)
{
    if (changelog_count != 0)
        return;
    char *text = malloc(CHANGELOG_MAX_SIZE);
    FILE *file = text != NULL ? fopen(CHANGELOG_PATH, "rb") : NULL;
    size_t length = file != NULL ? fread(text, 1, CHANGELOG_MAX_SIZE, file) : 0;
    if (file != NULL)
        fclose(file);
    if (length != 0)
        changelog_count = (unsigned)vitals_changelog_layout(text, length, changelog_width, APP_CHANGELOG_WIDTH,
                                                             APP_CHANGELOG_ITEM_WIDTH, changelog_lines,
                                                             CHANGELOG_MAX_LINES);
    free(text);
    if (changelog_count == 0)
    {
        changelog_lines[0].kind = CHANGELOG_TEXT;
        snprintf(changelog_lines[0].text, sizeof(changelog_lines[0].text),
                 "The changelog is missing from this app (" CHANGELOG_PATH ").");
        changelog_count = 1;
    }
}

static void run_changelog(void)
{
    unsigned scroll = 0, last_scroll = ~0u;
    CheckScrollRepeat repeat = {0};
    load_changelog();
    for (;;)
    {
        SceCtrlData pads[64];
        int pad_count = sceCtrlReadBufferPositive(0, pads, 64);
        unsigned pressed = 0;
        int steps = 0;
        uint64_t sample_ms = now_ms();
        for (int i = 0; i < pad_count && i < 64; ++i)
        {
            pressed |= pads[i].buttons & ~held;
            held = pads[i].buttons;
            steps += check_scroll_repeat(&repeat,
                                         check_scroll_direction(pads[i].buttons & SCE_CTRL_UP,
                                                                pads[i].buttons & SCE_CTRL_DOWN, pads[i].ly,
                                                                pads[i].ry),
                                         sample_ms);
        }
        if (pressed & back_button)
            break;
        scroll = check_scroll_move(scroll, steps, changelog_count, APP_CHANGELOG_VISIBLE_LINES);
        if (scroll != last_scroll)
        {
            AppChangelog view = {installed,          outdated,        installed_version,
                                 debug_level > 0 ? debug_names[debug_level] : NULL,
                                 newer_release(),    changelog_lines, changelog_count,
                                 scroll};
            app_draw_changelog(canvas, &view);
            present();
            last_scroll = scroll;
        }
        sceKernelDelayThread(30000);
    }
}

int main(void)
{
    int exit_code = 1, font_ready = 0, display_active = 0;
    SceKernelAllocMemBlockOpt opt = {0};
    opt.size = sizeof(opt);
    opt.attr = 4;
    opt.alignment = 256 * 1024;
    SceUID display = sceKernelAllocMemBlock("vitals screen", SCE_KERNEL_MEMBLOCK_TYPE_USER_CDRAM_RW,
                                            2 * 1024 * 1024, &opt);
    if (display < 0 || sceKernelGetMemBlockBase(display, &pixels) < 0)
        goto cleanup;
    canvas = malloc(CHECK_WIDTH * CHECK_HEIGHT * sizeof(*canvas));
    if (!canvas || check_font_init() < 0)
        goto cleanup;
    font_ready = 1;
    memset(pixels, 0, CHECK_WIDTH * CHECK_HEIGHT * sizeof(*canvas));
    SceDisplayFrameBuf frame = {0};
    frame.size = sizeof(frame);
    frame.base = pixels;
    frame.pitch = 960;
    frame.pixelformat = SCE_DISPLAY_PIXELFORMAT_A8B8G8R8;
    frame.width = 960;
    frame.height = 544;
    if (sceDisplaySetFrameBuf(&frame, SCE_DISPLAY_SETBUF_NEXTFRAME) < 0)
        goto cleanup;
    display_active = 1;
    sceDisplayWaitSetFrameBuf();
    sceCtrlSetSamplingMode(SCE_CTRL_MODE_ANALOG);
    read_button_setting();

    char firmware[32];
    int supported = vitals_install_firmware_supported(firmware, sizeof(firmware));
    unsigned selected = 0;
    int refresh = 1;
    start_release_check();
    for (;;)
    {
        /* Installing is offered only on 3.60 and 3.65; the test works everywhere */
        enum Action actions[8];
        AppMenuItem items[8];
        unsigned count = 0;
        /* The installed files are read when the menu opens and after an operation, not on every
         * button press */
        if (refresh)
        {
            installed = vitals_install_detect();
            /* Another version's plugin counts even when that version installed fewer files */
            outdated = vitals_install_plugin_current() == 0;
            if (vitals_install_plugin_version(installed_version, sizeof(installed_version)) < 0)
                installed_version[0] = '\0';
            debug_level = installed && !outdated ? vitals_install_debug_level() : -1;
            debug_choice = debug_level < 0 ? 0 : debug_level;
            /* The install item starts where the plugin is listed now, so it stays there unless
             * another place is chosen */
            placement_current = vitals_install_placement();
            placement_choice = placement_current < 0 ? VITALS_PLACEMENT_BLOCK : (VitalsPlacement)placement_current;
            refresh = 0;
        }
        int removable = supported && (installed || outdated);
        if (supported)
        {
            if (removable)
            {
                actions[count++] = outdated ? ACTION_UPDATE : ACTION_REINSTALL;
                actions[count++] = ACTION_CERTIFICATES;
            }
            else
                actions[count++] = ACTION_INSTALL;
        }
        actions[count++] = ACTION_TEST;
        /* Only this version's own modules can be switched, so an update comes first */
        if (supported && debug_level >= 0)
            actions[count++] = ACTION_DEBUG;
        actions[count++] = ACTION_CHANGELOG;
        /* Uninstalling sits last, right above Exit, away from the everyday options */
        if (removable)
            actions[count++] = ACTION_UNINSTALL;
        actions[count++] = ACTION_EXIT;
        static char update_description[96], debug_label[48], debug_description[96], install_label[64];
        for (unsigned i = 0; i < count; ++i)
            items[i] = action_items[actions[i]];
        for (unsigned i = 0; i < count; ++i)
            if (actions[i] == ACTION_DEBUG)
            {
                /* What each level is for, shown for the one being chosen */
                static const char *const debug_purposes[VITALS_DEBUG_LEVEL_COUNT] = {
                    "For everyday use: no logs",
                    "For debugging only: shows logs on the console",
                    "For deep analysis only: logs everything on the console and slows things down a lot",
                };
                snprintf(debug_label, sizeof(debug_label), "Debug output: < %s >%s", debug_names[debug_choice],
                         debug_choice == debug_level ? "  (installed)" : "");
                snprintf(debug_description, sizeof(debug_description), "%s", debug_purposes[debug_choice]);
                items[i].label = debug_label;
                items[i].description = debug_description;
            }
        for (unsigned i = 0; i < count; ++i)
            if (actions[i] == ACTION_UPDATE && installed_version[0] != '\0' &&
                strcmp(installed_version, VITALS_VERSION) != 0)
            {
                snprintf(update_description, sizeof(update_description),
                         "Replaces the installed vitals %s with %s", installed_version, VITALS_VERSION);
                items[i].description = update_description;
            }
        /* Left and Right choose where config.txt lists vitals, as on the debug item; the selected
         * install item shows what the choice does */
        for (unsigned i = 0; i < count; ++i)
            if (installs_plugin(actions[i]))
            {
                snprintf(install_label, sizeof(install_label), "%s: < %s >%s", action_items[actions[i]].label,
                         placement_names[placement_choice],
                         (int)placement_choice == placement_current ? "  (current)" : "");
                items[i].label = install_label;
                if (i == selected)
                    items[i].description = placement_purposes[placement_choice];
            }
        if (selected >= count)
            selected = count - 1;
        /* On the debug item, the confirm button only does something once another level is chosen */
        static const AppHint debug_pending[] = {
            {APP_GLYPH_DPAD, APP_GLYPH_STICK, "Choose"},
            {APP_GLYPH_CONFIRM, APP_GLYPH_NONE, "Apply and reboot"},
            {APP_GLYPH_BACK, APP_GLYPH_NONE, "Exit"},
        };
        static const AppHint debug_current[] = {
            {APP_GLYPH_DPAD, APP_GLYPH_STICK, "Choose"},
            {APP_GLYPH_BACK, APP_GLYPH_NONE, "Exit"},
        };
        const AppHint *hints = NULL;
        unsigned hint_count = 0;
        if (actions[selected] == ACTION_DEBUG)
        {
            hints = debug_choice != debug_level ? debug_pending : debug_current;
            hint_count = debug_choice != debug_level ? sizeof(debug_pending) / sizeof(debug_pending[0])
                                                      : sizeof(debug_current) / sizeof(debug_current[0]);
        }
        AppHome home = {installed, outdated, installed_version, debug_level > 0 ? debug_names[debug_level] : NULL,
                        supported, firmware, items, count, selected, hints, hint_count, newer_release()};
        app_draw_home(canvas, &home);
        present();
        unsigned pressed = 0;
        /* The D-pad or either stick moves, with a repeat while held, as on the test screen; a
         * newer release found meanwhile redraws the menu without waiting for a button */
        const char *shown_release = home.latest_release;
        static CheckScrollRepeat vertical, sideways;
        int moves = 0, turns = 0;
        for (;;)
        {
            SceCtrlData pads[64];
            int pad_count = sceCtrlReadBufferPositive(0, pads, 64);
            uint64_t sample_ms = now_ms();
            for (int i = 0; i < pad_count && i < 64; ++i)
            {
                unsigned buttons = pads[i].buttons;
                pressed |= buttons & ~held;
                held = buttons;
                moves += check_scroll_repeat(&vertical,
                                             check_scroll_direction(buttons & SCE_CTRL_UP, buttons & SCE_CTRL_DOWN,
                                                                    pads[i].ly, pads[i].ry),
                                             sample_ms);
                turns += check_scroll_repeat(&sideways,
                                             check_scroll_direction(buttons & SCE_CTRL_LEFT, buttons & SCE_CTRL_RIGHT,
                                                                    pads[i].lx, pads[i].rx),
                                             sample_ms);
            }
            if ((pressed & (confirm_button | back_button)) || moves || turns || newer_release() != shown_release)
                break;
            sceKernelDelayThread(30000);
        }
        if (pressed & back_button)
            break;
        if (moves)
        {
            int target = (int)selected + moves;
            selected = target < 0 ? 0 : target >= (int)count ? count - 1 : (unsigned)target;
        }
        else if (turns)
        {
            /* Left and Right only choose a debug level or a placement; nothing changes until the
             * confirm button */
            if (installs_plugin(actions[selected]))
            {
                VitalsPlacement options[4];
                unsigned option_count = placement_options(options), at = 0;
                while (at + 1 < option_count && options[at] != placement_choice)
                    ++at;
                int target = (int)at + turns;
                if (target < 0)
                    target = 0;
                if (target >= (int)option_count)
                    target = (int)option_count - 1;
                placement_choice = options[target];
            }
            else if (actions[selected] == ACTION_DEBUG)
            {
                int target = debug_choice + turns;
                debug_choice = target < 0 ? 0 : target >= VITALS_DEBUG_LEVEL_COUNT ? VITALS_DEBUG_LEVEL_COUNT - 1 : target;
            }
        }
        else if (pressed & confirm_button)
        {
            enum Action action = actions[selected];
            if (action == ACTION_EXIT)
                break;
            /* The release check never runs alongside the test or an operation; reading the
             * changelog needs no network, so it keeps going */
            if (action != ACTION_CHANGELOG && (action != ACTION_DEBUG || debug_choice != debug_level))
                stop_release_check();
            if (action == ACTION_CHANGELOG)
                run_changelog();
            else if (action == ACTION_TEST)
                run_test();
            else if (action != ACTION_DEBUG || debug_choice != debug_level)
            {
                if (installs_plugin(action))
                    vitals_install_set_placement(placement_choice);
                run_operation(action);
                /* A failed operation returns here; what it changed is read again */
                refresh = 1;
            }
        }
    }
    exit_code = 0;
cleanup:
    if (app_util_ready)
        sceAppUtilShutdown();
    stop_release_check();
    vitals_check_close();
    network_stop();
    if (font_ready)
        check_font_close();
    free(canvas);
    if (display_active)
    {
        if (sceDisplaySetFrameBuf(NULL, SCE_DISPLAY_SETBUF_NEXTFRAME) >= 0 &&
            sceDisplayWaitSetFrameBuf() >= 0)
            sceKernelFreeMemBlock(display);
    }
    else if (display >= 0)
        sceKernelFreeMemBlock(display);
    sceKernelExitProcess(exit_code);
    return exit_code;
}
