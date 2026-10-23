#include "check.h"
#include "font.h"
#include "input.h"
#include "install.h"
#include "ui.h"
#include <psp2/ctrl.h>
#include <psp2/display.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/sysmem.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/net/net.h>
#include <psp2/net/netctl.h>
#include <psp2/power.h>
#include <psp2/sysmodule.h>
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

static uint64_t now_ms(void) { return sceKernelGetSystemTimeWide() / 1000; }

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

/* The network is started once and shared by the certificate download and the test */
static void *net_memory;
static int net_loaded, net_ready, ctl_ready, net_result = 1;
static int network_start(void)
{
    if (net_result <= 0)
        return net_result;
    int rc = 0;
    if (sceSysmoduleIsLoaded(SCE_SYSMODULE_NET) != SCE_SYSMODULE_LOADED)
    {
        rc = sceSysmoduleLoadModule(SCE_SYSMODULE_NET);
        if (rc < 0)
            goto done;
        net_loaded = 1;
    }
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
    rc = sceNetCtlInit();
    if (rc < 0)
        goto done;
    ctl_ready = 1;
    uint64_t deadline = now_ms() + 10000;
    for (;;)
    {
        int state = 0;
        rc = sceNetCtlInetGetState(&state);
        if (rc < 0 || state == SCE_NETCTL_STATE_CONNECTED)
            break;
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
    };
    char status[96];
    for (unsigned i = 0; i < TASK_MAX_LINES; ++i)
        task_line_pointers[i] = task_lines[i];
    task = (AppTask){.title = titles[action], .lines = task_line_pointers, .state = CHECK_RUNNING, .status = "Working..."};
    draw_task();
    /* The test's HTTP libraries are released first, so no vitals module is in use */
    vitals_check_close();
    int result = vitals_install_run(action == ACTION_CERTIFICATES ? VITALS_OPTION_CERTIFICATES
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
    while (!(read_presses() & SCE_CTRL_CIRCLE))
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
        if (pressed & SCE_CTRL_CIRCLE)
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
            page = (int)((page + page_presses) % 3);
            scroll = 0;
        }
        scroll = check_scroll_move(scroll, page == 0 ? scroll_steps : 0,
                                   view.handshake.cipher_count, CHECK_VISIBLE_CIPHERS);
        if (ready && !busy && !leaving && (pressed & SCE_CTRL_CROSS))
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
    vitals_check_close();
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

    char firmware[32];
    int supported = vitals_install_firmware_supported(firmware, sizeof(firmware));
    unsigned selected = 0;
    for (;;)
    {
        /* Installing is offered only on 3.65; the test works everywhere */
        enum Action actions[6];
        AppMenuItem items[6];
        unsigned count = 0;
        installed = vitals_install_detect();
        /* Another version's plugin counts even when that version installed fewer files */
        outdated = vitals_install_plugin_current() == 0;
        if (vitals_install_plugin_version(installed_version, sizeof(installed_version)) < 0)
            installed_version[0] = '\0';
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
        /* Uninstalling sits last, right above Exit, away from the everyday options */
        if (removable)
            actions[count++] = ACTION_UNINSTALL;
        actions[count++] = ACTION_EXIT;
        static char update_description[96];
        for (unsigned i = 0; i < count; ++i)
            items[i] = action_items[actions[i]];
        for (unsigned i = 0; i < count; ++i)
            if (actions[i] == ACTION_UPDATE && installed_version[0] != '\0' &&
                strcmp(installed_version, VITALS_VERSION) != 0)
            {
                snprintf(update_description, sizeof(update_description),
                         "Replaces the installed vitals %s with %s", installed_version, VITALS_VERSION);
                items[i].description = update_description;
            }
        if (selected >= count)
            selected = count - 1;
        AppHome home = {installed, outdated, installed_version, supported, firmware, items, count, selected};
        app_draw_home(canvas, &home);
        present();
        unsigned pressed = 0;
        while (!(pressed = read_presses() & (SCE_CTRL_UP | SCE_CTRL_DOWN | SCE_CTRL_CROSS | SCE_CTRL_CIRCLE)))
            sceKernelDelayThread(30000);
        if (pressed & SCE_CTRL_CIRCLE)
            break;
        if (pressed & SCE_CTRL_UP && selected > 0)
            --selected;
        else if (pressed & SCE_CTRL_DOWN && selected + 1 < count)
            ++selected;
        else if (pressed & SCE_CTRL_CROSS)
        {
            enum Action action = actions[selected];
            if (action == ACTION_EXIT)
                break;
            if (action == ACTION_TEST)
                run_test();
            else
                run_operation(action);
        }
    }
    exit_code = 0;
cleanup:
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
