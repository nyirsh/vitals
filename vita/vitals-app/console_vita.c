/* The Vita's side of the shared app (console.h): what the system is, vitals' operations on it
 * (install.c), the Options' switches and the Vita's words */

#include "console.h"

#include "check_vita.h"
#include "dates.h"
#include "install.h"
#include "network.h"
#include "vitals_paths.h"

#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/power.h>
#include <psp2/rtc.h>
#include <stdio.h>
#include <string.h>

/* ---- the system ---- */

static struct {
    int read, supported;
    char text[64];
} info;

static void read_info(void)
{
    if (info.read)
        return;
    char firmware[40];
    info.supported = vitals_install_firmware_supported(firmware, sizeof(firmware));
    snprintf(info.text, sizeof(info.text), "PS Vita %s", firmware);
    info.read = 1;
}

const char *console_system_text(void)
{
    read_info();
    return info.text;
}

int console_supported(void)
{
    read_info();
    return info.supported;
}

int console_unsupported_allowed(void)
{
    return 0;
}

static const ConsoleWords words = {
    .name = "Vita",
    .made_for = "PS Vita 3.60 or 3.65",
    .install_description = "Lets the browser, apps and games connect to modern secure (TLS 1.2 and 1.3) sites",
    .debug_purposes =
        {
            "For everyday use: no logs",
            "For debugging only: shows logs on the console",
            "For deep analysis only: logs everything on the console and slows things down a lot",
        },
};

const ConsoleWords *console_words(void)
{
    return &words;
}

/* ---- vitals on the console ---- */

int vitals_install_detect(void)
{
    /* Another version's plugin counts even when that version installed fewer files, so it can be
     * updated or removed */
    return vitals_install_complete() || vitals_install_plugin_current() >= 0;
}

int vitals_install_read(char *version, size_t size, int *debug_level)
{
    /* An earlier layout's install reads as unknown, so the menu offers to update it */
    if (vitals_install_old_layout() || vitals_install_plugin_version(version, size) < 0)
        return -1;
    /* Modules that match none of this app's builds (another version's) count as release ones */
    int level = vitals_install_debug_level();
    *debug_level = level < 0 ? 0 : level;
    return 0;
}

/* Every operation replaces vitals' modules or the certificate store, so the test's HTTP libraries
 * are released first and nothing of vitals' is in use */

int vitals_install_run(int debug_level, VitalsNote note)
{
    vitals_check_close();
    /* config.txt lists vitals first in the first *KERNEL section, so it loads before the other
     * kernel plugins */
    vitals_install_set_placement(VITALS_PLACEMENT_FIRST);
    int result = vitals_install_apply(VITALS_OPTION_FULL, 0, note);
    /* An install puts the release modules in place; the debug output's builds go over them */
    if (result >= 0 && debug_level > 0)
        result = vitals_install_debug_modules(debug_level, note);
    return result;
}

int vitals_uninstall_run(VitalsNote note)
{
    vitals_check_close();
    return vitals_install_apply(VITALS_OPTION_FULL, 1, note);
}

int vitals_install_set_debug_level(int debug_level, VitalsNote note)
{
    vitals_check_close();
    return vitals_install_debug_modules(debug_level, note);
}

int vitals_update_certificates(VitalsNote note)
{
    vitals_check_close();
    return vitals_install_apply(VITALS_OPTION_CERTIFICATES, 0, note);
}

int vitals_install_network_ready(void)
{
    return network_start(NULL) == 0;
}

void vitals_certificates_date(char *text, size_t size, int *stale)
{
    SceIoStat status;
    SceRtcTick utc, local;
    *stale = 0;
    if (size == 0)
        return;
    text[0] = '\0';
    if (sceIoGetstat(VITALS_CA_MOZILLA_PATH, &status) < 0)
        return;
    /* Files keep their times in UTC; shown in the console's */
    SceDateTime when = status.st_mtime;
    if (sceRtcGetTick(&when, &utc) >= 0 && sceRtcConvertUtcToLocalTime(&utc, &local) >= 0)
        (void)sceRtcSetTick(&when, &local);
    snprintf(text, size, "%04u-%02u-%02u", when.year, when.month, when.day);
    SceDateTime today;
    if (sceRtcGetCurrentClockLocalTime(&today) >= 0)
        *stale = vitals_older_than_three_months(when.year, when.month, when.day, today.year, today.month, today.day);
}

void vitals_reboot(void)
{
    scePowerRequestColdReset();
    for (;;)
        sceKernelDelayThread(1000 * 1000);
}

/* ---- the switches ---- */

/* Each one's .off in ux0:data/vitals/flags, the PS3's four (vitals/switches.h), which the app writes
 * and deletes and the kernel plugin reads */
static const ConsoleSwitchState tls_states[] = {
    {"On", "vitals TLS enabled", CONSOLE_TONE_USUAL, 0},
    {"Off", "Sony TLS enabled", CONSOLE_TONE_RED, 1},
};
/* The host redirects are vitals' HTTP's, so they're one of its states: On (both), Redirects off
 * (vitals' HTTP without them, redirects.off) and Off (Sony's, which has none: http.off) */
static const ConsoleSwitchState http_states[] = {
    {"On", "vitals HTTP and redirects enabled", CONSOLE_TONE_USUAL, 0},
    {"Redirects off", "vitals HTTP enabled, redirects disabled", CONSOLE_TONE_ORANGE, 2},
    {"Off", "Sony HTTP enabled, no redirects", CONSOLE_TONE_RED, 1},
};
static const ConsoleSwitchState dns_states[] = {
    {"On", "vitals DNS rules enabled", CONSOLE_TONE_USUAL, 0},
    {"Off", "vitals DNS rules disabled", CONSOLE_TONE_RED, 1},
};
static const ConsoleSwitch switches[] = {
    {"TLS", {VITALS_TLS_OFF, NULL, NULL}, tls_states, 2},
    {"HTTP", {VITALS_HTTP_OFF, VITALS_REDIRECTS_OFF, NULL}, http_states, 3},
    {"DNS rules", {VITALS_DNS_OFF, NULL, NULL}, dns_states, 2},
};

unsigned console_switch_count(void)
{
    return sizeof(switches) / sizeof(switches[0]);
}

const ConsoleSwitch *console_switch(unsigned index)
{
    return &switches[index];
}

int console_flag_exists(const char *path)
{
    SceIoStat status;
    return sceIoGetstat(path, &status) >= 0;
}

/* Present writes the empty file (and its folders), absent deletes it: 0, or the error */
int console_flag_set(const char *path, int present)
{
    if (!present)
    {
        int rc = sceIoRemove(path);
        return rc >= 0 || !console_flag_exists(path) ? 0 : rc;
    }
    if (console_flag_exists(path))
        return 0;
    (void)sceIoMkdir(VITALS_DIRECTORY, 0777);
    (void)sceIoMkdir(VITALS_FLAGS_DIRECTORY, 0777);
    SceUID file = sceIoOpen(path, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0777);
    if (file < 0)
        return file;
    sceIoClose(file);
    return 0;
}

/* ---- the network, for the app's own downloads ---- */

int console_network_start(int (*stop)(void))
{
    return network_start(stop);
}

/* ---- the rest ---- */

void console_app_file(const char *name, char *path, size_t size)
{
    snprintf(path, size, "app0:%s", name);
}

void console_close(void)
{
    vitals_check_close();
    network_stop();
}
