/* Host test of the installer's file operations: install, reinstall and uninstall on a console
 * mapped onto a temporary folder, the removal of iTLS-Enso, tls_fixer and reAuth, and what
 * config.txt and the certificate store look like when any rename fails */
#include "install.h"
#include "ca_update.h"
#include "vita_files.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CONFIG "ur0:tai/config.txt"
/* The system's own store, which vitals leaves as it was, and the backup earlier versions kept of it
 * when they wrote their bundle there; vitals' store is its own */
#define CA "vs0:/data/external/cert/CA_LIST.cer"
#define CA_BACKUP "vs0:/data/external/cert/CA_LIST.cer_old"
#define SONY_STORE "ux0:data/vitals/system/sony-certs.pem"
#define STORE "ux0:data/vitals/system/mozilla-certs.pem"
/* Where an earlier build kept vitals' store in one file */
#define COMBINED_STORE "ux0:data/vitals/system/CA_LIST.cer"
#define EARLIER_BUNDLE "AN EARLIER VERSION'S BUNDLE\n"
#define REDIRECTS "ux0:data/vitals/redirects.txt"
#define DNS_RULES "ux0:data/vitals/dns.txt"
/* A report where earlier versions saved it, and where it goes; another already moved */
#define EARLIER_REPORT "ux0:data/vitals/vitals-testresults-2026-01-02_03-04-05.txt"
#define REPORT "ux0:data/vitals/reports/connection-test-2026-01-02_03-04-05.txt"
#define EARLIER_REPORT_TAKEN "ux0:data/vitals/vitals-testresults-2026-02-02_00-00-00.txt"
#define REPORT_TAKEN "ux0:data/vitals/reports/connection-test-2026-02-02_00-00-00.txt"
#define VITALS_BLOCK "# VITALS\n*KERNEL\nur0:tai/vitals.skprx\n\n"
#define SONY_CA "SONY ORIGINAL CERTIFICATES\n"
#define BUNDLE "VITALS MERGED CERTIFICATES\n"
#define ORIGINAL_CONFIG "# taiHEN config\n*KERNEL\nur0:tai/nonpdrm.skprx\n\n*main\nur0:tai/henkaku.suprx\n"

/* ---- Stand-ins for the network and the (separately tested) certificate update, ca_update.c ---- */
static int network = 1, download_fails, downloads, app_bundles;
int vitals_install_network_ready(void) { return network; }
static int prepared(VitalsCaBundle *bundle)
{
    memset(bundle, 0, sizeof(*bundle));
    bundle->size = strlen(BUNDLE);
    bundle->data = malloc(bundle->size);
    memcpy(bundle->data, BUNDLE, bundle->size);
    return 0;
}
/* The app's log: nothing to keep here */
void app_log_download(const char *line) { (void)line; }
/* curl's bundle, trusting only the app's Mozilla bundle, Sony's list as the app carries it left out */
int vitals_ca_download(const char *trust, size_t trust_length, const char *user_agent, void (*log)(const char *line),
                       const char *sony, size_t sony_length, VitalsCaBundle *out, VitalsNote note)
{
    (void)user_agent, (void)log, (void)note;
    ++downloads;
    assert(trust_length == strlen("contents of mozilla-certs.pem\n") && strcmp(trust, "contents of mozilla-certs.pem\n") == 0);
    assert(sony_length == strlen("contents of sony-certs.pem\n") && strcmp(sony, "contents of sony-certs.pem\n") == 0);
    memset(out, 0, sizeof(*out));
    return download_fails ? -1 : prepared(out);
}
/* The bundle the app carries, when there's no download */
int vitals_ca_prepare(const char *bundle, size_t length, const char *sony, size_t sony_length, VitalsCaBundle *out,
                      VitalsNote note)
{
    (void)length, (void)sony_length, (void)note;
    ++app_bundles;
    assert(strcmp(bundle, "contents of mozilla-certs.pem\n") == 0 && strcmp(sony, "contents of sony-certs.pem\n") == 0);
    return prepared(out);
}
void vitals_ca_free(VitalsCaBundle *bundle) { free(bundle->data); bundle->data = NULL; }

static void note(const char *line) { (void)line; }

static int is(const char *vita_path, const char *expected);
static int exists(const char *vita_path);
/* vitals' store: Sony's list as the app carries it, and the Mozilla certificates it lacks */
static int store_installed(void)
{
    return is(SONY_STORE, "contents of sony-certs.pem\n") && is(STORE, BUNDLE) && !exists(COMBINED_STORE);
}
static int store_absent(void)
{
    return !exists(SONY_STORE) && !exists(STORE) && !exists(COMBINED_STORE);
}

/* ---- Files on the mapped console ---- */
static char root[512];

static void make_directories(const char *vita_directory)
{
    char path[2048];
    snprintf(path, sizeof(path), "%s", vita_files_path(vita_directory));
    for (char *slash = path + strlen(root) + 1; (slash = strchr(slash, '/')) != NULL; ++slash)
    {
        *slash = '\0';
        (void)mkdir(path, 0777);
        *slash = '/';
    }
    (void)mkdir(path, 0777);
}

static void put(const char *vita_path, const char *text)
{
    /* The folder the file goes in: up to the last '/', or the drive itself ("app0:") */
    char directory[512];
    snprintf(directory, sizeof(directory), "%s", vita_path);
    char *end = strrchr(directory, '/');
    if (end == NULL)
        end = strchr(directory, ':') + 1;
    *end = '\0';
    make_directories(directory);
    FILE *file = fopen(vita_files_path(vita_path), "wb");
    assert(file != NULL);
    fputs(text, file);
    fclose(file);
}

static int exists(const char *vita_path)
{
    struct stat info;
    return stat(vita_files_path(vita_path), &info) == 0;
}

/* The whole file, or NULL when missing; the result is valid until the next call */
static const char *get(const char *vita_path)
{
    static char text[65536];
    FILE *file = fopen(vita_files_path(vita_path), "rb");
    if (file == NULL)
        return NULL;
    size_t size = fread(text, 1, sizeof(text) - 1, file);
    fclose(file);
    text[size] = '\0';
    return text;
}

static int is(const char *vita_path, const char *expected)
{
    const char *text = get(vita_path);
    return text != NULL && strcmp(text, expected) == 0;
}

/* Where earlier versions installed their HTTP provider and PSN redirect */
#define OLD_HTTP_PROVIDER "vs0:/data/external/vitals/native/vitals_http.suprx"
#define OLD_REAUTH "vs0:/data/external/vitals/native/vitals-reauth.suprx"

/* What vitals installs, and the app0: file each comes from: the kernel plugin in ur0:tai, its modules
 * in ux0:data/vitals/system */
static const char *const installed[][2] = {
    {"ur0:tai/vitals.skprx", "app0:vitals.skprx"},
    {"ux0:data/vitals/system/vitals.suprx", "app0:vitals.suprx"},
    {"ux0:data/vitals/system/ScePsp2Compat.suprx", "app0:compat.suprx"},
    {"ux0:data/vitals/system/libhttp.suprx", "app0:libhttp.suprx"},
    {"ux0:data/vitals/system/libssl.suprx", "app0:libssl.suprx"},
};

/* Where earlier versions kept those modules, which an install or uninstall takes out */
static const char *const old_layout[] = {
    "vs0:/data/external/vitals/libhttp.suprx",
    "vs0:/data/external/vitals/libssl.suprx",
    "vs0:/data/external/vitals/ScePsp2Compat.suprx",
    "vs0:/data/external/vitals/native/vitals.suprx",
    "ur0:tai/vitals-native/vitals.suprx",
};
#define OLD_LAYOUT_COUNT (sizeof(old_layout) / sizeof(old_layout[0]))
#define INSTALLED_COUNT (sizeof(installed) / sizeof(installed[0]))

/* A fresh console with taiHEN, Sony's certificates and the app's files */
static void fresh_console(void)
{
    if (root[0] != '\0')
    {
        char command[600];
        snprintf(command, sizeof(command), "rm -rf '%s'", root);
        assert(system(command) == 0);
    }
    snprintf(root, sizeof(root), "%s/vitals-install-XXXXXX", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp");
    assert(mkdtemp(root) != NULL);
    vita_files_root(root);
    put(CONFIG, ORIGINAL_CONFIG);
    put(CA, SONY_CA);
    make_directories("ux0:data");
    make_directories("vs0:sys/external");
    const char *app_files[] = {"vitals.skprx", "vitals.suprx", "compat.suprx", "libhttp.suprx", "libssl.suprx",
                               "redirects.txt", "dns.txt",
                               "sony-certs.pem", "mozilla-certs.pem"};
    for (size_t i = 0; i < sizeof(app_files) / sizeof(app_files[0]); ++i)
    {
        char path[128], content[128];
        snprintf(path, sizeof(path), "app0:%s", app_files[i]);
        snprintf(content, sizeof(content), "contents of %s\n", app_files[i]);
        put(path, content);
    }
    /* The debug builds of vitals-http, vitals-ssl, the browser provider and the kernel plugin, one
     * folder per level */
    const char *debug_files[] = {"libhttp.suprx", "libssl.suprx", "vitals.suprx", "vitals.skprx"};
    for (int level = 1; level <= 2; ++level)
        for (size_t i = 0; i < sizeof(debug_files) / sizeof(debug_files[0]); ++i)
        {
            char path[128], content[128];
            snprintf(path, sizeof(path), "app0:debug/%d/%s", level, debug_files[i]);
            snprintf(content, sizeof(content), "level %d build of %s\n", level, debug_files[i]);
            put(path, content);
        }
}

static void expect_installed(void)
{
    assert(is(CONFIG, VITALS_BLOCK ORIGINAL_CONFIG));
    for (size_t i = 0; i < INSTALLED_COUNT; ++i)
    {
        char expected[128];
        snprintf(expected, sizeof(expected), "contents of %s\n", installed[i][1] + 5);
        assert(is(installed[i][0], expected));
    }
    assert(store_installed() && is(CA, SONY_CA) && !exists(CA_BACKUP));
    assert(exists(REDIRECTS) && exists(DNS_RULES));
    assert(vitals_install_complete() == 1 && vitals_install_old_layout() == 0);
    /* Nothing temporary is left behind */
    assert(!exists("ur0:tai/config_vitals.tmp") && !exists(STORE ".prepared") && !exists(STORE ".tmp") &&
           !exists(STORE ".vitals-old") && !exists(SONY_STORE ".tmp") && !exists(SONY_STORE ".vitals-old") &&
           !exists(CA ".prepared") && !exists(CA ".vitals-remove"));
}

static void expect_uninstalled(void)
{
    assert(is(CONFIG, ORIGINAL_CONFIG));
    for (size_t i = 0; i < INSTALLED_COUNT; ++i)
        assert(!exists(installed[i][0]));
    assert(is(CA, SONY_CA) && !exists(CA_BACKUP) && store_absent());
    assert(!exists("ux0:data/vitals/system/installed.txt") && vitals_install_debug_level() == 0);
    assert(!exists("ux0:data/vitals/flags/debug.1") && !exists("ux0:data/vitals/flags/debug.2"));
    assert(vitals_install_complete() == 0);
}

/* An earlier version's layout: its modules on vs0 and in ur0:tai/vitals-native, its bundle the
 * system's store and the system's own kept aside */
static void put_old_layout(void)
{
    make_directories("vs0:/data/external/vitals/native");
    make_directories("ur0:tai/vitals-native");
    for (size_t i = 0; i < OLD_LAYOUT_COUNT; ++i)
        put(old_layout[i], "an earlier version's module\n");
    put(CA, EARLIER_BUNDLE);
    put(CA_BACKUP, SONY_CA);
    put(CA ".prepared", "half of an earlier version's bundle\n");
}

static void expect_no_old_layout(void)
{
    for (size_t i = 0; i < OLD_LAYOUT_COUNT; ++i)
        assert(!exists(old_layout[i]));
    assert(!exists("vs0:/data/external/vitals/native") && !exists("vs0:/data/external/vitals") &&
           !exists("ur0:tai/vitals-native"));
    assert(vitals_install_old_layout() == 0);
}

/* An install over an earlier version's layout moves it: the modules go to ux0:data/vitals/system and
 * the old copies and their folders go; while any is left, vitals doesn't count as installed */
static void test_old_layout_moves(void)
{
    fresh_console();
    put_old_layout();
    assert(vitals_install_old_layout() == 1);
    assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) >= 0);
    expect_installed();
    expect_no_old_layout();
    put("ur0:tai/vitals-native/vitals.suprx", "an earlier version's module\n");
    assert(vitals_install_old_layout() == 1 && vitals_install_complete() == 0);
    /* Uninstalling takes the old copies out too */
    assert(vitals_install_apply(VITALS_OPTION_FULL, 1, note) >= 0);
    expect_uninstalled();
    expect_no_old_layout();
    assert(!exists("ux0:data/vitals/system"));

    /* The bundle alone on the system counts as the old layout; a certificate update puts the
     * system's own back too, whatever it holds (here the user's edit of Sony's), as it was */
    fresh_console();
    assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) >= 0);
    put(CA, EARLIER_BUNDLE);
    put(CA_BACKUP, "SONY CERTIFICATES, AS THE USER EDITED THEM\n");
    assert(vitals_install_old_layout() == 1 && vitals_install_complete() == 0);
    assert(vitals_install_apply(VITALS_OPTION_CERTIFICATES, 0, note) >= 0);
    assert(is(CA, "SONY CERTIFICATES, AS THE USER EDITED THEM\n") && !exists(CA_BACKUP));
    assert(store_installed() && vitals_install_old_layout() == 0 && vitals_install_complete() == 1);
    /* And so does an uninstall */
    put(CA, EARLIER_BUNDLE);
    put(CA_BACKUP, SONY_CA);
    assert(vitals_install_apply(VITALS_OPTION_FULL, 1, note) >= 0);
    expect_uninstalled();
    /* Without a backup, the system's store is left as it is */
    fresh_console();
    put(CA, EARLIER_BUNDLE);
    assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) >= 0);
    assert(is(CA, EARLIER_BUNDLE) && store_installed());
    assert(vitals_install_apply(VITALS_OPTION_FULL, 1, note) >= 0);
    assert(is(CA, EARLIER_BUNDLE) && store_absent());

    /* An earlier build's store in one file: the old layout, which an update takes out */
    fresh_console();
    assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) >= 0);
    put(COMBINED_STORE, "SONY'S, MOZILLA'S AND CUSTOM IN ONE\n");
    put(COMBINED_STORE ".prepared", "half of it\n");
    assert(vitals_install_old_layout() == 1 && vitals_install_complete() == 0);
    assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) >= 0);
    expect_installed();
    assert(!exists(COMBINED_STORE ".prepared"));
    /* The user's own certificates are the kernel's to read: never written or removed */
    put("ux0:data/vitals/custom-certs.pem", "MY CERTIFICATES\n");
    assert(vitals_install_apply(VITALS_OPTION_CERTIFICATES, 0, note) >= 0);
    assert(vitals_install_apply(VITALS_OPTION_FULL, 1, note) >= 0);
    expect_uninstalled();
    assert(is("ux0:data/vitals/custom-certs.pem", "MY CERTIFICATES\n"));
}

static void test_install_reinstall_uninstall(void)
{
    fresh_console();
    assert(vitals_install_complete() == 0);
    /* An earlier version's HTTP provider and PSN redirect, which vitals-http replaces, go on
     * install */
    make_directories("vs0:/data/external/vitals/native");
    put(OLD_HTTP_PROVIDER, "an earlier version's provider\n");
    put(OLD_REAUTH, "an earlier version's redirect\n");
    /* Reports where earlier versions saved them move to reports/ under today's name; one already
     * there under that name is kept, and the earlier one left where it was */
    put(EARLIER_REPORT, "an earlier report\n");
    put(EARLIER_REPORT_TAKEN, "older\n");
    put(REPORT_TAKEN, "already moved\n");
    put("ux0:data/vitals/notes.txt", "the user's\n");
    assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) >= 0);
    expect_installed();
    assert(!exists(OLD_HTTP_PROVIDER) && !exists(OLD_REAUTH));
    assert(!exists(EARLIER_REPORT) && is(REPORT, "an earlier report\n"));
    assert(is(EARLIER_REPORT_TAKEN, "older\n") && is(REPORT_TAKEN, "already moved\n"));
    assert(is("ux0:data/vitals/notes.txt", "the user's\n"));
    assert(is(REDIRECTS, "contents of redirects.txt\n") && is(DNS_RULES, "contents of dns.txt\n"));
    /* While it is there, vitals doesn't count as installed */
    put(OLD_HTTP_PROVIDER, "an earlier version's provider\n");
    assert(vitals_install_complete() == 0);
    assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) >= 0);
    put(OLD_REAUTH, "an earlier version's redirect\n");
    assert(vitals_install_complete() == 0);
    assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) >= 0);
    expect_installed();
    /* The installed plugin is the one the app carries; another version's is told apart, also
     * when only its length differs, and an update puts the app's back */
    assert(vitals_install_plugin_current() == 1);
    /* These stand-in files are not modules, so their version is unknown, never made up */
    char version[16] = "unset";
    assert(vitals_install_plugin_version(version, sizeof(version)) < 0 && strcmp(version, "unset") == 0);
    put("ur0:tai/vitals.skprx", "contents of an older vitals.skprx\n");
    assert(vitals_install_plugin_current() == 0);
    put("ur0:tai/vitals.skprx", "contents of vitals.skprx\nand more\n");
    assert(vitals_install_plugin_current() == 0);
    assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) >= 0);
    assert(vitals_install_plugin_current() == 1);

    /* Reinstalling keeps one config entry, the user's redirect list and Sony's original backup */
    put(REDIRECTS, "my.old.host my.new.host\n");
    put(DNS_RULES, "my.blocked.host block\n");
    assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) >= 0);
    expect_installed();
    assert(is(REDIRECTS, "my.old.host my.new.host\n") && is(DNS_RULES, "my.blocked.host block\n"));

    /* Updating certificates replaces vitals' store with curl's bundle and touches nothing else */
    put(STORE, "OLDER VITALS BUNDLE\n");
    downloads = app_bundles = 0;
    assert(vitals_install_apply(VITALS_OPTION_CERTIFICATES, 0, note) >= 0);
    expect_installed();
    assert(downloads == 1 && app_bundles == 0);
    /* An update that can't download changes nothing: no network, or the download fails */
    put(STORE, "OLDER VITALS BUNDLE\n");
    network = 0;
    assert(vitals_install_apply(VITALS_OPTION_CERTIFICATES, 0, note) < 0);
    assert(is(STORE, "OLDER VITALS BUNDLE\n") && app_bundles == 0);
    network = 1;
    download_fails = 1;
    assert(vitals_install_apply(VITALS_OPTION_CERTIFICATES, 0, note) < 0);
    assert(is(STORE, "OLDER VITALS BUNDLE\n") && downloads == 2 && app_bundles == 0);
    /* An install takes the bundle the app carries instead, with or without a network */
    assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) >= 0);
    expect_installed();
    assert(app_bundles == 1);
    download_fails = 0;
    network = 0;
    assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) >= 0);
    expect_installed();
    assert(app_bundles == 2 && downloads == 3);
    network = 1;

    /* Uninstalling restores taiHEN's config and Sony's certificates, and keeps the user's list */
    assert(vitals_install_apply(VITALS_OPTION_FULL, 1, note) >= 0);
    expect_uninstalled();
    assert(is(REDIRECTS, "my.old.host my.new.host\n") && is(DNS_RULES, "my.blocked.host block\n"));
    /* and the reports, with their folder; an empty folder goes */
    assert(is(REPORT, "an earlier report\n"));
    assert(remove(vita_files_path(REPORT)) == 0 && remove(vita_files_path(REPORT_TAKEN)) == 0 &&
           remove(vita_files_path(EARLIER_REPORT_TAKEN)) == 0);
    assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) >= 0 && exists("ux0:data/vitals/reports"));
    assert(vitals_install_apply(VITALS_OPTION_FULL, 1, note) >= 0 && !exists("ux0:data/vitals/reports"));
    /* Without an installed plugin there is nothing to compare */
    assert(vitals_install_plugin_current() < 0);
}

/* The installed providers and redirect are the given level's builds */
static void expect_debug_level(int level)
{
    static const char *const modules[][2] = {
        {"ux0:data/vitals/system/libhttp.suprx", "libhttp.suprx"},
        {"ux0:data/vitals/system/libssl.suprx", "libssl.suprx"},
        {"ux0:data/vitals/system/vitals.suprx", "vitals.suprx"},
        {"ur0:tai/vitals.skprx", "vitals.skprx"},
    };
    for (size_t i = 0; i < sizeof(modules) / sizeof(modules[0]); ++i)
    {
        char expected[128];
        if (level == 0)
            snprintf(expected, sizeof(expected), "contents of %s\n", modules[i][1]);
        else
            snprintf(expected, sizeof(expected), "level %d build of %s\n", level, modules[i][1]);
        assert(is(modules[i][0], expected));
    }
    assert(vitals_install_debug_level() == level);
    /* A debug build of the plugin is still this app's */
    assert(vitals_install_plugin_current() == 1);
}

/* Switching debug output replaces only vitals-http, vitals-ssl, the browser provider and the kernel
 * plugin, in every place they are installed, and a full install puts the release builds back */
static void test_debug_levels(void)
{
    fresh_console();
    assert(vitals_install_debug_level() == 0);
    assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) >= 0);
    expect_debug_level(0);
    for (int level = 2; level >= 0; --level)
    {
        assert(vitals_install_debug_modules(level, note) >= 0);
        expect_debug_level(level);
        assert(is(CONFIG, VITALS_BLOCK ORIGINAL_CONFIG));
    }
    assert(vitals_install_debug_modules(3, note) < 0 && vitals_install_debug_modules(-1, note) < 0);
    expect_debug_level(0);
    assert(vitals_install_debug_modules(1, note) >= 0);
    expect_debug_level(1);
    assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) >= 0);
    expect_installed();
    expect_debug_level(0);
    /* installed.txt has the release; the level is a marker in flags/, as on the PS3, whatever the
     * modules hold, none for Off */
    assert(is("ux0:data/vitals/system/installed.txt", "version=" VITALS_VERSION "\n"));
    assert(!exists("ux0:data/vitals/flags/debug.1") && !exists("ux0:data/vitals/flags/debug.2"));
    put("ux0:data/vitals/system/libhttp.suprx", "another version's libhttp\n");
    assert(vitals_install_debug_level() == 0);
    assert(vitals_install_debug_modules(2, note) >= 0);
    assert(exists("ux0:data/vitals/flags/debug.2") && !exists("ux0:data/vitals/flags/debug.1"));
    assert(vitals_install_debug_level() == 2);
    assert(vitals_install_debug_modules(1, note) >= 0);
    assert(exists("ux0:data/vitals/flags/debug.1") && !exists("ux0:data/vitals/flags/debug.2"));
    /* An install puts the release modules back, and takes the marker away */
    assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) >= 0);
    assert(vitals_install_debug_level() == 0 && !exists("ux0:data/vitals/flags/debug.1"));
}

static void test_conflicting_installs_are_removed(void)
{
    fresh_console();
    /* iTLS-Enso (its CA backup is what the system had before, which vitals puts back), tls_fixer
     * and reAuth */
    put(CONFIG, "# ITLS\n*KERNEL\nur0:tai/itls.skprx\n\n"
                "# TLS_FIXER\n*KERNEL\nur0:tai/tls_fixer.skprx\n\n"
                ORIGINAL_CONFIG
                "*KERNEL\r\nux0:tai/reAuth.skprx\r\n");
    put(CA, "ITLS BUNDLE\n");
    put(CA_BACKUP, SONY_CA);
    /* iTLS-Enso's full set, including its 3.60 DNS fix and replacement Store library */
    const char *others[] = {"ur0:tai/itls.skprx", "ur0:tai/itls.suprx", "vs0:/data/external/itls/libhttp.suprx",
                            "vs0:/data/external/itls/libssl.suprx", "vs0:/data/external/itls/ScePsp2Compat.suprx",
                            "vs0:/data/external/itls/old_dns_fix.suprx", "vs0:/data/external/itls/np_commerce2.suprx",
                            "ur0:tai/tls_fixer.skprx", "vs0:/data/external/tls_fixer/native/tls_fixer.suprx",
                            "ux0:tai/reAuth.skprx", "ur0:data/reAuth/reAuth.suprx", "ur0:data/reAuth/libhttp.suprx"};
    for (size_t i = 0; i < sizeof(others) / sizeof(others[0]); ++i)
        put(others[i], "old plugin\n");

    assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) >= 0);
    for (size_t i = 0; i < sizeof(others) / sizeof(others[0]); ++i)
        assert(!exists(others[i]));
    assert(!exists("ur0:data/reAuth") && !exists("vs0:/data/external/itls") && !exists("vs0:/data/external/tls_fixer"));
    /* Their entries are gone; the rest of the config is kept exactly, CRLF included */
    assert(is(CONFIG, VITALS_BLOCK ORIGINAL_CONFIG "*KERNEL\r\n"));
    assert(is(CA, SONY_CA) && !exists(CA_BACKUP) && store_installed());

    assert(vitals_install_apply(VITALS_OPTION_FULL, 1, note) >= 0);
    assert(is(CA, SONY_CA) && store_absent() && is(CONFIG, ORIGINAL_CONFIG "*KERNEL\r\n"));
}

/* The plugin's line, wherever the user keeps it under *KERNEL, counts as vitals' entry */
static void test_moved_plugin_line(void)
{
    static const char moved[] = "*KERNEL\nur0:tai/nonpdrm.skprx\nUR0:TAI/vitals.skprx\n\n*main\nur0:tai/henkaku.suprx\n";
    static const char without[] = "*KERNEL\nur0:tai/nonpdrm.skprx\n\n*main\nur0:tai/henkaku.suprx\n";

    /* Moved into the user's own section: installs and reinstalls add no second entry, and vitals
     * counts as installed; uninstalling removes just that line */
    fresh_console();
    put(CONFIG, moved);
    assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) >= 0);
    assert(is(CONFIG, moved) && vitals_install_complete() == 1);
    assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) >= 0);
    assert(is(CONFIG, moved) && vitals_install_complete() == 1);
    assert(vitals_install_apply(VITALS_OPTION_FULL, 1, note) >= 0);
    assert(is(CONFIG, without) && vitals_install_complete() == 0);

    /* Commented out, it doesn't count: the block is added, and uninstalling leaves the comment */
    fresh_console();
    put(CONFIG, "*KERNEL\n# ur0:tai/vitals.skprx\n");
    assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) >= 0);
    assert(is(CONFIG, VITALS_BLOCK "*KERNEL\n# ur0:tai/vitals.skprx\n") && vitals_install_complete() == 1);
    assert(vitals_install_apply(VITALS_OPTION_FULL, 1, note) >= 0);
    assert(is(CONFIG, "*KERNEL\n# ur0:tai/vitals.skprx\n"));

    /* vitals' block and a copy of the line elsewhere: uninstalling removes both */
    fresh_console();
    put(CONFIG, VITALS_BLOCK ORIGINAL_CONFIG "*KERNEL\nur0:tai/vitals.skprx\n");
    assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) >= 0);
    assert(is(CONFIG, VITALS_BLOCK ORIGINAL_CONFIG "*KERNEL\nur0:tai/vitals.skprx\n"));
    assert(vitals_install_apply(VITALS_OPTION_FULL, 1, note) >= 0);
    assert(is(CONFIG, ORIGINAL_CONFIG "*KERNEL\n") && vitals_install_complete() == 0);
}

/* Where vitals is listed is chosen at install, and changing it moves the one line there */
static void test_placements(void)
{
    static const char first[] =
        "# taiHEN config\n*KERNEL\nur0:tai/vitals.skprx\nur0:tai/nonpdrm.skprx\n\n*main\nur0:tai/henkaku.suprx\n";
    static const char last[] =
        "# taiHEN config\n*KERNEL\nur0:tai/nonpdrm.skprx\nur0:tai/vitals.skprx\n\n*main\nur0:tai/henkaku.suprx\n";

    fresh_console();
    assert(vitals_install_placement() < 0);
    vitals_install_set_placement(VITALS_PLACEMENT_FIRST);
    assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) >= 0);
    assert(is(CONFIG, first) && vitals_install_placement() == VITALS_PLACEMENT_FIRST && vitals_install_complete() == 1);
    /* The old config is kept as the backup, as before */
    assert(is("ur0:tai/config_previtals.txt", ORIGINAL_CONFIG));
    /* Kept where it is, or asked for where it already is: nothing changes */
    vitals_install_set_placement(VITALS_PLACEMENT_KEEP);
    assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) >= 0 && is(CONFIG, first));
    vitals_install_set_placement(VITALS_PLACEMENT_FIRST);
    assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) >= 0 && is(CONFIG, first));
    /* Moved between all three places, never listed twice */
    vitals_install_set_placement(VITALS_PLACEMENT_LAST);
    assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) >= 0);
    assert(is(CONFIG, last) && vitals_install_placement() == VITALS_PLACEMENT_LAST);
    vitals_install_set_placement(VITALS_PLACEMENT_BLOCK);
    assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) >= 0);
    assert(is(CONFIG, VITALS_BLOCK ORIGINAL_CONFIG) && vitals_install_placement() == VITALS_PLACEMENT_BLOCK);
    vitals_install_set_placement(VITALS_PLACEMENT_FIRST);
    assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) >= 0 && is(CONFIG, first));
    /* Uninstalling removes it from any of them */
    assert(vitals_install_apply(VITALS_OPTION_FULL, 1, note) >= 0);
    assert(is(CONFIG, ORIGINAL_CONFIG) && vitals_install_placement() < 0);
    vitals_install_set_placement(VITALS_PLACEMENT_LAST);
    assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) >= 0 && is(CONFIG, last));
    assert(vitals_install_apply(VITALS_OPTION_FULL, 1, note) >= 0 && is(CONFIG, ORIGINAL_CONFIG));

    /* Without a *KERNEL section of the user's, first and last fall back to vitals' own block */
    static const char no_kernel[] = "*main\nur0:tai/henkaku.suprx\n";
    for (int placement = VITALS_PLACEMENT_FIRST; placement <= VITALS_PLACEMENT_LAST; ++placement)
    {
        fresh_console();
        put(CONFIG, no_kernel);
        vitals_install_set_placement((VitalsPlacement)placement);
        assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) >= 0);
        assert(is(CONFIG, VITALS_BLOCK "*main\nur0:tai/henkaku.suprx\n"));
        assert(vitals_install_placement() == VITALS_PLACEMENT_BLOCK);
    }

    /* Moved by hand elsewhere: told apart, kept by default, and movable to a place of its own */
    static const char between[] = "*KERNEL\nur0:tai/a.skprx\nur0:tai/vitals.skprx\nur0:tai/b.skprx\n";
    fresh_console();
    put(CONFIG, between);
    assert(vitals_install_placement() == VITALS_PLACEMENT_KEEP);
    vitals_install_set_placement(VITALS_PLACEMENT_KEEP);
    assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) >= 0 && is(CONFIG, between));
    vitals_install_set_placement(VITALS_PLACEMENT_LAST);
    assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) >= 0);
    assert(is(CONFIG, "*KERNEL\nur0:tai/a.skprx\nur0:tai/b.skprx\nur0:tai/vitals.skprx\n"));
    vitals_install_set_placement(VITALS_PLACEMENT_KEEP);
}

static void test_missing_config(void)
{
    /* Without a config.txt, vitals cannot be enabled, and its plugin is not left behind */
    fresh_console();
    assert(unlink(vita_files_path(CONFIG)) == 0);
    assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) < 0);
    assert(!exists("ur0:tai/vitals.skprx") && !exists(CONFIG));
}

/* A console for test_failed_renames: vitals installed when removing; when migrating, an earlier
 * version's bundle over the system's store, the system's own beside it */
static void failed_renames_console(int removing, int migrating)
{
    fresh_console();
    if (removing)
        assert(vitals_install_apply(VITALS_OPTION_FULL, 0, note) >= 0);
    if (migrating)
    {
        put(CA, EARLIER_BUNDLE);
        put(CA_BACKUP, SONY_CA);
    }
}

/* Every rename an operation makes is made to fail in turn; config.txt and both certificate stores
 * must always be either their old or their new version, never missing or partial */
static void test_failed_renames(int removing, int migrating)
{
    failed_renames_console(removing, migrating);
    vita_files_renames = 0;
    assert(vitals_install_apply(VITALS_OPTION_FULL, removing, note) >= 0);
    int total = vita_files_renames;
    assert(total > 0);

    for (int failing = 1; failing <= total; ++failing)
    {
        failed_renames_console(removing, migrating);
        vita_files_renames = 0;
        vita_files_fail_rename = failing;
        int result = vitals_install_apply(VITALS_OPTION_FULL, removing, note);
        vita_files_fail_rename = 0;

        const char *config = get(CONFIG);
        assert(config != NULL);
        int config_old = strcmp(config, removing ? VITALS_BLOCK ORIGINAL_CONFIG : ORIGINAL_CONFIG) == 0;
        int config_new = strcmp(config, removing ? ORIGINAL_CONFIG : VITALS_BLOCK ORIGINAL_CONFIG) == 0;
        assert(config_old || config_new);
        /* The system's store is what it was, or the backup put back; what it had before is never
         * lost: it is the store or the backup */
        const char *ca = get(CA);
        assert(ca != NULL && (strcmp(ca, SONY_CA) == 0 || (migrating && strcmp(ca, EARLIER_BUNDLE) == 0)));
        assert(is(CA, SONY_CA) || is(CA_BACKUP, SONY_CA));
        /* vitals' two files are each whole, or not there */
        const char *store = get(STORE);
        assert(store == NULL || strcmp(store, BUNDLE) == 0);
        const char *sony = get(SONY_STORE);
        assert(sony == NULL || strcmp(sony, "contents of sony-certs.pem\n") == 0);
        if (result >= 0)
        {
            assert(config_new && is(CA, SONY_CA) && !exists(CA_BACKUP));
            assert(removing ? store_absent() : store_installed());
        }
    }
}

/* Installing is offered on 3.60 and 3.65 only */
static void test_supported_firmware(void)
{
    static const struct
    {
        unsigned int version;
        int supported;
    } firmware[] = {{0x03600000u, 1}, {0x03650000u, 1}, {0x03600011u, 1}, {0x03610000u, 0},
                    {0x03630000u, 0}, {0x03680000u, 0}, {0x03740000u, 0}, {0x03550000u, 0}};
    for (size_t i = 0; i < sizeof(firmware) / sizeof(firmware[0]); ++i)
    {
        char description[32];
        vita_files_firmware = firmware[i].version;
        assert(vitals_install_firmware_supported(description, sizeof(description)) == firmware[i].supported);
        assert(description[0] != '\0');
    }
    vita_files_firmware = 0x03650000u;
}

int main(void)
{
    test_supported_firmware();
    test_install_reinstall_uninstall();
    test_old_layout_moves();
    test_debug_levels();
    test_conflicting_installs_are_removed();
    test_moved_plugin_line();
    test_placements();
    test_missing_config();
    for (int removing = 0; removing <= 1; ++removing)
        for (int migrating = 0; migrating <= 1; ++migrating)
            test_failed_renames(removing, migrating);

    char command[600];
    snprintf(command, sizeof(command), "rm -rf '%s'", root);
    assert(system(command) == 0);
    puts("installer files: install, reinstall, uninstall, debug levels, conflicting plugins, moved plugin line, "
         "placements, missing config, failed renames PASS");
    return 0;
}
