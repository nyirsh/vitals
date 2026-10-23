/* Host test of the installer's file operations: install, reinstall and uninstall on a console
 * mapped onto a temporary folder, the removal of iTLS-Enso, tls_fixer and reAuth, and what
 * config.txt and the certificate store look like when any rename fails */
#include "install.h"
#include "certificates.h"
#include "vita_files.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CONFIG "ur0:tai/config.txt"
#define CA "vs0:/data/external/cert/CA_LIST.cer"
#define CA_BACKUP "vs0:/data/external/cert/CA_LIST.cer_old"
#define REDIRECTS "ux0:data/vitals/redirects.txt"
#define VITALS_BLOCK "# VITALS\n*KERNEL\nur0:tai/vitals.skprx\n\n"
#define SONY_CA "SONY ORIGINAL CERTIFICATES\n"
#define BUNDLE "VITALS MERGED CERTIFICATES\n"
#define ORIGINAL_CONFIG "# taiHEN config\n*KERNEL\nur0:tai/nonpdrm.skprx\n\n*main\nur0:tai/henkaku.suprx\n"

/* ---- Stand-ins for the network and the (separately tested) certificate merge ---- */
int vitals_install_network_ready(void) { return 0; }
int vitals_prepare_certificates(const char *sony_path, const char *mozilla_path, const char *custom_path,
                                const char *url, long timeout_seconds, VitalsCertificateBundle *bundle)
{
    assert(strcmp(sony_path, "app0:sony-certs.pem") == 0 && strcmp(mozilla_path, "app0:mozilla-certs.pem") == 0);
    /* The user's own certificates are always offered to the merge */
    assert(custom_path != NULL && strcmp(custom_path, "ux0:data/vitals/custom-certs.pem") == 0);
    assert(url == NULL && timeout_seconds > 0);
    memset(bundle, 0, sizeof(*bundle));
    bundle->size = strlen(BUNDLE);
    bundle->data = malloc(bundle->size);
    memcpy(bundle->data, BUNDLE, bundle->size);
    bundle->sony_count = bundle->mozilla_count = bundle->combined_count = 1;
    return 0;
}
void vitals_free_certificates(VitalsCertificateBundle *bundle) { free(bundle->data); bundle->data = NULL; }

static void note(const char *line) { (void)line; }

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

/* What vitals installs, and the app0: file each comes from */
static const char *const installed[][2] = {
    {"ur0:tai/vitals.skprx", "app0:vitals.skprx"},
    {"ur0:tai/vitals-native/vitals.suprx", "app0:vitals.suprx"},
    {"vs0:/data/external/vitals/ScePsp2Compat.suprx", "app0:compat.suprx"},
    {"vs0:/data/external/vitals/libhttp.suprx", "app0:lhttp.suprx"},
    {"vs0:/data/external/vitals/libssl.suprx", "app0:lssl.suprx"},
    {"vs0:/data/external/vitals/native/vitals_http.suprx", "app0:vitals_http.suprx"},
    {"vs0:/data/external/vitals/native/vitals.suprx", "app0:vitals.suprx"},
    {"vs0:/data/external/vitals/native/vitals-reauth.suprx", "app0:vitals-reauth.suprx"},
};
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
    const char *app_files[] = {"vitals.skprx", "vitals.suprx", "compat.suprx", "lhttp.suprx", "lssl.suprx",
                               "vitals_http.suprx", "vitals-reauth.suprx", "redirects.txt",
                               "sony-certs.pem", "mozilla-certs.pem"};
    for (size_t i = 0; i < sizeof(app_files) / sizeof(app_files[0]); ++i)
    {
        char path[128], content[128];
        snprintf(path, sizeof(path), "app0:%s", app_files[i]);
        snprintf(content, sizeof(content), "contents of %s\n", app_files[i]);
        put(path, content);
    }
    /* The debug builds of the providers and redirect, one folder per level */
    const char *debug_files[] = {"vitals_http.suprx", "vitals.suprx", "vitals-reauth.suprx"};
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
    assert(is(CA, BUNDLE) && is(CA_BACKUP, SONY_CA));
    assert(exists(REDIRECTS));
    assert(vitals_install_detect() == 1);
    /* Nothing temporary is left behind */
    assert(!exists("ur0:tai/config_vitals.tmp") && !exists("vs0:/data/external/cert/CA_LIST.cer.prepared"));
}

static void expect_uninstalled(void)
{
    assert(is(CONFIG, ORIGINAL_CONFIG));
    for (size_t i = 0; i < INSTALLED_COUNT; ++i)
        assert(!exists(installed[i][0]));
    assert(is(CA, SONY_CA) && !exists(CA_BACKUP));
    assert(vitals_install_detect() == 0);
}

static void test_install_reinstall_uninstall(void)
{
    fresh_console();
    assert(vitals_install_detect() == 0);
    assert(vitals_install_run(VITALS_OPTION_FULL, 0, note) >= 0);
    expect_installed();
    assert(is(REDIRECTS, "contents of redirects.txt\n"));
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
    assert(vitals_install_run(VITALS_OPTION_FULL, 0, note) >= 0);
    assert(vitals_install_plugin_current() == 1);

    /* Reinstalling keeps one config entry, the user's redirect list and Sony's original backup */
    put(REDIRECTS, "my.old.host my.new.host\n");
    assert(vitals_install_run(VITALS_OPTION_FULL, 0, note) >= 0);
    expect_installed();
    assert(is(REDIRECTS, "my.old.host my.new.host\n"));

    /* Updating certificates replaces the store and touches nothing else */
    put(CA, "OLDER VITALS BUNDLE\n");
    assert(vitals_install_run(VITALS_OPTION_CERTIFICATES, 0, note) >= 0);
    expect_installed();

    /* Uninstalling restores taiHEN's config and Sony's certificates, and keeps the user's list */
    assert(vitals_install_run(VITALS_OPTION_FULL, 1, note) >= 0);
    expect_uninstalled();
    assert(is(REDIRECTS, "my.old.host my.new.host\n"));
    /* Without an installed plugin there is nothing to compare */
    assert(vitals_install_plugin_current() < 0);
}

/* The installed providers and redirect are the given level's builds */
static void expect_debug_level(int level)
{
    static const char *const modules[][2] = {
        {"vs0:/data/external/vitals/native/vitals_http.suprx", "vitals_http.suprx"},
        {"vs0:/data/external/vitals/native/vitals.suprx", "vitals.suprx"},
        {"ur0:tai/vitals-native/vitals.suprx", "vitals.suprx"},
        {"vs0:/data/external/vitals/native/vitals-reauth.suprx", "vitals-reauth.suprx"},
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
}

/* Switching debug output replaces only the providers and redirect, in every place they are
 * installed, and a full install puts the release builds back */
static void test_debug_levels(void)
{
    fresh_console();
    assert(vitals_install_debug_level() < 0);
    assert(vitals_install_run(VITALS_OPTION_FULL, 0, note) >= 0);
    expect_debug_level(0);
    for (int level = 2; level >= 0; --level)
    {
        assert(vitals_install_set_debug_level(level, note) >= 0);
        expect_debug_level(level);
        assert(is("ur0:tai/vitals.skprx", "contents of vitals.skprx\n") && is(CONFIG, VITALS_BLOCK ORIGINAL_CONFIG));
    }
    assert(vitals_install_set_debug_level(3, note) < 0 && vitals_install_set_debug_level(-1, note) < 0);
    expect_debug_level(0);
    assert(vitals_install_set_debug_level(1, note) >= 0);
    expect_debug_level(1);
    assert(vitals_install_run(VITALS_OPTION_FULL, 0, note) >= 0);
    expect_installed();
    expect_debug_level(0);
    /* A provider that matches none of the app's builds (another version's) has no level */
    put("vs0:/data/external/vitals/native/vitals_http.suprx", "another version's provider\n");
    assert(vitals_install_debug_level() < 0);
}

static void test_conflicting_installs_are_removed(void)
{
    fresh_console();
    /* iTLS-Enso (its CA backup is Sony's original, which vitals reuses), tls_fixer and reAuth */
    put(CONFIG, "# ITLS\n*KERNEL\nur0:tai/itls.skprx\n\n"
                "# TLS_FIXER\n*KERNEL\nur0:tai/tls_fixer.skprx\n\n"
                ORIGINAL_CONFIG
                "*KERNEL\r\nux0:tai/reAuth.skprx\r\n");
    put(CA, "ITLS BUNDLE\n");
    put(CA_BACKUP, SONY_CA);
    const char *others[] = {"ur0:tai/itls.skprx", "ur0:tai/itls.suprx", "vs0:/data/external/itls/libhttp.suprx",
                            "ur0:tai/tls_fixer.skprx", "vs0:/data/external/tls_fixer/native/tls_fixer.suprx",
                            "ux0:tai/reAuth.skprx", "ur0:data/reAuth/reAuth.suprx", "ur0:data/reAuth/libhttp.suprx"};
    for (size_t i = 0; i < sizeof(others) / sizeof(others[0]); ++i)
        put(others[i], "old plugin\n");

    assert(vitals_install_run(VITALS_OPTION_FULL, 0, note) >= 0);
    for (size_t i = 0; i < sizeof(others) / sizeof(others[0]); ++i)
        assert(!exists(others[i]));
    assert(!exists("ur0:data/reAuth") && !exists("vs0:/data/external/itls") && !exists("vs0:/data/external/tls_fixer"));
    /* Their entries are gone; the rest of the config is kept exactly, CRLF included */
    assert(is(CONFIG, VITALS_BLOCK ORIGINAL_CONFIG "*KERNEL\r\n"));
    assert(is(CA, BUNDLE) && is(CA_BACKUP, SONY_CA));

    assert(vitals_install_run(VITALS_OPTION_FULL, 1, note) >= 0);
    assert(is(CA, SONY_CA) && is(CONFIG, ORIGINAL_CONFIG "*KERNEL\r\n"));
}

static void test_missing_config(void)
{
    /* Without a config.txt, vitals cannot be enabled, and its plugin is not left behind */
    fresh_console();
    assert(unlink(vita_files_path(CONFIG)) == 0);
    assert(vitals_install_run(VITALS_OPTION_FULL, 0, note) < 0);
    assert(!exists("ur0:tai/vitals.skprx") && !exists(CONFIG));
}

/* Every rename an operation makes is made to fail in turn; config.txt and the certificate store
 * must always be either their old or their new version, never missing or partial */
static void test_failed_renames(int removing)
{
    fresh_console();
    if (removing)
        assert(vitals_install_run(VITALS_OPTION_FULL, 0, note) >= 0);
    vita_files_renames = 0;
    assert(vitals_install_run(VITALS_OPTION_FULL, removing, note) >= 0);
    int total = vita_files_renames;
    assert(total > 0);

    for (int failing = 1; failing <= total; ++failing)
    {
        fresh_console();
        if (removing)
            assert(vitals_install_run(VITALS_OPTION_FULL, 0, note) >= 0);
        vita_files_renames = 0;
        vita_files_fail_rename = failing;
        int result = vitals_install_run(VITALS_OPTION_FULL, removing, note);
        vita_files_fail_rename = 0;

        const char *config = get(CONFIG);
        assert(config != NULL);
        int config_old = strcmp(config, removing ? VITALS_BLOCK ORIGINAL_CONFIG : ORIGINAL_CONFIG) == 0;
        int config_new = strcmp(config, removing ? ORIGINAL_CONFIG : VITALS_BLOCK ORIGINAL_CONFIG) == 0;
        assert(config_old || config_new);
        const char *ca = get(CA);
        assert(ca != NULL && (strcmp(ca, SONY_CA) == 0 || strcmp(ca, BUNDLE) == 0));
        /* Sony's original is never lost: it is the store or its backup */
        assert(is(CA, SONY_CA) || is(CA_BACKUP, SONY_CA));
        if (result >= 0)
            assert(config_new);
    }
}

int main(void)
{
    test_install_reinstall_uninstall();
    test_debug_levels();
    test_conflicting_installs_are_removed();
    test_missing_config();
    test_failed_renames(0);
    test_failed_renames(1);

    char command[600];
    snprintf(command, sizeof(command), "rm -rf '%s'", root);
    assert(system(command) == 0);
    puts("installer files: install, reinstall, uninstall, debug levels, conflicting plugins, missing config, "
         "failed renames PASS");
    return 0;
}
