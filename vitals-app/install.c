/*
    Original installer code by SKGleba
    All Rights Reserved
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/power.h>
#include <psp2/vshbridge.h>

#include <stdarg.h>

#include "certificates.h"
#include "config_edit.h"
#include "install.h"

/* Progress messages go to the app's screen through install_note (see vitals_install_run) */
#define printf install_note
static VitalsInstallNote g_note;
static void install_note(const char *format, ...) __attribute__((format(__printf__, 1, 2)));
static void install_note(const char *format, ...)
{
    char line[160];
    va_list args;
    va_start(args, format);
    vsnprintf(line, sizeof(line), format, args);
    va_end(args);
    size_t length = strlen(line);
    while (length > 0 && (line[length - 1] == '\n' || line[length - 1] == ' '))
        line[--length] = '\0';
    if (g_note != NULL && length > 0)
        g_note(line);
}

#define COPY_BUFFER_SIZE 0x4000
#define CONFIG_MAX_SIZE 0x100000

static const char vitals_config_block[] =
    "# VITALS\n*KERNEL\nur0:tai/vitals.skprx\n\n";
static const char browser_provider_global[] = "ur0:tai/vitals-native/vitals.suprx";
static const char redirect_list[] = "ux0:data/vitals/redirects.txt";

enum
{
    MODULE_COMPAT,
    MODULE_LIBHTTP,
    MODULE_LIBSSL,
    MODULE_HTTP_PROVIDER,
    MODULE_BROWSER_PROVIDER,
    MODULE_REAUTH,
};

static const char *const new_modules[] = {
    [MODULE_COMPAT] = "vs0:/data/external/vitals/ScePsp2Compat.suprx",
    [MODULE_LIBHTTP] = "vs0:/data/external/vitals/libhttp.suprx",
    [MODULE_LIBSSL] = "vs0:/data/external/vitals/libssl.suprx",
    [MODULE_HTTP_PROVIDER] = "vs0:/data/external/vitals/native/vitals_http.suprx",
    [MODULE_BROWSER_PROVIDER] = "vs0:/data/external/vitals/native/vitals.suprx",
    [MODULE_REAUTH] = "vs0:/data/external/vitals/native/vitals-reauth.suprx",
};

static int path_exists(const char *path)
{
    SceIoStat status;

    return path != NULL && sceIoGetstat(path, &status) >= 0;
}

static int remove_if_exists(const char *path)
{
    if (!path_exists(path))
    {
        return 0;
    }
    return sceIoRemove(path);
}

static int write_all(SceUID descriptor, const void *data, SceSize size)
{
    const uint8_t *cursor = data;
    SceSize remaining = size;

    while (remaining != 0)
    {
        SceSSize written = sceIoWrite(descriptor, cursor, remaining);
        if (written < 0)
        {
            return (int)written;
        }
        if (written == 0)
        {
            return -1;
        }
        cursor += (SceSize)written;
        remaining -= (SceSize)written;
    }
    return 0;
}

static int copy_file(const char *source, const char *destination)
{
    uint8_t *buffer = NULL;
    SceUID source_fd = -1;
    SceUID destination_fd = -1;
    int result = 0;

    source_fd = sceIoOpen(source, SCE_O_RDONLY, 0);
    if (source_fd < 0)
    {
        return source_fd;
    }
    destination_fd = sceIoOpen(
        destination,
        SCE_O_WRONLY | SCE_O_TRUNC | SCE_O_CREAT,
        0777);
    if (destination_fd < 0)
    {
        result = destination_fd;
        goto cleanup;
    }

    buffer = malloc(COPY_BUFFER_SIZE);
    if (buffer == NULL)
    {
        result = -1;
        goto cleanup;
    }

    for (;;)
    {
        SceSSize read_size = sceIoRead(source_fd, buffer, COPY_BUFFER_SIZE);
        if (read_size < 0)
        {
            result = (int)read_size;
            break;
        }
        if (read_size == 0)
        {
            break;
        }
        result = write_all(destination_fd, buffer, (SceSize)read_size);
        if (result < 0)
        {
            break;
        }
    }

cleanup:
    free(buffer);
    if (destination_fd >= 0)
    {
        int close_result = sceIoClose(destination_fd);
        if (result >= 0 && close_result < 0)
        {
            result = close_result;
        }
    }
    if (source_fd >= 0)
    {
        int close_result = sceIoClose(source_fd);
        if (result >= 0 && close_result < 0)
        {
            result = close_result;
        }
    }
    if (result < 0)
    {
        (void)remove_if_exists(destination);
    }
    return result;
}

static int replace_file(const char *source, const char *destination)
{
    char temporary[256];
    char previous[256];
    int temporary_length;
    int previous_length;
    int had_previous;
    int result;

    temporary_length = snprintf(temporary, sizeof(temporary), "%s.tmp", destination);
    previous_length = snprintf(previous, sizeof(previous), "%s.vitals-old", destination);
    if (temporary_length < 0 || (size_t)temporary_length >= sizeof(temporary) ||
        previous_length < 0 || (size_t)previous_length >= sizeof(previous))
    {
        return -1;
    }

    (void)remove_if_exists(temporary);
    (void)remove_if_exists(previous);
    result = copy_file(source, temporary);
    if (result < 0)
    {
        return result;
    }

    had_previous = path_exists(destination);
    if (had_previous)
    {
        result = sceIoRename(destination, previous);
        if (result < 0)
        {
            (void)remove_if_exists(temporary);
            return result;
        }
    }

    result = sceIoRename(temporary, destination);
    if (result < 0)
    {
        if (had_previous)
        {
            (void)sceIoRename(previous, destination);
        }
        (void)remove_if_exists(temporary);
        return result;
    }

    if (had_previous)
    {
        result = remove_if_exists(previous);
    }
    return result;
}

static int read_file(const char *path, char **data, SceSize *size)
{
    SceUID descriptor;
    SceOff file_size;
    char *buffer;
    SceSize total = 0;
    int result = 0;

    if (data == NULL || size == NULL)
    {
        return -1;
    }
    *data = NULL;
    *size = 0;

    descriptor = sceIoOpen(path, SCE_O_RDONLY, 0);
    if (descriptor < 0)
    {
        return descriptor;
    }
    file_size = sceIoLseek(descriptor, 0, SCE_SEEK_END);
    if (file_size < 0 || file_size > CONFIG_MAX_SIZE ||
        sceIoLseek(descriptor, 0, SCE_SEEK_SET) < 0)
    {
        result = file_size < 0 ? (int)file_size : -1;
        (void)sceIoClose(descriptor);
        return result;
    }

    buffer = malloc((size_t)file_size + 1);
    if (buffer == NULL)
    {
        (void)sceIoClose(descriptor);
        return -1;
    }

    while (total < (SceSize)file_size)
    {
        SceSSize read_size = sceIoRead(
            descriptor,
            buffer + total,
            (SceSize)file_size - total);
        if (read_size < 0)
        {
            result = (int)read_size;
            break;
        }
        if (read_size == 0)
        {
            result = -1;
            break;
        }
        total += (SceSize)read_size;
    }

    if (sceIoClose(descriptor) < 0 && result >= 0)
    {
        result = -1;
    }
    if (result < 0)
    {
        free(buffer);
        return result;
    }

    buffer[total] = '\0';
    *data = buffer;
    *size = total;
    return 0;
}

static int plugin_configured(void)
{
    char *config = NULL;
    SceSize config_size = 0;
    int configured = 0;

    if (read_file("ur0:tai/config.txt", &config, &config_size) >= 0)
    {
        (void)config_size;
        configured = strstr(config, vitals_config_block) != NULL;
    }
    free(config);
    return configured;
}

static int install_plugin_config(void)
{
    static const char config_path[] = "ur0:tai/config.txt";
    static const char backup_path[] = "ur0:tai/config_previtals.txt";
    static const char temporary_path[] = "ur0:tai/config_vitals.tmp";
    char *config = NULL;
    SceSize config_size = 0;
    SceUID descriptor;
    int result;

    result = read_file(config_path, &config, &config_size);
    if (result < 0)
    {
        return result;
    }
    if (strstr(config, vitals_config_block) != NULL)
    {
        free(config);
        return 0;
    }

    (void)remove_if_exists(temporary_path);
    descriptor = sceIoOpen(
        temporary_path,
        SCE_O_WRONLY | SCE_O_TRUNC | SCE_O_CREAT,
        0777);
    if (descriptor < 0)
    {
        free(config);
        return descriptor;
    }

    result = write_all(
        descriptor,
        vitals_config_block,
        (SceSize)(sizeof(vitals_config_block) - 1));
    if (result >= 0)
    {
        result = write_all(descriptor, config, config_size);
    }
    if (sceIoClose(descriptor) < 0 && result >= 0)
    {
        result = -1;
    }
    free(config);
    if (result < 0)
    {
        (void)remove_if_exists(temporary_path);
        return result;
    }

    result = remove_if_exists(backup_path);
    if (result < 0)
    {
        (void)remove_if_exists(temporary_path);
        return result;
    }
    result = sceIoRename(config_path, backup_path);
    if (result < 0)
    {
        (void)remove_if_exists(temporary_path);
        return result;
    }
    result = sceIoRename(temporary_path, config_path);
    if (result < 0)
    {
        (void)sceIoRename(backup_path, config_path);
        (void)remove_if_exists(temporary_path);
    }
    return result;
}

/* Replaces ur0:tai/config.txt with first followed by second, through a temporary file and a
 * rollback copy, so an interrupted write never leaves a broken config behind */
static int write_config(const char *first, SceSize first_size, const char *second, SceSize second_size)
{
    static const char config_path[] = "ur0:tai/config.txt";
    static const char temporary_path[] = "ur0:tai/config_vitals.tmp";
    static const char rollback_path[] = "ur0:tai/config_vitals-remove.old";
    SceUID descriptor;
    int result;

    (void)remove_if_exists(temporary_path);
    (void)remove_if_exists(rollback_path);
    descriptor = sceIoOpen(
        temporary_path,
        SCE_O_WRONLY | SCE_O_TRUNC | SCE_O_CREAT,
        0777);
    if (descriptor < 0)
    {
        return descriptor;
    }

    result = write_all(descriptor, first, first_size);
    if (result >= 0)
    {
        result = write_all(descriptor, second, second_size);
    }
    if (sceIoClose(descriptor) < 0 && result >= 0)
    {
        result = -1;
    }
    if (result < 0)
    {
        (void)remove_if_exists(temporary_path);
        return result;
    }

    result = sceIoRename(config_path, rollback_path);
    if (result < 0)
    {
        (void)remove_if_exists(temporary_path);
        return result;
    }
    result = sceIoRename(temporary_path, config_path);
    if (result < 0)
    {
        (void)sceIoRename(rollback_path, config_path);
        (void)remove_if_exists(temporary_path);
        return result;
    }
    return remove_if_exists(rollback_path);
}

static int remove_config_block(const char *block, SceSize block_size)
{
    static const char config_path[] = "ur0:tai/config.txt";
    char *config = NULL;
    char *match;
    SceSize config_size = 0;
    SceSize before_size;
    SceSize after_offset;
    int result;

    if (!path_exists(config_path))
    {
        return 0;
    }
    result = read_file(config_path, &config, &config_size);
    if (result < 0)
    {
        return result;
    }
    match = strstr(config, block);
    if (match == NULL)
    {
        free(config);
        return 0;
    }

    before_size = (SceSize)(match - config);
    after_offset = before_size + block_size;
    result = write_config(config, before_size, config + after_offset, config_size - after_offset);
    free(config);
    return result;
}

static int uninstall_plugin_config(void)
{
    return remove_config_block(vitals_config_block, (SceSize)(sizeof(vitals_config_block) - 1));
}

/* The project was called tls_fixer before; its plugin must not load next to vitals */
static const char legacy_config_block[] =
    "# TLS_FIXER\n*KERNEL\nur0:tai/tls_fixer.skprx\n\n";
static const char *const legacy_files[] = {
    "ur0:tai/tls_fixer.skprx",
    "ur0:tai/tls_fixer-native/tls_fixer.suprx",
    "vs0:/data/external/tls_fixer/ScePsp2Compat.suprx",
    "vs0:/data/external/tls_fixer/libhttp.suprx",
    "vs0:/data/external/tls_fixer/libssl.suprx",
    "vs0:/data/external/tls_fixer/old_dns_fix.suprx",
    "vs0:/data/external/tls_fixer/np_commerce2.suprx",
    "vs0:/data/external/tls_fixer/native/tls_fixer_http.suprx",
    "vs0:/data/external/tls_fixer/native/tls_fixer.suprx",
};
static const char *const legacy_directories[] = {
    "ur0:tai/tls_fixer-native",
    "vs0:/data/external/tls_fixer/native",
    "vs0:/data/external/tls_fixer",
};

static int legacy_install_present(void)
{
    if (path_exists(legacy_files[0]))
        return 1;
    for (unsigned i = 0; i < sizeof(legacy_directories) / sizeof(legacy_directories[0]); ++i)
        if (path_exists(legacy_directories[i]))
            return 1;
    return 0;
}

static int remove_legacy_install(void)
{
    int result;

    if (!legacy_install_present())
        return 0;
    printf("Removing the old tls_fixer installation... \n");
    /* The boot entry goes first, so a partial cleanup never leaves it pointing at nothing */
    result = remove_config_block(legacy_config_block, (SceSize)(sizeof(legacy_config_block) - 1));
    for (unsigned i = 0; result >= 0 && i < sizeof(legacy_files) / sizeof(legacy_files[0]); ++i)
        result = remove_if_exists(legacy_files[i]);
    /* Best effort: an emptied old directory is harmless if something else still lives there */
    for (unsigned i = 0; result >= 0 && i < sizeof(legacy_directories) / sizeof(legacy_directories[0]); ++i)
        if (path_exists(legacy_directories[i]))
            (void)sceIoRmdir(legacy_directories[i]);
    return result;
}

/* vitals is built and tested for 3.65 only; its module checks and the bundled Sony
 * modules target that firmware */
#define SUPPORTED_FIRMWARE UINT32_C(0x03650000)

/* Returns 1 on 3.65; otherwise 0, with the detected firmware (or that it couldn't be read)
 * in description */
int vitals_install_firmware_supported(char *description, size_t size)
{
    SceKernelFwInfo firmware;

    memset(&firmware, 0, sizeof(firmware));
    firmware.size = sizeof(firmware);
    if (_vshSblGetSystemSwVersion(&firmware) < 0)
    {
        snprintf(description, size, "unknown (it could not be read)");
        return 0;
    }
    snprintf(description, size, "%.*s", (int)sizeof(firmware.versionString), firmware.versionString);
    return (firmware.version & UINT32_C(0xffff0000)) == SUPPORTED_FIRMWARE;
}

/* SKGleba's iTLS-Enso, which vitals grew out of
 * Its certificate backup (CA_LIST.cer_old) is kept: it holds Sony's original file, which
 * vitals keeps as its own uninstall backup */
static const char itls_config_block[] = "# ITLS\n*KERNEL\nur0:tai/itls.skprx\n\n";
static const char *const itls_files[] = {
    "ur0:tai/itls.skprx",
    "ur0:tai/itls.suprx",
    "vs0:/data/external/itls/ScePsp2Compat.suprx",
    "vs0:/data/external/itls/libhttp.suprx",
    "vs0:/data/external/itls/libssl.suprx",
    "vs0:/data/external/itls/old_dns_fix.suprx",
    "vs0:/data/external/itls/np_commerce2.suprx",
};

static int itls_install_present(void)
{
    for (unsigned i = 0; i < sizeof(itls_files) / sizeof(itls_files[0]); ++i)
        if (path_exists(itls_files[i]))
            return 1;
    return path_exists("vs0:/data/external/itls");
}

static int remove_itls_install(void)
{
    int result;

    if (!itls_install_present())
        return 0;
    printf("Removing iTLS-Enso, which cannot run alongside vitals... \n");
    /* The boot entry goes first, so a partial cleanup never leaves it pointing at nothing */
    result = remove_config_block(itls_config_block, (SceSize)(sizeof(itls_config_block) - 1));
    for (unsigned i = 0; result >= 0 && i < sizeof(itls_files) / sizeof(itls_files[0]); ++i)
        result = remove_if_exists(itls_files[i]);
    /* Best effort: an emptied directory is harmless if something else still lives there */
    if (result >= 0 && path_exists("vs0:/data/external/itls"))
        (void)sceIoRmdir("vs0:/data/external/itls");
    return result;
}

/* Reiko Asakura's reAuth, which also hooks the module loader for libhttp
 * It has no installer: its kernel plugin is listed by hand in config.txt, under any path */
#define REAUTH_PLUGIN "reAuth.skprx"
#define REAUTH_MAX_PATHS 4
static const char *const reauth_files[] = {
    "ur0:data/reAuth/reAuth.suprx",
    "ur0:data/reAuth/libhttp.suprx",
    "ur0:data/reAuth/libssl.suprx",
};

typedef struct ReauthPaths
{
    char paths[REAUTH_MAX_PATHS][256];
    unsigned count;
} ReauthPaths;

static void remember_reauth_path(void *context, const char *path, size_t length)
{
    ReauthPaths *found = context;
    if (found->count < REAUTH_MAX_PATHS && length < sizeof(found->paths[0]))
    {
        memcpy(found->paths[found->count], path, length);
        found->paths[found->count][length] = '\0';
        ++found->count;
    }
}

static int remove_reauth_install(void)
{
    char *config = NULL, *kept = NULL;
    SceSize config_size = 0;
    size_t kept_size = 0;
    ReauthPaths found = {0};
    int result = 0;

    if (path_exists("ur0:tai/config.txt"))
    {
        result = read_file("ur0:tai/config.txt", &config, &config_size);
        if (result < 0)
            return result;
        kept = malloc((size_t)config_size + 1);
        if (kept == NULL)
        {
            free(config);
            return -1;
        }
        if (vitals_config_remove_plugin(config, config_size, REAUTH_PLUGIN, kept, &kept_size,
                                        remember_reauth_path, &found) == 0)
        {
            free(kept);
            kept = NULL;
        }
        free(config);
    }
    if (kept == NULL && !path_exists("ur0:data/reAuth") && !path_exists("ur0:tai/" REAUTH_PLUGIN))
        return 0;

    printf("Removing reAuth... \n");
    /* The boot entry goes first, so a partial cleanup never leaves it pointing at nothing */
    if (kept != NULL)
    {
        result = write_config(kept, (SceSize)kept_size, "", 0);
        free(kept);
    }
    for (unsigned i = 0; result >= 0 && i < found.count; ++i)
        result = remove_if_exists(found.paths[i]);
    if (result >= 0)
        result = remove_if_exists("ur0:tai/" REAUTH_PLUGIN);
    for (unsigned i = 0; result >= 0 && i < sizeof(reauth_files) / sizeof(reauth_files[0]); ++i)
        result = remove_if_exists(reauth_files[i]);
    /* Best effort: an emptied directory is harmless if something else still lives there */
    if (result >= 0 && path_exists("ur0:data/reAuth"))
        (void)sceIoRmdir("ur0:data/reAuth");
    return result;
}

static int install_plugin(int requested_state)
{
    int result;
    int had_previous = path_exists("ur0:tai/vitals.skprx");
    int removing = requested_state == 1;

    if (removing)
    {
        printf("Removing the vitals plugin... \n");
        result = uninstall_plugin_config();
        if (result < 0)
        {
            return result;
        }
        return remove_if_exists("ur0:tai/vitals.skprx");
    }

    printf("Installing the vitals plugin... \n");
    result = replace_file("app0:vitals.skprx", "ur0:tai/vitals.skprx");
    if (result < 0)
    {
        return result;
    }
    (void)remove_if_exists("ux0:tai/config_previtals.txt");
    result = install_plugin_config();
    if (result < 0 && !had_previous)
    {
        (void)remove_if_exists("ur0:tai/vitals.skprx");
    }
    return result;
}

static int install_compat(int requested_state)
{
    int result = remove_if_exists("vs0:/data/external/webcore/ScePsp2Compat.supr0");
    int removing = requested_state == 1;

    if (result < 0)
        return result;
    if (removing)
    {
        printf("Removing browser compatibility and TLS 1.3 modules... \n");
        result = remove_if_exists(browser_provider_global);
        if (result >= 0)
            result = remove_if_exists(new_modules[MODULE_BROWSER_PROVIDER]);
        if (result >= 0)
            result = remove_if_exists(new_modules[MODULE_COMPAT]);
        return result;
    }

    printf("Installing browser compatibility and TLS 1.3 modules... \n");
    if (!path_exists("ur0:tai/vitals-native"))
    {
        result = sceIoMkdir("ur0:tai/vitals-native", 0777);
        if (result < 0)
            return result;
    }
    if (!path_exists("vs0:/data/external/vitals/native"))
    {
        result = sceIoMkdir("vs0:/data/external/vitals/native", 0777);
        if (result < 0)
            return result;
    }
    result = replace_file("app0:vitals.suprx", browser_provider_global);
    if (result >= 0)
        result = replace_file("app0:vitals.suprx", new_modules[MODULE_BROWSER_PROVIDER]);
    if (result >= 0)
        result = replace_file("app0:compat.suprx", new_modules[MODULE_COMPAT]);
    return result;
}

static int install_http_modules(int requested_state)
{
    int result;
    int removing = requested_state == 1;

    result = remove_if_exists("vs0:sys/external/libhttp.supr0");
    if (result < 0)
    {
        return result;
    }
    if (removing)
    {
        printf("Removing the vitals HTTP, SSL, and TLS 1.3 modules... \n");
        result = remove_if_exists(new_modules[MODULE_HTTP_PROVIDER]);
        if (result >= 0)
        {
            result = remove_if_exists(new_modules[MODULE_REAUTH]);
        }
        if (result >= 0)
        {
            result = remove_if_exists(new_modules[MODULE_LIBHTTP]);
        }
        if (result >= 0)
        {
            result = remove_if_exists(new_modules[MODULE_LIBSSL]);
        }
    }
    else
    {
        printf("Installing the vitals HTTP, SSL, and TLS 1.3 modules... \n");
        if (!path_exists("vs0:/data/external/vitals/native"))
        {
            result = sceIoMkdir("vs0:/data/external/vitals/native", 0777);
            if (result < 0)
                return result;
        }
        result = replace_file("app0:vitals_http.suprx", new_modules[MODULE_HTTP_PROVIDER]);
        /* Sends PSN sign-in and the Store to their new host */
        if (result >= 0)
        {
            result = replace_file("app0:vitals-reauth.suprx", new_modules[MODULE_REAUTH]);
        }
        if (result >= 0)
        {
            result = replace_file("app0:lhttp.suprx", new_modules[MODULE_LIBHTTP]);
        }
        if (result >= 0)
        {
            result = replace_file("app0:lssl.suprx", new_modules[MODULE_LIBSSL]);
        }
        /* A starter host redirect list; an existing one is the user's and is never replaced */
        if (result >= 0 && !path_exists(redirect_list))
        {
            (void)sceIoMkdir("ux0:data/vitals", 0777);
            if (copy_file("app0:redirects.txt", redirect_list) < 0)
                printf("Could not create %s; host redirects stay off.\n", redirect_list);
        }
    }
    return result;
}

static int install_certificates(int requested_state)
{
    static const char certificate_path[] = "vs0:/data/external/cert/CA_LIST.cer";
    static const char backup_path[] = "vs0:/data/external/cert/CA_LIST.cer_old";
    static const char temporary_path[] = "vs0:/data/external/cert/CA_LIST.cer.prepared";
    static const char rollback_path[] = "vs0:/data/external/cert/CA_LIST.cer.vitals-remove";
    int result;
    int removing = requested_state == 1;

    if (removing)
    {
        int had_current;

        printf("Removing vitals CA certs... \n");
        if (!path_exists(backup_path))
        {
            printf("No CA backup; leaving the current certificate file unchanged.\n");
            return 0;
        }
        result = remove_if_exists(rollback_path);
        if (result < 0)
        {
            return result;
        }
        had_current = path_exists(certificate_path);
        if (had_current)
        {
            result = sceIoRename(certificate_path, rollback_path);
            if (result < 0)
            {
                return result;
            }
        }
        result = sceIoRename(backup_path, certificate_path);
        if (result < 0)
        {
            if (had_current)
            {
                (void)sceIoRename(rollback_path, certificate_path);
            }
            return result;
        }
        return had_current ? remove_if_exists(rollback_path) : 0;
    }

    VitalsCertificateBundle bundle;
    printf("Fetching latest curl/Mozilla certificates...\n");
    int online = vitals_install_network_ready();
    result = vitals_prepare_certificates("app0:sony-certs.pem", "app0:mozilla-certs.pem",
                                         online ? VITALS_CA_UPDATE_URL : NULL, 30, &bundle);
    if (result < 0)
    {
        printf("Certificate preparation failed: %s\n", bundle.failure_stage != NULL ? bundle.failure_stage : "invalid input");
        printf("errno=%d crypto=0x%08lX\n", bundle.failure_errno, bundle.failure_crypto_error);
        return result;
    }
    printf(bundle.downloaded ? "Using downloaded Mozilla certificates.\n" : "Download unavailable; using embedded Mozilla certificates.\n");
    printf("Sony: %u, Mozilla: %u, combined: %u certificates.\n",
           (unsigned int)bundle.sony_count, (unsigned int)bundle.mozilla_count,
           (unsigned int)bundle.combined_count);
    (void)remove_if_exists(temporary_path);
    SceUID descriptor = sceIoOpen(temporary_path, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0777);
    result = descriptor < 0 ? descriptor : write_all(descriptor, bundle.data, (SceSize)bundle.size);
    if (descriptor >= 0)
    {
        int close_result = sceIoClose(descriptor);
        if (result >= 0 && close_result < 0)
            result = close_result;
    }
    vitals_free_certificates(&bundle);
    if (result >= 0)
        result = sceIoSync("vs0:", 0);
    if (result < 0)
    {
        (void)remove_if_exists(temporary_path);
        return result;
    }
    if (path_exists(backup_path))
    {
        result = replace_file(temporary_path, certificate_path);
        (void)remove_if_exists(temporary_path);
        return result;
    }
    result = remove_if_exists(backup_path);
    if (result >= 0)
    {
        result = sceIoRename(certificate_path, backup_path);
    }
    if (result >= 0)
    {
        result = sceIoRename(temporary_path, certificate_path);
    }
    if (result < 0)
    {
        if (!path_exists(certificate_path) && path_exists(backup_path))
        {
            (void)sceIoRename(backup_path, certificate_path);
        }
        (void)remove_if_exists(temporary_path);
    }
    return result;
}

static int apply_component(void *context, unsigned component, int removing)
{
    (void)context;
    switch (component)
    {
    case VITALS_COMPONENT_COORDINATOR:
        return install_plugin(removing);
    case VITALS_COMPONENT_BROWSER:
        return install_compat(removing);
    case VITALS_COMPONENT_SYSTEM:
        return install_http_modules(removing);
    case VITALS_COMPONENT_CERTIFICATES:
        return install_certificates(removing);
    default:
        return -1;
    }
}

int vitals_install_detect(void)
{
    /* vitals counts as installed when its plugin, every module and the certificates are in place */
    return !path_exists("vs0:sys/external/libhttp.supr0") &&
           !path_exists("vs0:/data/external/webcore/ScePsp2Compat.supr0") &&
           path_exists("ur0:tai/vitals.skprx") && plugin_configured() &&
           path_exists(new_modules[MODULE_COMPAT]) && path_exists(new_modules[MODULE_BROWSER_PROVIDER]) &&
           path_exists(browser_provider_global) && path_exists(new_modules[MODULE_LIBHTTP]) &&
           path_exists(new_modules[MODULE_LIBSSL]) && path_exists(new_modules[MODULE_HTTP_PROVIDER]) &&
           path_exists(new_modules[MODULE_REAUTH]) &&
           path_exists("vs0:/data/external/cert/CA_LIST.cer_old");
}

int vitals_install_run(enum VitalsOption option, int removing, VitalsInstallNote note)
{
    uint8_t mount_data[0x100] = {0};
    VitalsInstallPlan plan;
    int result;

    g_note = note;
    (void)vshIoUmount(0x300, 0, 0, 0);
    (void)vshIoUmount(0x300, 1, 0, 0);
    result = _vshIoMount(0x300, 0, 2, mount_data);
    if (result >= 0)
        result = remove_legacy_install();
    /* iTLS-Enso hooks the same module loader, so it must not stay installed next to vitals */
    if (result >= 0 && option == VITALS_OPTION_FULL && !removing)
        result = remove_itls_install();
    /* reAuth's redirect is built into vitals, and both would take over the same libhttp loads */
    if (result >= 0 && option == VITALS_OPTION_FULL && !removing)
        result = remove_reauth_install();
    if (result >= 0 && !path_exists("vs0:/data/external/vitals"))
        result = sceIoMkdir("vs0:/data/external/vitals", 0777);
    if (result >= 0)
        result = vitals_plan_option(option, removing, &plan);
    if (result >= 0)
        result = vitals_execute_plan(&plan, apply_component, NULL);
    g_note = NULL;
    return result;
}
