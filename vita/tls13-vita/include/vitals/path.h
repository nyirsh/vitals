#ifndef VITALS_PATH_H
#define VITALS_PATH_H

#include <stddef.h>

#define VITALS_BROWSER_PROVIDER_FILENAME "vitals.suprx"
/* vitals' modules, in ux0:data/vitals as the PS3's are in /dev_hdd0/vitals/system: the kernel plugin
 * loads them in Sony's place, and the module manager reads them past every app's sandbox */
#define VITALS_SYSTEM_DIRECTORY "ux0:data/vitals/system"
/* The browser provider, which the kernel plugin injects after vitals' browser engine starts */
#define VITALS_BROWSER_PROVIDER_BOOT_PATH VITALS_SYSTEM_DIRECTORY "/" VITALS_BROWSER_PROVIDER_FILENAME
/* vitals-http, the system's libhttp once installed */
#define VITALS_LIBHTTP_PATH VITALS_SYSTEM_DIRECTORY "/libhttp.suprx"
/* vitals-ssl, the system's libssl once installed; the browser provider's TLS too */
#define VITALS_LIBSSL_PATH VITALS_SYSTEM_DIRECTORY "/libssl.suprx"
/* vitals' browser engine stays next to Sony's: its swap keeps the folder the process names it by
 * (vitals_browser_replacement_path), so a process that sees vs0:data/external under another name
 * finds it there too */
#define VITALS_COMPAT_PATH "vs0:/data/external/vitals/ScePsp2Compat.suprx"

#ifdef __cplusplus
extern "C" {
#endif

int vitals_path_equals(const char *path, const char *expected, size_t maximum);
int vitals_path_has_suffix(const char *path, const char *suffix, size_t maximum);
int vitals_browser_replacement_path(const char *path, char *output, size_t capacity);
int vitals_browser_provider_path(const char *replacement, char *output, size_t capacity);
int vitals_browser_module_path(const char *provider, char *output, size_t capacity);
int vitals_browser_ca_path(const char *replacement, char *output, size_t capacity);

#ifdef __cplusplus
}
#endif

#endif
