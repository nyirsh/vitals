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
/* vitals' browser engine (ScePsp2Compat), loaded in place of Sony's webcore one */
#define VITALS_COMPAT_PATH VITALS_SYSTEM_DIRECTORY "/ScePsp2Compat.suprx"

#ifdef __cplusplus
extern "C" {
#endif

int vitals_path_equals(const char *path, const char *expected, size_t maximum);
int vitals_path_has_suffix(const char *path, const char *suffix, size_t maximum);
/* A process's request for Sony's browser engine: a path ending in webcore/ScePsp2Compat.suprx,
 * right after a ':' or '/', on a device (the process may see vs0:data/external under a device of its
 * own): 1, or 0 for any other path */
int vitals_browser_engine_request(const char *request);

#ifdef __cplusplus
}
#endif

#endif
