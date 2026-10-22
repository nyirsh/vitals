#ifndef VITALS_PATH_H
#define VITALS_PATH_H

#include <stddef.h>

#define VITALS_BROWSER_PROVIDER_FILENAME "vitals.suprx"
#define VITALS_BROWSER_PROVIDER_BOOT_PATH "ur0:tai/vitals-native/vitals.suprx"

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
