#ifndef VITALS_APP_CONFIG_EDIT_H
#define VITALS_APP_CONFIG_EDIT_H

#include <stddef.h>

/* Called for each removed plugin line with its path (not NUL-terminated) */
typedef void (*VitalsConfigFound)(void *context, const char *path, size_t length);

/* Copies taiHEN's config.txt (config, size bytes) into output without the plugin lines whose
 * file name is name, compared without case
 * Sections, comments, other plugins and line endings are kept exactly
 * output must hold size + 1 bytes; it is NUL-terminated and its length stored in *output_size
 * Returns the number of lines removed */
size_t vitals_config_remove_plugin(const char *config, size_t size, const char *name, char *output,
                                   size_t *output_size, VitalsConfigFound found, void *context);
/* 1 when taiHEN's config.txt (config, size bytes) lists the plugin at path, on a line of its own,
 * in a section whose header is section (such as "*KERNEL"); wherever the section is, and however
 * often its header repeats. Both are compared without case and spaces around them are ignored
 * Commented lines don't count, and lines before the first header belong to no section */
int vitals_config_has_plugin(const char *config, size_t size, const char *section, const char *path);

#endif
