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

/* Where config.txt lists a plugin, as vitals_config_plugin_place tells */
typedef enum
{
    VITALS_CONFIG_NOT_LISTED,
    /* In its own block (the whole text of block, as the installer writes it) */
    VITALS_CONFIG_BLOCK,
    /* The first plugin line of the first section headed section */
    VITALS_CONFIG_FIRST,
    /* The last plugin line of the last section headed section */
    VITALS_CONFIG_LAST,
    /* Listed in such a section, somewhere else */
    VITALS_CONFIG_ELSEWHERE,
} VitalsConfigPlace;

/* Where config (size bytes) lists the plugin at path in a section headed section, as
 * vitals_config_has_plugin finds it; its own block is told first, then the first line, then the
 * last, so a plugin alone in its section counts as first */
VitalsConfigPlace vitals_config_plugin_place(const char *config, size_t size, const char *block, const char *section,
                                             const char *path);
/* Copies config (size bytes) into output with path added on a line of its own: first under the
 * first header equal to section (last 0), or right after the last plugin line of the last such
 * section (last 1), or after its header when it has none. The new line ends as the line before
 * it does, '\n' or "\r\n"; everything else is kept exactly
 * output must hold size + strlen(path) + 5 bytes; it is NUL-terminated and its length stored in
 * *output_size. Returns 0, or -1 when config has no such section */
int vitals_config_insert_plugin(const char *config, size_t size, const char *section, const char *path, int last,
                                char *output, size_t *output_size);

#endif
