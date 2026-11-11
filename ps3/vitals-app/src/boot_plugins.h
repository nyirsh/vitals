#ifndef VITALS_APP_BOOT_PLUGINS_H
#define VITALS_APP_BOOT_PLUGINS_H

#include <stddef.h>

/* boot_plugins.txt edited, as text, so the host tests can run it (vitals-app/tests): current's lines
 * (length bytes; NULL for a missing file) without plugin's, then plugin's at the end when add. Lines
 * are trimmed and empty ones dropped; the line ending is current's ("\r\n" when it has any, else
 * "\n"). *edited is malloc'd, NUL-terminated, *edited_length its length; *had says whether current
 * listed plugin. 0, or -1 without memory */
int boot_plugins_edit(const char *current, size_t length, const char *plugin, int add, char **edited,
                      size_t *edited_length, int *had);

#endif
