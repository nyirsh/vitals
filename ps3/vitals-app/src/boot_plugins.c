/* boot_plugins.txt's editing, apart from cellFs (install.c reads and writes the file) */

#include "boot_plugins.h"

#include <stdlib.h>
#include <string.h>

int boot_plugins_edit(const char *current, size_t length, const char *plugin, int add, char **edited,
                      size_t *edited_length, int *had)
{
	size_t plugin_length = strlen(plugin), newlines = 0;
	for (size_t i = 0; i < length; ++i)
		newlines += current[i] == '\n';
	int crlf = 0;
	for (size_t i = 0; i + 1 < length && !crlf; ++i)
		crlf = current[i] == '\r' && current[i + 1] == '\n';
	const char *ending = crlf ? "\r\n" : "\n";
	size_t ending_length = strlen(ending);
	/* At most every line kept, each with the longer ending (a last line without one gets one), then
	 * the plugin's line and the NUL */
	size_t capacity = length + (newlines + 1) * 2 + plugin_length + 3;
	char *out = malloc(capacity);
	if (out == NULL)
		return -1;
	size_t used = 0;
	*had = 0;
	for (size_t at = 0; at < length;) {
		size_t end = at;
		while (end < length && current[end] != '\n')
			++end;
		size_t start = at, stop = end;
		while (stop > start && (current[stop - 1] == '\r' || current[stop - 1] == ' ' || current[stop - 1] == '\t'))
			--stop;
		while (start < stop && (current[start] == ' ' || current[start] == '\t'))
			++start;
		int ours = stop - start == plugin_length && memcmp(current + start, plugin, plugin_length) == 0;
		*had |= ours;
		if (!ours && stop > start) {
			memcpy(out + used, current + at, stop - at);
			used += stop - at;
			memcpy(out + used, ending, ending_length);
			used += ending_length;
		}
		at = end + 1;
	}
	if (add) {
		memcpy(out + used, plugin, plugin_length);
		used += plugin_length;
		memcpy(out + used, ending, ending_length);
		used += ending_length;
	}
	out[used] = '\0';
	*edited = out;
	*edited_length = used;
	return 0;
}
