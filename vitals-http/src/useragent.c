#include "vh.h"

#include "diagnostics.h"

#include <string.h>

/* What follows an app's own User-Agent: "libhttp/3.74 (PS Vita)", or the first line of
 * ux0:data/vitals/useragent.txt that isn't empty or a '#' comment, read once per sceHttpInit
 * through the kernel plugin. A line with anything but printable ASCII is ignored, so the file
 * can't add headers of its own */

/* The build sets it (make USER_AGENT=...); the host tests use this one */
#ifndef VH_DEFAULT_SUFFIX
#define VH_DEFAULT_SUFFIX "libhttp/" VH_USER_AGENT_VERSION " (PS Vita)"
#endif
#define VH_SUFFIX_READ 256u

static char g_suffix[VH_SUFFIX_MAX];
static int g_loaded;

/* The first line that holds something, trimmed, into g_suffix; 0 when there is none */
static int pick_line(const char *text, size_t length)
{
    for (size_t at = 0; at < length;) {
        size_t end = at;
        while (end < length && text[end] != '\n')
            ++end;
        size_t start = at, stop = end;
        at = end + 1;
        while (start < stop && (text[start] == ' ' || text[start] == '\t'))
            ++start;
        while (stop > start && (text[stop - 1] == ' ' || text[stop - 1] == '\t' || text[stop - 1] == '\r'))
            --stop;
        if (start == stop || text[start] == '#')
            continue;
        if (stop - start >= sizeof(g_suffix))
            return 0;
        for (size_t i = start; i < stop; ++i)
            if ((unsigned char)text[i] < 0x20 || (unsigned char)text[i] > 0x7e)
                return 0;
        memcpy(g_suffix, text + start, stop - start);
        g_suffix[stop - start] = '\0';
        return 1;
    }
    return 0;
}

/* With the lock held */
const char *vh_user_agent_suffix(void)
{
    if (!g_loaded) {
        char text[VH_SUFFIX_READ];
        g_loaded = 1;
        int read = vh_platform_useragent_read(text, sizeof(text));
        if (read > 0 && pick_line(text, (size_t)read))
            VITALS_LOG("user agent suffix from file: %s", g_suffix);
        else {
            if (read > 0)
                VITALS_LOG("user agent file ignored: no usable line");
            memcpy(g_suffix, VH_DEFAULT_SUFFIX, sizeof(VH_DEFAULT_SUFFIX));
        }
    }
    return g_suffix;
}

void vh_user_agent_clear(void)
{
    g_loaded = 0;
}
