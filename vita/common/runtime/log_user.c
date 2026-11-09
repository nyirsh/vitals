/* A module's log line (vitals_log_sink.h): to the kernel plugin, whose file takes it when that's
 * the Logs option, else to the debug console */

#include <psp2/kernel/clib.h>

#include <stdarg.h>

#include "vitals/log_write.h"

#ifndef VITALS_DEBUG
#define VITALS_DEBUG 0
#endif

#if VITALS_DEBUG >= 1
void vitals_log_user(const char *format, ...)
{
    char line[256];
    va_list arguments;
    va_start(arguments, format);
    int length = sceClibVsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length < 0)
        return;
    if ((unsigned int)length >= sizeof(line))
    {
        /* Cut, still a line */
        length = sizeof(line) - 1;
        line[length - 1] = '\n';
    }
    if (vitals_log_write(line, (unsigned int)length) != 1)
        sceClibPrintf("%s", line);
}
#endif
