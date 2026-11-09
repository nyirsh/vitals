/* A module's log line (vitals_log_sink.h): to the kernel plugin, whose file takes it when that's
 * the Logs option, else to the debug console */

#include <psp2/kernel/clib.h>
#include <psp2/kernel/processmgr.h>

#include <stdarg.h>

#include "vitals/log_write.h"

#ifndef VITALS_DEBUG
#define VITALS_DEBUG 0
#endif

#if VITALS_DEBUG >= 1
void vitals_log_user(const char *name, const char *format, ...)
{
    char line[256];
    int used = sceClibSnprintf(line, sizeof(line), "%s: [%u ms] ", name,
                               (unsigned int)((unsigned long long)sceKernelGetSystemTimeWide() / 1000u));
    if (used < 0)
        return;
    va_list arguments;
    va_start(arguments, format);
    int length = sceClibVsnprintf(line + used, sizeof(line) - (size_t)used, format, arguments);
    va_end(arguments);
    if (length < 0)
        return;
    length += used;
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
