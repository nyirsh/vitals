/* The shared app's log (app_log.h): the Vita's app keeps none, so nothing is written */

#include "app_log.h"

void app_log_start(void)
{
}

void app_log(const char *format, ...)
{
    (void)format;
}
