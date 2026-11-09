/* The Vita's side of the app's log (app_log.h): the file or the debug console, as the Logs option says */

#include "app_log.h"

#include "platform.h"
#include "vitals/switches.h"

#include <psp2/io/fcntl.h>
#include <psp2/kernel/clib.h>

int app_log_to_file(void)
{
    return platform_file_exists(VITALS_LOG_TO_FILE);
}

void app_log_write(const char *line, size_t length)
{
    if (!app_log_to_file())
    {
        sceClibPrintf("vitals-app: %s", line);
        return;
    }
    SceUID file = sceIoOpen(VITALS_APP_LOG, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND, 0777);
    if (file < 0)
        return;
    (void)sceIoWrite(file, line, (SceSize)length);
    (void)sceIoSyncByFd(file, 0);
    (void)sceIoClose(file);
}
