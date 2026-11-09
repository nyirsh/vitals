/* The Vita's side of the app's log (app_log.h): the debug console and vitals-app.log */

#include "app_log.h"

#include <psp2/io/fcntl.h>
#include <psp2/kernel/clib.h>

void app_log_write(const char *line, size_t length)
{
    sceClibPrintf("vitals-app: %s", line);
    SceUID file = sceIoOpen(VITALS_APP_LOG, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND, 0777);
    if (file < 0)
        return;
    (void)sceIoWrite(file, line, (SceSize)length);
    (void)sceIoSyncByFd(file, 0);
    (void)sceIoClose(file);
}
