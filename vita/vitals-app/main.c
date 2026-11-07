/* vitals on the Vita: the shared app (shared/app/app.c), over the Vita's console_vita.c and
 * platform_vita.c */

#include "app.h"

#include <psp2/kernel/processmgr.h>

/* The glyph cache (shared/app/font.c), the screen's canvas, the documents and the certificate
 * download (curl and OpenSSL) */
unsigned int _newlib_heap_size_user = 32u * 1024u * 1024u;

int main(void)
{
    int exit_code = app_main(0);
    sceKernelExitProcess(exit_code);
    return exit_code;
}
