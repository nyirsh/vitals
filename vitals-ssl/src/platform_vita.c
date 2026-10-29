#include "diagnostics.h"

#include <psp2/kernel/modulemgr.h>

/* As Sony's libssl, which says it was built with SDK 3.73; vita-elf-create exports this symbol as
 * the module's SDK version */
const unsigned int module_sdk_version __attribute__((used)) = 0x03730011;

int module_start(SceSize args, void *argp)
{
    (void)args, (void)argp;
    VITALS_LOG("started (skeleton: every export fails)");
    return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize args, void *argp)
{
    (void)args, (void)argp;
    return SCE_KERNEL_STOP_SUCCESS;
}

int _start(SceSize args, void *argp) __attribute__((weak, alias("module_start")));
