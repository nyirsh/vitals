#ifndef VITALS_HOOK_GUARD_H
#define VITALS_HOOK_GUARD_H

#include <stddef.h>
#include <psp2kern/types.h>

#define VITALS_MODULEMGR_LOAD_OFFSET ((size_t)0x21ec)
#define VITALS_MODULEMGR_START_OFFSET ((size_t)0x286c)

int vitals_validate_loader_hook(SceUID module_id);

#endif
