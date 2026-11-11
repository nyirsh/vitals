#ifndef VITALS_HOST_SYSMODULE_H
#define VITALS_HOST_SYSMODULE_H

/* On a host the modules are linked in: loading one does nothing */

#define CELL_SYSMODULE_NET 0x0000
#define CELL_SYSMODULE_HTTP 0x0001
#define CELL_SYSMODULE_SSL 0x0003
#define CELL_SYSMODULE_FS 0x000e

static inline int cellSysmoduleLoadModule(unsigned id)
{
	(void)id;
	return 0;
}

#endif
