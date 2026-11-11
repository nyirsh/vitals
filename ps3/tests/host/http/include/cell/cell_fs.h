#ifndef VITALS_HOST_CELL_FS_H
#define VITALS_HOST_CELL_FS_H

/* The cellFs calls the probe makes, on the host's files (probe_host.c): /dev_hdd0 is the directory
 * VITALS_PROBE_HDD names */

#include <stdint.h>

#define CELL_FS_SUCCEEDED 0
#define CELL_FS_O_RDONLY 000000
#define CELL_FS_O_WRONLY 000001
#define CELL_FS_O_CREAT 000100
#define CELL_FS_O_TRUNC 001000

typedef struct CellFsStat {
	uint64_t st_size;
} CellFsStat;

int cellFsOpen(const char *path, int flags, int *fd, const void *argument, uint64_t size);
int cellFsRead(int fd, void *data, uint64_t size, uint64_t *read);
int cellFsWrite(int fd, const void *data, uint64_t size, uint64_t *written);
int cellFsClose(int fd);
int cellFsFstat(int fd, CellFsStat *status);

#endif
