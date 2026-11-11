/* The PS3's files for the shared app (platform.h), on cellFs */

#include "platform.h"

#include <cell/cell_fs.h>
#include <stdint.h>
#include <string.h>

long platform_read_file(const char *path, char *data, size_t capacity)
{
	int fd;
	if (cellFsOpen(path, CELL_FS_O_RDONLY, &fd, NULL, 0) != CELL_FS_SUCCEEDED)
		return -1;
	uint64_t length = 0, read = 0;
	while (length < capacity && cellFsRead(fd, data + length, capacity - length, &read) == CELL_FS_SUCCEEDED && read != 0)
		length += read;
	cellFsClose(fd);
	return (long)length;
}

int platform_write_file(const char *path, const void *data, size_t length)
{
	int fd;
	if (cellFsOpen(path, CELL_FS_O_WRONLY | CELL_FS_O_CREAT | CELL_FS_O_TRUNC, &fd, NULL, 0) != CELL_FS_SUCCEEDED)
		return -1;
	uint64_t written = 0;
	int rc = cellFsWrite(fd, data, length, &written);
	if (cellFsClose(fd) != CELL_FS_SUCCEEDED)
		rc = -1;
	return rc == CELL_FS_SUCCEEDED && written == length ? 0 : -1;
}

int platform_file_exists(const char *path)
{
	CellFsStat status;
	return cellFsStat(path, &status) == CELL_FS_SUCCEEDED;
}

int platform_make_folder(const char *path)
{
	return cellFsMkdir(path, CELL_FS_S_IFDIR | 0777) == CELL_FS_SUCCEEDED || platform_file_exists(path) ? 0 : -1;
}

int platform_remove_file(const char *path)
{
	return cellFsUnlink(path) == CELL_FS_SUCCEEDED ? 0 : -1;
}

int platform_rename(const char *from, const char *to)
{
	return cellFsRename(from, to) == CELL_FS_SUCCEEDED ? 0 : -1;
}

int platform_list_folder(const char *path, void (*each)(void *context, const char *name), void *context)
{
	int fd;
	if (cellFsOpendir(path, &fd) != CELL_FS_SUCCEEDED)
		return -1;
	CellFsDirent entry;
	uint64_t read = 0;
	while (cellFsReaddir(fd, &entry, &read) == CELL_FS_SUCCEEDED && read != 0)
		if (strcmp(entry.d_name, ".") != 0 && strcmp(entry.d_name, "..") != 0)
			each(context, entry.d_name);
	cellFsClosedir(fd);
	return 0;
}
