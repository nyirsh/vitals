/* Stand-ins for the Vita file functions the installer uses, backed by a host directory */
#define _POSIX_C_SOURCE 200809L
#include "vita_files.h"

#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/vshbridge.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define FAILED ((int)0x80010002)

static char root[1024];
int vita_files_fail_rename, vita_files_renames;
unsigned int vita_files_firmware = 0x03650000u;

void vita_files_root(const char *directory)
{
    snprintf(root, sizeof(root), "%s", directory);
    vita_files_fail_rename = vita_files_renames = 0;
}

/* "vs0:/data/x" and "vs0:data/x" both become <root>/vs0/data/x */
static const char *map(const char *vita_path, char *host, size_t size)
{
    const char *colon = strchr(vita_path, ':');
    if (colon == NULL)
        return NULL;
    const char *rest = colon + 1;
    while (*rest == '/')
        ++rest;
    snprintf(host, size, "%s/%.*s/%s", root, (int)(colon - vita_path), vita_path, rest);
    size_t length = strlen(host);
    if (length > 0 && host[length - 1] == '/')
        host[length - 1] = '\0';
    return host;
}

const char *vita_files_path(const char *vita_path)
{
    static char host[2048];
    return map(vita_path, host, sizeof(host));
}

SceUID sceIoOpen(const char *path, int flags, int mode)
{
    char host[2048];
    int host_flags = (flags & SCE_O_RDWR) == SCE_O_RDWR ? O_RDWR : (flags & SCE_O_WRONLY) ? O_WRONLY : O_RDONLY;
    if (flags & SCE_O_CREAT)
        host_flags |= O_CREAT;
    if (flags & SCE_O_TRUNC)
        host_flags |= O_TRUNC;
    if (flags & SCE_O_APPEND)
        host_flags |= O_APPEND;
    if (map(path, host, sizeof(host)) == NULL)
        return FAILED;
    int fd = open(host, host_flags, mode & 0777);
    return fd < 0 ? FAILED : fd;
}

int sceIoClose(SceUID fd) { return close(fd) == 0 ? 0 : FAILED; }

SceSSize sceIoRead(SceUID fd, void *data, SceSize size)
{
    ssize_t count = read(fd, data, size);
    return count < 0 ? FAILED : (SceSSize)count;
}

SceSSize sceIoWrite(SceUID fd, const void *data, SceSize size)
{
    ssize_t count = write(fd, data, size);
    return count < 0 ? FAILED : (SceSSize)count;
}

SceOff sceIoLseek(SceUID fd, SceOff offset, int whence)
{
    off_t result = lseek(fd, (off_t)offset, whence == SCE_SEEK_END ? SEEK_END : whence == SCE_SEEK_CUR ? SEEK_CUR : SEEK_SET);
    return result < 0 ? FAILED : (SceOff)result;
}

int sceIoRemove(const char *path)
{
    char host[2048];
    return map(path, host, sizeof(host)) != NULL && unlink(host) == 0 ? 0 : FAILED;
}

int sceIoRename(const char *from, const char *to)
{
    char host_from[2048], host_to[2048];
    if (++vita_files_renames == vita_files_fail_rename)
        return FAILED;
    if (map(from, host_from, sizeof(host_from)) == NULL || map(to, host_to, sizeof(host_to)) == NULL)
        return FAILED;
    return rename(host_from, host_to) == 0 ? 0 : FAILED;
}

int sceIoSync(const char *device, unsigned int flags)
{
    (void)device, (void)flags;
    return 0;
}

int sceIoGetstat(const char *path, SceIoStat *status)
{
    char host[2048];
    struct stat info;
    if (map(path, host, sizeof(host)) == NULL || stat(host, &info) != 0)
        return FAILED;
    status->st_size = (uint64_t)info.st_size;
    return 0;
}

int sceIoMkdir(const char *path, int mode)
{
    char host[2048];
    return map(path, host, sizeof(host)) != NULL && mkdir(host, (mode_t)(mode & 0777)) == 0 ? 0 : FAILED;
}

int sceIoRmdir(const char *path)
{
    char host[2048];
    return map(path, host, sizeof(host)) != NULL && rmdir(host) == 0 ? 0 : FAILED;
}

/* Remounting vs0 writable is a no-op on the host */
int vshIoUmount(int id, int force, int unk2, int unk3) { (void)id, (void)force, (void)unk2, (void)unk3; return 0; }
int _vshIoMount(int id, const char *path, int permission, void *buffer)
{
    (void)id, (void)path, (void)permission, (void)buffer;
    return 0;
}
int _vshSblGetSystemSwVersion(SceKernelFwInfo *info)
{
    info->version = vita_files_firmware;
    snprintf(info->versionString, sizeof(info->versionString), "%x.%02x",
             vita_files_firmware >> 24, (vita_files_firmware >> 16) & 0xff);
    return 0;
}
