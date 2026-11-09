/* The Vita's files for the shared app (platform.h), on sceIo: built in the app, and in the
 * installer's host tests against their stand-ins (tests/vita_files.c) */

#include "platform.h"

#include <psp2/io/dirent.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>

#include <string.h>

long platform_read_file(const char *path, char *data, size_t capacity)
{
    SceUID file = sceIoOpen(path, SCE_O_RDONLY, 0);
    if (file < 0)
        return -1;
    size_t length = 0;
    while (length < capacity)
    {
        int read = sceIoRead(file, data + length, (SceSize)(capacity - length));
        if (read < 0)
        {
            sceIoClose(file);
            return -1;
        }
        if (read == 0)
            break;
        length += (size_t)read;
    }
    sceIoClose(file);
    return (long)length;
}

int platform_write_file(const char *path, const void *data, size_t length)
{
    SceUID file = sceIoOpen(path, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0777);
    if (file < 0)
        return -1;
    size_t written = 0;
    while (written < length)
    {
        int n = sceIoWrite(file, (const char *)data + written, (SceSize)(length - written));
        if (n <= 0)
            break;
        written += (size_t)n;
    }
    int closed = sceIoClose(file);
    return written == length && closed >= 0 ? 0 : -1;
}

int platform_file_exists(const char *path)
{
    SceIoStat status;
    return sceIoGetstat(path, &status) >= 0;
}

int platform_make_folder(const char *path)
{
    return sceIoMkdir(path, 0777) >= 0 || platform_file_exists(path) ? 0 : -1;
}

int platform_remove_file(const char *path)
{
    return sceIoRemove(path) >= 0 ? 0 : -1;
}

int platform_rename(const char *from, const char *to)
{
    return sceIoRename(from, to) >= 0 ? 0 : -1;
}

int platform_list_folder(const char *path, void (*each)(void *context, const char *name), void *context)
{
    SceUID folder = sceIoDopen(path);
    if (folder < 0)
        return -1;
    SceIoDirent entry;
    while (sceIoDread(folder, &entry) > 0)
        if (strcmp(entry.d_name, ".") != 0 && strcmp(entry.d_name, "..") != 0)
            each(context, entry.d_name);
    (void)sceIoDclose(folder);
    return 0;
}
