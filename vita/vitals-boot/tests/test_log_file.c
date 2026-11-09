/* The debug output's file (log_file.c), on files kept in memory: nothing is decided until ux0: is
 * there, the choice then sends lines to the file or the console, the last boot's log is kept once,
 * a system call's line is taken, and what doesn't fit is counted rather than lost silently */

#include "log_file.h"
#include "vitals/log_write.h"
#include "vitals/switches.h"

#include <vitasdkkern.h>

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

int syscall_depth;
long long ksceKernelGetSystemTimeWide(void) { return 1234000; }
static int mounted, flag, console_lines, opens;
static char file[0x40000], old_file[0x40000], console[1024];
static size_t file_size, old_size;
static int file_exists_now;

#define LOG_PATH "ux0:data/vitals/logs/vitals.log"
#define OLD_PATH LOG_PATH ".old"

int ksceIoGetstat(const char *path, SceIoStat *status)
{
	(void)status;
	if (strcmp(path, "ux0:data") == 0)
		return mounted ? 0 : -1;
	if (strcmp(path, VITALS_LOG_TO_FILE) == 0)
		return flag ? 0 : -1;
	if (strcmp(path, LOG_PATH) == 0)
		return file_exists_now ? 0 : -1;
	return -1;
}
int ksceIoMkdir(const char *path, int mode)
{
	(void)path, (void)mode;
	return 0;
}
int ksceIoRemove(const char *path)
{
	assert(strcmp(path, OLD_PATH) == 0);
	old_size = 0;
	return 0;
}
int ksceIoRename(const char *from, const char *to)
{
	assert(strcmp(from, LOG_PATH) == 0 && strcmp(to, OLD_PATH) == 0);
	memcpy(old_file, file, file_size);
	old_size = file_size;
	file_size = 0;
	file_exists_now = 0;
	return 0;
}
int ksceIoOpen(const char *path, int flags, int mode)
{
	(void)mode;
	assert(strcmp(path, LOG_PATH) == 0 && (flags & SCE_O_APPEND));
	++opens;
	file_exists_now = 1;
	return 7;
}
int ksceIoWrite(int fd, const void *data, unsigned int size)
{
	assert(fd == 7 && file_size + size <= sizeof(file));
	memcpy(file + file_size, data, size);
	file_size += size;
	return (int)size;
}
int ksceIoClose(int fd)
{
	assert(fd == 7);
	return 0;
}
SceUID ksceKernelCreateMutex(const char *name, unsigned int attributes, int count, const void *option)
{
	(void)name, (void)attributes, (void)count, (void)option;
	return 3;
}
int ksceKernelDeleteMutex(SceUID id) { return id == 3 ? 0 : -1; }
int ksceKernelLockMutex(SceUID id, int count, unsigned int *timeout)
{
	(void)count, (void)timeout;
	return id == 3 ? 0 : -1;
}
int ksceKernelUnlockMutex(SceUID id, int count)
{
	(void)count;
	return id == 3 ? 0 : -1;
}
/* No thread: the test makes each pass itself */
SceUID ksceKernelCreateThread(const char *name, SceKernelThreadEntry entry, int priority, SceSize stack, SceUInt attributes,
                              int cpu, const SceKernelThreadOptParam * option)
{
	(void)name, (void)entry, (void)priority, (void)stack, (void)attributes, (void)cpu, (void)option;
	return -1;
}
int ksceKernelStartThread(SceUID id, SceSize size, void *argument)
{
	(void)id, (void)size, (void)argument;
	return 0;
}
int ksceKernelDelayThread(SceUInt microseconds)
{
	(void)microseconds;
	return 0;
}
int ksceKernelWaitThreadEnd(SceUID id, int *status, SceUInt *timeout)
{
	(void)id, (void)status, (void)timeout;
	return 0;
}
int ksceKernelDeleteThread(SceUID id)
{
	(void)id;
	return 0;
}
int ksceKernelCopyFromUser(void *to, const void *from, SceSize size)
{
	memcpy(to, from, size);
	return 0;
}
int ksceDebugPrintf(const char *format, ...)
{
	va_list arguments;
	va_start(arguments, format);
	vsnprintf(console, sizeof(console), format, arguments);
	va_end(arguments);
	++console_lines;
	return 0;
}

static int in_file(const char *text)
{
	file[file_size] = '\0';
	return strstr(file, text) != NULL;
}

int main(void)
{
	vitals_log_file_start();

	/* ux0: not there yet: the console has the line, and the ring keeps it */
	vitals_log_kernel("vitals-boot", "first %d\n", 1);
	assert(console_lines == 1 && strcmp(console, "vitals-boot: [1234 ms] first 1\n") == 0);
	assert(vitals_log_write("vitals-http: early\n", 19) == 0);
	vitals_log_file_step();
	assert(file_size == 0 && opens == 0);

	/* Log file chosen, an old one there: it's kept once, and the waiting lines are written */
	mounted = 1;
	flag = 1;
	file_exists_now = 1;
	memcpy(file, "last boot's\n", 12);
	file_size = 12;
	vitals_log_file_step();
	assert(old_size == 12 && memcmp(old_file, "last boot's\n", 12) == 0);
	assert(in_file("vitals-boot: [1234 ms] first 1\n") && in_file("vitals-http: early\n") && !in_file("last boot's"));

	/* From now on the file alone takes them */
	console_lines = 0;
	vitals_log_kernel("vitals-dns", "query %s\n", "a.example");
	assert(vitals_log_write("vitals-ssl: hello\n", 18) == 1);
	assert(console_lines == 0);
	vitals_log_file_step();
	assert(in_file("vitals-dns: [1234 ms] query a.example\n") && in_file("vitals-ssl: hello\n"));
	/* Kept once per boot only */
	assert(old_size == 12);

	/* A line too long is cut, still a line */
	char big[600];
	memset(big, 'x', sizeof(big) - 1);
	big[sizeof(big) - 1] = '\0';
	size_t before = file_size;
	vitals_log_kernel("vitals-boot", "%s\n", big);
	vitals_log_file_step();
	assert(file_size - before == VITALS_LOG_LINE_MAX - 1 && file[file_size - 1] == '\n');

	/* A burst bigger than the ring: what fits is written, what doesn't is counted */
	char line[201];
	memset(line, 'y', 199);
	line[199] = '\n';
	line[200] = '\0';
	for (int i = 0; i < 400; ++i)
		vitals_log_file_put(line, 200);
	vitals_log_file_step();
	assert(in_file("vitals-boot: [1234 ms] 73 lines lost, too many at once\n"));
	puts("log file: waits for ux0:, keeps the last boot's, takes lines, cuts long ones, counts lost ones PASS");
	return 0;
}
