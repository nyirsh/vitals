#include "vs.h"

#include "vitals_log.h"

#include <cell/fs/cell_fs_file_api.h>
#include <cell/libnet.h>
#include <ppu-lv2.h>
#include <sys/synchronization.h>
#include <sys/thread.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* The console's side of vitals' libssl (the Vita's vitals-ssl/src/platform_vita.c): the lock,
 * sys_net's socket calls, files, and the running game */


/* sys_net's recv and send, as Sony's libssl imports them: PS3DK's own recv and send copy sys_net's
 * errno into its libc's, which this module doesn't link (libnet_stub.a names the imports so) */
long __ps3dk_raw_recv(int fd, void *data, size_t size, int flags);
long __ps3dk_raw_send(int fd, const void *data, size_t size, int flags);

static sys_lwmutex_t g_lock;

int vs_platform_lock_create(void)
{
	sys_lwmutex_attribute_t attr;
	sys_lwmutex_attribute_initialize(attr);
	attr.attr_recursive = SYS_SYNC_RECURSIVE;
	sys_lwmutex_attribute_name_set(attr.name, "_sslsys");
	return sys_lwmutex_create(&g_lock, &attr) == 0 ? 0 : -1;
}

void vs_platform_lock_destroy(void)
{
	(void)sys_lwmutex_destroy(&g_lock);
}

void vs_platform_lock(void)
{
	(void)sys_lwmutex_lock(&g_lock, 0);
}

void vs_platform_unlock(void)
{
	(void)sys_lwmutex_unlock(&g_lock);
}

int vs_platform_recv(int fd, void *data, size_t size)
{
	return (int)__ps3dk_raw_recv(fd, data, size, 0);
}

int vs_platform_send(int fd, const void *data, size_t size)
{
	return (int)__ps3dk_raw_send(fd, data, size, 0);
}

int vs_platform_net_errno(void)
{
	return sys_net_errno;
}

void vs_platform_set_net_errno(int value)
{
	sys_net_errno = value;
}

/* sysPrxForUser's own thread calls (liblv2_stub.a), as libssl links no liblv2 of its own */
int sys_ppu_thread_create(sys_ppu_thread_t *thread, void (*entry)(uint64_t), uint64_t argument, int priority,
                          size_t stack, uint64_t flags, const char *name);
void sys_ppu_thread_exit(uint64_t value) __attribute__((noreturn));

typedef struct VsHelper {
	void (*function)(void *);
	void *argument;
} VsHelper;

static void helper_entry(uint64_t argument)
{
	VsHelper *helper = (VsHelper *)(uintptr_t)argument;
	helper->function(helper->argument);
	sys_ppu_thread_exit(0);
}

/* At a high priority (the XMB's run from about 1000 to 3000, lower is sooner): the caller waits.
 * The thread's creation's error when there's none (function not run) */
int vs_platform_run_with_stack(void (*function)(void *), void *argument, uint32_t stack)
{
	VsHelper helper = {function, argument};
	sys_ppu_thread_t thread = 0;
	int rc = sys_ppu_thread_create(&thread, helper_entry, (uint64_t)(uintptr_t)&helper, 1000, stack,
	                               THREAD_JOINABLE, "vitals_ssl_io");
	if (rc != 0)
		return rc;
	u64 ignored = 0;
	int joined = sysThreadJoin(thread, &ignored);
	if (joined != 0) {
		/* Not seen yet: the helper may still be running on helper and argument, which are the caller's */
		VITALS_LOG("the helper thread couldn't be joined (0x%08X)", (unsigned)joined);
	}
	return 0;
}

void vs_platform_stack(uint32_t *size, uint32_t *left)
{
	sys_ppu_thread_stack_t info;
	uint64_t r1;
	__asm__ volatile("mr %0, 1" : "=r"(r1));
	*size = *left = 0;
	if (sysThreadGetStackInformation(&info) != 0)
		return;
	*size = (uint32_t)info.pst_size;
	*left = (uint32_t)r1 > (uint32_t)info.pst_addr ? (uint32_t)r1 - (uint32_t)info.pst_addr : 0;
}

void vs_platform_log(const char *text)
{
	vitals_log("vitals-ssl", text);
}

/* cellFs, as Sony's libssl reads its CA files */
int vs_platform_file_open(const char *path)
{
	int fd = -1;
	return cellFsOpen(path, CELL_FS_O_RDONLY, &fd, NULL, 0) == 0 ? fd : -1;
}

int vs_platform_file_read(int fd, void *data, size_t size)
{
	uint64_t count = 0;
	return cellFsRead(fd, data, size, &count) == 0 ? (int)count : -1;
}

int vs_platform_file_seek(int fd, uint32_t offset)
{
	uint64_t position = 0;
	return cellFsLseek(fd, offset, CELL_FS_SEEK_SET, &position) == 0 ? 0 : -1;
}

int64_t vs_platform_file_size(int fd)
{
	CellFsStat stat;
	return cellFsFstat(fd, &stat) == 0 ? (int64_t)stat.st_size : -1;
}

void vs_platform_file_close(int fd)
{
	(void)cellFsClose(fd);
}

int vs_platform_sony_cert_path(char *path, size_t size, const char *file)
{
	int length = snprintf(path, size, "/dev_flash/data/cert/%s", file);
	return length > 0 && (size_t)length < size ? 0 : -1;
}

const char *vs_platform_store_path(unsigned part)
{
	return part == 0 ? VITALS_BUNDLE : part == 1 ? VITALS_CUSTOM_CERTS : NULL;
}

int vs_platform_readable(const void *pointer)
{
	/* sys_page_attr_t: 24 bytes (two 64-bit words and the page size), which a 16-byte buffer here
	 * overran by 8 on the caller's stack */
	uint64_t attribute[4] __attribute__((aligned(16)));
	if (pointer == NULL)
		return 0;
	lv2syscall2(351, (uint64_t)(uintptr_t)pointer, (uint64_t)(uintptr_t)attribute);
	return p1 == 0;
}

/* sys_process_get_paramsfo (syscall 30), as Sony's libssl reads it (0x2484): the title ID one byte
 * in */
void vs_platform_title_id(char id[10])
{
	unsigned char sfo[0x40] __attribute__((aligned(16)));
	memset(sfo, 0, sizeof(sfo));
	id[0] = '\0';
	lv2syscall1(30, (uint64_t)(uintptr_t)sfo);
	if (p1 != 0)
		return;
	memcpy(id, sfo + 1, 9);
	id[9] = '\0';
}
