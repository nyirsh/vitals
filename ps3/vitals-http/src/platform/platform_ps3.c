/* The console's side of vitals' libhttp: the lock and heap as Sony's libhttp makes them
 * (cellHttpInit, 0x19b40: "_httsys", a heap named "cellHttp_Library" on the game's block), the IDs'
 * check, and sys_net's sockets through PS3DK's raw imports, which leave errno in sys_net's (this
 * module links no libc), as vitals-ssl's platform does */

#include "vh.h"

#include <cell/libnet.h>
#include <net/errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <ppu-lv2.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/synchronization.h>

int __ps3dk_raw_socket(int domain, int type, int protocol);
int __ps3dk_raw_connect(int fd, const struct sockaddr *address, socklen_t length);
int __ps3dk_raw_setsockopt(int fd, int level, int name, const void *value, socklen_t length);
int __ps3dk_raw_socketclose(int fd);
int __ps3dk_raw_getsockopt(int fd, int level, int name, void *value, socklen_t *length);
int __ps3dk_raw_socketselect(int count, fd_set *readable, fd_set *writable, fd_set *failed, struct timeval *timeout);
struct hostent *__ps3dk_raw_gethostbyname(const char *name);
long __ps3dk_raw_recv(int fd, void *data, size_t size, int flags);
long __ps3dk_raw_send(int fd, const void *data, size_t size, int flags);

uint32_t _sys_heap_create_heap(const char *name, uint32_t size, uint32_t flags, const void *memory);
int _sys_heap_delete_heap(uint32_t heap);
void *_sys_heap_malloc(uint32_t heap, uint32_t size);
int _sys_heap_free(uint32_t heap, void *address);

static sys_lwmutex_t g_lock;
static uint32_t g_heap;

int vh_platform_lock_create(void)
{
	sys_lwmutex_attribute_t attr;
	sys_lwmutex_attribute_initialize(attr);
	attr.attr_recursive = SYS_SYNC_RECURSIVE;
	sys_lwmutex_attribute_name_set(attr.name, "_httsys");
	return sys_lwmutex_create(&g_lock, &attr) == 0 ? 0 : -1;
}

void vh_platform_lock_destroy(void)
{
	(void)sys_lwmutex_destroy(&g_lock);
}

void vh_platform_lock(void)
{
	(void)sys_lwmutex_lock(&g_lock, 0);
}

void vh_platform_unlock(void)
{
	(void)sys_lwmutex_unlock(&g_lock);
}

/* As Sony's: kind 8 (the memory given), flags 0x80000000 */
int vh_platform_pool_create(void *block, size_t size)
{
	const struct {
		uint32_t kind, start;
	} memory = {8, (uint32_t)(uintptr_t)block};
	g_heap = _sys_heap_create_heap("cellHttp_Library", (uint32_t)size, 0x80000000u, &memory);
	return g_heap != 0 ? 0 : -1;
}

void vh_platform_pool_delete(void)
{
	if (g_heap != 0)
		(void)_sys_heap_delete_heap(g_heap);
	g_heap = 0;
}

void *vh_platform_alloc(size_t size)
{
	return g_heap != 0 ? _sys_heap_malloc(g_heap, (uint32_t)size) : NULL;
}

void vh_platform_free(void *memory)
{
	if (g_heap != 0)
		(void)_sys_heap_free(g_heap, memory);
}

uint32_t _sys_heap_get_total_free_size(uint32_t heap);
int _sys_heap_get_mallinfo(uint32_t heap, void *info);

uint32_t vh_platform_pool_free_size(void)
{
	return g_heap != 0 ? _sys_heap_get_total_free_size(g_heap) : 0;
}

void vh_platform_pool_mallinfo(uint32_t info[10])
{
	memset(info, 0, 10 * sizeof(uint32_t));
	if (g_heap != 0)
		(void)_sys_heap_get_mallinfo(g_heap, info);
}

int vh_platform_wait_readable(const int *fds, unsigned count, int64_t timeout)
{
	fd_set readable;
	FD_ZERO(&readable);
	for (unsigned i = 0; i < count; ++i)
		FD_SET(fds[i], &readable);
	struct timeval wait = {(long)(timeout / 1000000), (long)(timeout % 1000000)};
	int ready = __ps3dk_raw_socketselect(1024, &readable, NULL, NULL, timeout >= 0 ? &wait : NULL);
	if (ready < 0)
		return VH_NET_ERROR(VH_NET_SELECT, sys_net_errno);
	for (unsigned i = 0; ready > 0 && i < count; ++i)
		if (FD_ISSET(fds[i], &readable))
			return (int)i;
	return -1;
}

/* The cookie store's heap, on the block cellHttpInitCookie is given, and its own lock: the store
 * lives apart from cellHttpInit's (either may come first) */
static sys_lwmutex_t g_cookie_lock;
static uint32_t g_cookie_heap;

int vh_platform_cookie_create(void *block, size_t size)
{
	sys_lwmutex_attribute_t attr;
	sys_lwmutex_attribute_initialize(attr);
	attr.attr_recursive = SYS_SYNC_RECURSIVE;
	sys_lwmutex_attribute_name_set(attr.name, "_htcook");
	if (sys_lwmutex_create(&g_cookie_lock, &attr) != 0)
		return -1;
	const struct {
		uint32_t kind, start;
	} memory = {8, (uint32_t)(uintptr_t)block};
	g_cookie_heap = _sys_heap_create_heap("cellHttp_Cookie", (uint32_t)size, 0x80000000u, &memory);
	if (g_cookie_heap == 0) {
		(void)sys_lwmutex_destroy(&g_cookie_lock);
		return -1;
	}
	return 0;
}

void vh_platform_cookie_delete(void)
{
	if (g_cookie_heap != 0)
		(void)_sys_heap_delete_heap(g_cookie_heap);
	g_cookie_heap = 0;
	(void)sys_lwmutex_destroy(&g_cookie_lock);
}

void vh_platform_cookie_lock(void)
{
	(void)sys_lwmutex_lock(&g_cookie_lock, 0);
}

void vh_platform_cookie_unlock(void)
{
	(void)sys_lwmutex_unlock(&g_cookie_lock);
}

void *vh_platform_cookie_alloc(size_t size)
{
	return g_cookie_heap != 0 ? _sys_heap_malloc(g_cookie_heap, (uint32_t)(size == 0 ? 1 : size)) : NULL;
}

void vh_platform_cookie_free(void *memory)
{
	if (g_cookie_heap != 0 && memory != NULL)
		(void)_sys_heap_free(g_cookie_heap, memory);
}

/* sys_fs_open, sys_fs_lseek, sys_fs_read and sys_fs_close (syscalls 801, 818, 802, 804): lv2's
 * own, so this module needs no cellFs */
static int fs_open(const char *path, int *fd)
{
	lv2syscall6(801, (uint64_t)(uintptr_t)path, 0 /* CELL_FS_O_RDONLY */, (uint64_t)(uintptr_t)fd, 0, 0, 0);
	return (int)p1;
}

static int fs_seek(int fd, unsigned offset)
{
	uint64_t position = 0;
	lv2syscall4(818, (uint64_t)fd, (uint64_t)offset, 0 /* SEEK_SET */, (uint64_t)(uintptr_t)&position);
	return (int)p1;
}

static int fs_read(int fd, void *buffer, unsigned size, uint64_t *got)
{
	lv2syscall4(802, (uint64_t)fd, (uint64_t)(uintptr_t)buffer, (uint64_t)size, (uint64_t)(uintptr_t)got);
	return (int)p1;
}

static void fs_close(int fd)
{
	lv2syscall1(804, (uint64_t)fd);
}

int vh_platform_file_read(const char *path, unsigned offset, void *buffer, unsigned size)
{
	int fd = -1;
	int rc = fs_open(path, &fd);
	if (rc != 0)
		return rc;
	uint64_t got = 0;
	rc = fs_seek(fd, offset);
	if (rc == 0)
		rc = fs_read(fd, buffer, size, &got);
	fs_close(fd);
	return rc != 0 ? rc : (int)got;
}

/* sys_fs_stat (syscall 808): 0, or cellFs's error (0x80010006 for nothing there) */
int vh_platform_stat(const char *path)
{
	uint64_t status[16];
	lv2syscall2(808, (uint64_t)(uintptr_t)path, (uint64_t)(uintptr_t)status);
	return (int)p1;
}

/* sys_time_get_current_time (syscall 145): seconds since 1970 */
int64_t vh_platform_now(void)
{
	uint64_t seconds = 0, nanoseconds = 0;
	lv2syscall2(145, (uint64_t)(uintptr_t)&seconds, (uint64_t)(uintptr_t)&nanoseconds);
	return (int64_t)seconds;
}

/* sys_memory_get_page_attribute (syscall 351), as Sony's libhttp checks an ID */
int vh_platform_readable(const void *pointer)
{
	/* sys_page_attr_t: 24 bytes (two 64-bit words and the page size), which a 16-byte buffer here
	 * overran by 8 on the caller's stack */
	uint64_t attribute[4] __attribute__((aligned(16)));
	if (pointer == NULL)
		return 0;
	lv2syscall2(351, (uint64_t)(uintptr_t)pointer, (uint64_t)(uintptr_t)attribute);
	return p1 == 0;
}

/* "a.b.c.d" into address (network order): 1, or 0 for a name */
static int ipv4(const char *text, uint32_t *address)
{
	uint32_t value = 0;
	for (int part = 0; part < 4; ++part) {
		unsigned number = 0, digits = 0;
		while (*text >= '0' && *text <= '9' && digits < 4)
			number = number * 10 + (unsigned)(*text++ - '0'), ++digits;
		if (digits == 0 || number > 255 || (part < 3 && *text++ != '.'))
			return 0;
		value = value << 8 | number;
	}
	if (*text != '\0')
		return 0;
	*address = value; /* the PS3 is big-endian: host order is network order */
	return 1;
}

static void timeout(int fd, int name, int64_t usec)
{
	if (usec <= 0)
		return;
	struct timeval value = {(long)(usec / 1000000), (long)(usec % 1000000)};
	(void)__ps3dk_raw_setsockopt(fd, SOL_SOCKET, name, &value, sizeof(value));
}

int vh_platform_connect(const char *host, unsigned port, int64_t conn_timeout, int64_t send_timeout,
                        int64_t recv_timeout)
{
	uint32_t address;
	if (!ipv4(host, &address)) {
		struct hostent *entry = __ps3dk_raw_gethostbyname(host);
		if (entry == NULL || entry->h_addr_list == NULL || entry->h_addr_list[0] == NULL)
			return VH_NET_ERROR(VH_NET_RESOLVER, sys_net_h_errno);
		memcpy(&address, entry->h_addr_list[0], sizeof(address));
	}
	int fd = __ps3dk_raw_socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return VH_NET_ERROR(VH_NET_CONNECT, sys_net_errno);
	/* As Sony's libhttp connects (0x10c4, and RPCS3's log of it): the send timeout, non-blocking,
	 * connect, which may say EINPROGRESS; then its waiter (0x5e4): socketselect over all 1024
	 * descriptors with the socket in both the read and the write set (RPCS3 says a refused one is
	 * readable, not writable), then SO_ERROR; then the receive timeout, whose failure on a dead socket
	 * is the error Sony's gives there (0x80710316: an option's class, EINVAL, in RPCS3) */
	timeout(fd, SO_SNDTIMEO, send_timeout);
	int on = 1, off = 0, error = 0;
	(void)__ps3dk_raw_setsockopt(fd, SOL_SOCKET, SO_NBIO, &on, sizeof(on));
	struct sockaddr_in to;
	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_port = (uint16_t)port;
	to.sin_addr.s_addr = address;
	if (__ps3dk_raw_connect(fd, (const struct sockaddr *)&to, sizeof(to)) != 0) {
		error = sys_net_errno;
		if (error == NET_EINPROGRESS || error == NET_EALREADY || error == NET_EWOULDBLOCK) {
			fd_set readable, writable;
			FD_ZERO(&readable);
			FD_ZERO(&writable);
			FD_SET(fd, &readable);
			FD_SET(fd, &writable);
			struct timeval wait = {(long)(conn_timeout / 1000000), (long)(conn_timeout % 1000000)};
			int ready = __ps3dk_raw_socketselect(1024, &readable, &writable, NULL, conn_timeout > 0 ? &wait : NULL);
			if (ready < 0) {
				error = sys_net_errno;
				(void)__ps3dk_raw_socketclose(fd);
				return VH_NET_ERROR(VH_NET_SELECT, error);
			} else if (ready == 0) {
				(void)__ps3dk_raw_socketclose(fd);
				return VH_ERROR_TIMEOUT;
			} else {
				socklen_t length = sizeof(error);
				error = 0;
				if (__ps3dk_raw_getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) != 0)
					error = sys_net_errno;
			}
		}
	}
	if (error != 0) {
		(void)__ps3dk_raw_socketclose(fd);
		return VH_NET_ERROR(VH_NET_CONNECT, error);
	}
	if (recv_timeout > 0) {
		struct timeval value = {(long)(recv_timeout / 1000000), (long)(recv_timeout % 1000000)};
		if (__ps3dk_raw_setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &value, sizeof(value)) != 0) {
			error = sys_net_errno;
			(void)__ps3dk_raw_socketclose(fd);
			return VH_NET_ERROR(VH_NET_OPTION, error);
		}
	}
	(void)__ps3dk_raw_setsockopt(fd, SOL_SOCKET, SO_NBIO, &off, sizeof(off));
	return fd;
}

int vh_platform_send(int fd, const void *data, size_t size)
{
	long sent = __ps3dk_raw_send(fd, data, size, 0);
	return sent >= 0 ? (int)sent : VH_NET_ERROR(VH_NET_SEND, sys_net_errno);
}

int vh_platform_recv(int fd, void *data, size_t size)
{
	long got = __ps3dk_raw_recv(fd, data, size, 0);
	return got >= 0 ? (int)got : VH_NET_ERROR(VH_NET_RECV, sys_net_errno);
}

void vh_platform_close(int fd)
{
	(void)__ps3dk_raw_socketclose(fd);
}
