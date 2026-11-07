/* vitals' libhttp's platform on a host, for the probe's host run (in place of
 * vitals-http/src/platform/platform_ps3.c): pthread locks, the system's allocator with what each
 * pool holds counted, and the system's sockets. sys_net's errno values are BSD's, as macOS's are,
 * so its error codes come out as the console's */

#include "vh.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* Where /dev_hdd0 is (probe_host.c) */
const char *vh_test_hdd(void);

/* ---- locks ---- */

static pthread_mutex_t g_lock, g_cookie_lock;

static int recursive(pthread_mutex_t *lock)
{
	pthread_mutexattr_t attributes;
	pthread_mutexattr_init(&attributes);
	pthread_mutexattr_settype(&attributes, PTHREAD_MUTEX_RECURSIVE);
	int result = pthread_mutex_init(lock, &attributes);
	pthread_mutexattr_destroy(&attributes);
	return result == 0 ? 0 : -1;
}

int vh_platform_lock_create(void)
{
	return recursive(&g_lock);
}

void vh_platform_lock_destroy(void)
{
	pthread_mutex_destroy(&g_lock);
}

void vh_platform_lock(void)
{
	pthread_mutex_lock(&g_lock);
}

void vh_platform_unlock(void)
{
	pthread_mutex_unlock(&g_lock);
}

/* ---- the pools: the system's allocator, each block's size kept before it, so a pool refuses
 * what wouldn't fit in the game's block and AddressSanitizer sees every block on its own ---- */

typedef struct Pool {
	int created;
	size_t capacity, used;
} Pool;

typedef struct Block {
	Pool *pool;
	size_t size;
	max_align_t align;
} Block;

static Pool g_pool, g_cookie_pool;

/* What the console's heap takes of a block for itself (about) */
#define HEAP_OVERHEAD 64u

static void *pool_alloc(Pool *pool, size_t size)
{
	if (!pool->created || size > pool->capacity || pool->used + size + HEAP_OVERHEAD > pool->capacity)
		return NULL;
	Block *block = malloc(sizeof(Block) + (size == 0 ? 1 : size));
	if (block == NULL)
		return NULL;
	block->pool = pool;
	block->size = size;
	pool->used += size;
	return block + 1;
}

static void pool_free(void *memory)
{
	if (memory == NULL)
		return;
	Block *block = (Block *)memory - 1;
	block->pool->used -= block->size;
	free(block);
}

int vh_platform_pool_create(void *block, size_t size)
{
	(void)block;
	g_pool.created = 1;
	g_pool.capacity = size;
	g_pool.used = 0;
	return 0;
}

void vh_platform_pool_delete(void)
{
	g_pool.created = 0;
}

void *vh_platform_alloc(size_t size)
{
	return pool_alloc(&g_pool, size);
}

void vh_platform_free(void *memory)
{
	pool_free(memory);
}

uint32_t vh_platform_pool_free_size(void)
{
	return g_pool.created ? (uint32_t)(g_pool.capacity - g_pool.used - HEAP_OVERHEAD) : 0;
}

void vh_platform_pool_mallinfo(uint32_t info[10])
{
	memset(info, 0, 10 * sizeof(uint32_t));
	if (g_pool.created) {
		info[0] = (uint32_t)g_pool.capacity;
		info[7] = (uint32_t)g_pool.used;
		info[8] = (uint32_t)(g_pool.capacity - g_pool.used);
	}
}

int vh_platform_cookie_create(void *block, size_t size)
{
	(void)block;
	if (recursive(&g_cookie_lock) != 0)
		return -1;
	g_cookie_pool.created = 1;
	g_cookie_pool.capacity = size;
	g_cookie_pool.used = 0;
	return 0;
}

void vh_platform_cookie_delete(void)
{
	g_cookie_pool.created = 0;
	pthread_mutex_destroy(&g_cookie_lock);
}

void vh_platform_cookie_lock(void)
{
	pthread_mutex_lock(&g_cookie_lock);
}

void vh_platform_cookie_unlock(void)
{
	pthread_mutex_unlock(&g_cookie_lock);
}

void *vh_platform_cookie_alloc(size_t size)
{
	return pool_alloc(&g_cookie_pool, size);
}

void vh_platform_cookie_free(void *memory)
{
	pool_free(memory);
}

/* ---- the rest of the system ---- */

int vh_platform_file_read(const char *path, unsigned offset, void *buffer, unsigned size)
{
	char host[1024];
	const char *prefix = "/dev_hdd0";
	if (strncmp(path, prefix, strlen(prefix)) == 0)
		snprintf(host, sizeof(host), "%s%s", vh_test_hdd(), path + strlen(prefix));
	else
		snprintf(host, sizeof(host), "%s", path);
	int fd = open(host, O_RDONLY);
	if (fd < 0)
		return (int)0x80010006;
	ssize_t got = pread(fd, buffer, size, (off_t)offset);
	close(fd);
	return got >= 0 ? (int)got : (int)0x80010002;
}

int vh_platform_stat(const char *path)
{
	char host[1024];
	const char *prefix = "/dev_hdd0";
	if (strncmp(path, prefix, strlen(prefix)) == 0)
		snprintf(host, sizeof(host), "%s%s", vh_test_hdd(), path + strlen(prefix));
	else
		snprintf(host, sizeof(host), "%s", path);
	struct stat status;
	return stat(host, &status) == 0 ? 0 : (int)0x80010006; /* cellFs's ENOENT */
}

int64_t vh_platform_now(void)
{
	return (int64_t)time(NULL);
}

/* Whether pointer can be read, as the console's page check says: a write from it into a pipe
 * fails with EFAULT when it can't */
int vh_platform_readable(const void *pointer)
{
	static int pipes[2] = {-1, -1};
	if (pointer == NULL)
		return 0;
	if (pipes[0] < 0 && pipe(pipes) != 0)
		return 1;
	if (write(pipes[1], pointer, 1) != 1)
		return 0;
	char drained;
	(void)read(pipes[0], &drained, 1);
	return 1;
}

static void set_timeout(int fd, int name, int64_t usec)
{
	if (usec <= 0)
		return;
	struct timeval value = {(time_t)(usec / 1000000), (suseconds_t)(usec % 1000000)};
	(void)setsockopt(fd, SOL_SOCKET, name, &value, sizeof(value));
}

int vh_platform_connect(const char *host, unsigned port, int64_t conn_timeout, int64_t send_timeout,
                        int64_t recv_timeout)
{
	struct in_addr address;
	if (inet_pton(AF_INET, host, &address) != 1) {
		struct hostent *entry = gethostbyname(host);
		if (entry == NULL || entry->h_addr_list == NULL || entry->h_addr_list[0] == NULL)
			return VH_NET_ERROR(VH_NET_RESOLVER, h_errno);
		memcpy(&address, entry->h_addr_list[0], sizeof(address));
	}
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return VH_NET_ERROR(VH_NET_CONNECT, errno);
	int on = 1;
	(void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
	set_timeout(fd, SO_SNDTIMEO, send_timeout);
	int flags = fcntl(fd, F_GETFL);
	(void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	struct sockaddr_in to;
	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_port = htons((uint16_t)port);
	to.sin_addr = address;
	int error = 0;
	if (connect(fd, (const struct sockaddr *)&to, sizeof(to)) != 0) {
		error = errno;
		if (error == EINPROGRESS) {
			fd_set writable;
			FD_ZERO(&writable);
			FD_SET(fd, &writable);
			struct timeval wait = {(time_t)(conn_timeout / 1000000), (suseconds_t)(conn_timeout % 1000000)};
			int ready = select(fd + 1, NULL, &writable, NULL, conn_timeout > 0 ? &wait : NULL);
			if (ready < 0) {
				error = errno;
				close(fd);
				return VH_NET_ERROR(VH_NET_SELECT, error);
			}
			if (ready == 0) {
				close(fd);
				return VH_ERROR_TIMEOUT;
			}
			socklen_t length = sizeof(error);
			error = 0;
			if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) != 0)
				error = errno;
		}
	}
	if (error != 0) {
		close(fd);
		return VH_NET_ERROR(VH_NET_CONNECT, error);
	}
	(void)fcntl(fd, F_SETFL, flags);
	set_timeout(fd, SO_RCVTIMEO, recv_timeout);
	return fd;
}

int vh_platform_send(int fd, const void *data, size_t size)
{
	ssize_t sent = send(fd, data, size, 0);
	return sent >= 0 ? (int)sent : VH_NET_ERROR(VH_NET_SEND, errno);
}

int vh_platform_recv(int fd, void *data, size_t size)
{
	ssize_t got = recv(fd, data, size, 0);
	return got >= 0 ? (int)got : VH_NET_ERROR(VH_NET_RECV, errno);
}

void vh_platform_close(int fd)
{
	close(fd);
}

int vh_platform_wait_readable(const int *fds, unsigned count, int64_t timeout)
{
	fd_set readable;
	FD_ZERO(&readable);
	int top = -1;
	for (unsigned i = 0; i < count; ++i) {
		FD_SET(fds[i], &readable);
		if (fds[i] > top)
			top = fds[i];
	}
	struct timeval wait = {(time_t)(timeout / 1000000), (suseconds_t)(timeout % 1000000)};
	int ready = select(top + 1, &readable, NULL, NULL, timeout >= 0 ? &wait : NULL);
	if (ready < 0)
		return VH_NET_ERROR(VH_NET_SELECT, errno);
	for (unsigned i = 0; ready > 0 && i < count; ++i)
		if (FD_ISSET(fds[i], &readable))
			return (int)i;
	return -1;
}
