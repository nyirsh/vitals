/* vitals' libssl's platform on a host, for the tests (in place of vitals-ssl/src/platform/platform_ps3.c):
 * the lock is a pthread mutex and sockets are the system's. sys_net's EAGAIN is 35, which the
 * system's is turned into where it differs */

#include "vs.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* Where the tests put Sony's CA files and Mozilla's bundle, and the title ID they pretend to be */
char vs_test_sony_cert_directory[512];
char vs_test_bundle_path[512];
char vs_test_title_id[10];

static pthread_mutex_t g_lock;

int vs_platform_lock_create(void)
{
	pthread_mutexattr_t attributes;
	pthread_mutexattr_init(&attributes);
	pthread_mutexattr_settype(&attributes, PTHREAD_MUTEX_RECURSIVE);
	int result = pthread_mutex_init(&g_lock, &attributes);
	pthread_mutexattr_destroy(&attributes);
	return result == 0 ? 0 : -1;
}

void vs_platform_lock_destroy(void)
{
	pthread_mutex_destroy(&g_lock);
}

void vs_platform_lock(void)
{
	pthread_mutex_lock(&g_lock);
}

void vs_platform_unlock(void)
{
	pthread_mutex_unlock(&g_lock);
}

int vs_platform_recv(int fd, void *data, size_t size)
{
	return (int)recv(fd, data, size, 0);
}

int vs_platform_send(int fd, const void *data, size_t size)
{
#ifdef MSG_NOSIGNAL
	return (int)send(fd, data, size, MSG_NOSIGNAL);
#else
	return (int)send(fd, data, size, 0);
#endif
}

int vs_platform_net_errno(void)
{
	return errno == EAGAIN || errno == EWOULDBLOCK ? VS_NET_EAGAIN : errno;
}

void vs_platform_set_net_errno(int value)
{
	errno = value == VS_NET_EAGAIN ? EAGAIN : value;
}

/* The host's threads have stacks enough: nothing is moved */
int vs_platform_run_with_stack(void (*function)(void *), void *argument, uint32_t stack)
{
	(void)function, (void)argument, (void)stack;
	return -1;
}

void vs_platform_stack(uint32_t *size, uint32_t *left)
{
	*size = *left = 0;
}

void vs_platform_log(const char *text)
{
	if (getenv("VS_TEST_LOG") != NULL)
		fprintf(stderr, "vitals-ssl: %s\n", text);
}

int vs_platform_file_open(const char *path)
{
	return open(path, O_RDONLY);
}

int vs_platform_file_read(int fd, void *data, size_t size)
{
	return (int)read(fd, data, size);
}

int vs_platform_file_seek(int fd, uint32_t offset)
{
	return lseek(fd, (off_t)offset, SEEK_SET) < 0 ? -1 : 0;
}

int64_t vs_platform_file_size(int fd)
{
	struct stat status;
	return fstat(fd, &status) == 0 ? (int64_t)status.st_size : -1;
}

void vs_platform_file_close(int fd)
{
	close(fd);
}

int vs_platform_sony_cert_path(char *path, size_t size, const char *file)
{
	int length = snprintf(path, size, "%s/%s", vs_test_sony_cert_directory, file);
	return length > 0 && (size_t)length < size ? 0 : -1;
}

const char *vs_platform_bundle_path(void)
{
	return vs_test_bundle_path;
}

int vs_platform_readable(const void *pointer)
{
	return pointer != NULL;
}

void vs_platform_title_id(char id[10])
{
	memcpy(id, vs_test_title_id, 10);
	id[9] = '\0';
}
