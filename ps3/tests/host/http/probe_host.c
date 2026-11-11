/* The libhttp probe (tests/http-probe) on a host, against vitals' libhttp and libssl built for it,
 * with AddressSanitizer: the probe's main is vitals_probe_main (CMakeLists.txt), and this one sets
 * up what the console has. VITALS_PROBE_HDD names the directory that stands for /dev_hdd0;
 * libssl's CA store reads Sony's CA files from VITALS_PS3_CERTS, when set */

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cell/cell_fs.h>

int vitals_probe_main(void);

extern char vs_test_sony_cert_directory[512], vs_test_bundle_path[512], vs_test_custom_path[512], vs_test_title_id[10];

static char g_hdd[512] = ".";

const char *vh_test_hdd(void)
{
	return g_hdd;
}

static void host_path(char *out, size_t size, const char *path)
{
	const char *prefix = "/dev_hdd0";
	if (strncmp(path, prefix, strlen(prefix)) == 0)
		snprintf(out, size, "%s%s", g_hdd, path + strlen(prefix));
	else
		snprintf(out, size, "%s", path);
}

int cellFsOpen(const char *path, int flags, int *fd, const void *argument, uint64_t size)
{
	(void)argument, (void)size;
	char host[1024];
	host_path(host, sizeof(host), path);
	int open_flags = (flags & CELL_FS_O_WRONLY) ? O_WRONLY : O_RDONLY;
	if (flags & CELL_FS_O_CREAT)
		open_flags |= O_CREAT;
	if (flags & CELL_FS_O_TRUNC)
		open_flags |= O_TRUNC;
	*fd = open(host, open_flags, 0644);
	return *fd >= 0 ? CELL_FS_SUCCEEDED : (int)0x80010006;
}

int cellFsRead(int fd, void *data, uint64_t size, uint64_t *read_size)
{
	ssize_t got = read(fd, data, (size_t)size);
	if (read_size != NULL)
		*read_size = got > 0 ? (uint64_t)got : 0;
	return got >= 0 ? CELL_FS_SUCCEEDED : (int)0x80010002;
}

int cellFsWrite(int fd, const void *data, uint64_t size, uint64_t *written)
{
	ssize_t put = write(fd, data, (size_t)size);
	if (written != NULL)
		*written = put > 0 ? (uint64_t)put : 0;
	return put >= 0 ? CELL_FS_SUCCEEDED : (int)0x80010002;
}

int cellFsClose(int fd)
{
	return close(fd) == 0 ? CELL_FS_SUCCEEDED : (int)0x80010002;
}

int cellFsFstat(int fd, CellFsStat *status)
{
	struct stat host;
	if (fstat(fd, &host) != 0)
		return (int)0x80010002;
	status->st_size = (uint64_t)host.st_size;
	return CELL_FS_SUCCEEDED;
}

int main(void)
{
	const char *hdd = getenv("VITALS_PROBE_HDD");
	if (hdd != NULL)
		snprintf(g_hdd, sizeof(g_hdd), "%s", hdd);
	const char *certs = getenv("VITALS_PS3_CERTS");
	snprintf(vs_test_sony_cert_directory, sizeof(vs_test_sony_cert_directory), "%s", certs != NULL ? certs : g_hdd);
	snprintf(vs_test_bundle_path, sizeof(vs_test_bundle_path), "%s/vitals/system/mozilla-certs.pem", g_hdd);
	snprintf(vs_test_custom_path, sizeof(vs_test_custom_path), "%s/vitals/custom-certs.pem", g_hdd);
	memset(vs_test_title_id, 0, sizeof(vs_test_title_id));
	setvbuf(stdout, NULL, _IOLBF, 0);
	return vitals_probe_main();
}
