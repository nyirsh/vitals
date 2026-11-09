/* Installing, uninstalling and the certificate update, with cellFs: each file is written next to its
 * place and renamed over it, so an interrupted copy leaves the old one */

#include "install.h"

#include "ca_update.h"
#include "installed.h"

#include "vitals/log.h"
#include "boot_plugins.h"
#include "sony_cas.h"
#include "vitals/store_certs.h"
#include "dates.h"
#include "download.h"

#include <cell/cell_fs.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/lv2_syscall.h>
#include <time.h>

#define COPY_CHUNK (64u * 1024u)

static char source[256] = "/dev_hdd0/game/" VITALS_TITLE_ID "/USRDIR";

static const char *const libssl_builds[VITALS_DEBUG_LEVEL_COUNT] = {"libssl.sprx", "libssl-debug1.sprx",
                                                                   "libssl-debug2.sprx"};
static const char *const libhttp_builds[VITALS_DEBUG_LEVEL_COUNT] = {"libhttp.sprx", "libhttp-debug1.sprx",
                                                                    "libhttp-debug2.sprx"};
static const char *const boot_builds[VITALS_DEBUG_LEVEL_COUNT] = {"vitals_boot.sprx", "vitals_boot-debug1.sprx",
                                                                  "vitals_boot-debug2.sprx"};
static const char *const dns_builds[VITALS_DEBUG_LEVEL_COUNT] = {"vitals_dns.bin", "vitals_dns-debug1.bin",
                                                                 "vitals_dns-debug2.bin"};
static const char *const level_names[VITALS_DEBUG_LEVEL_COUNT] = {"off", "Basic debug", "Full debug"};

void vitals_install_set_source(const char *eboot_path)
{
	const char *slash = eboot_path != NULL ? strrchr(eboot_path, '/') : NULL;
	if (slash != NULL && strncmp(eboot_path, "/dev_", 5) == 0 && (size_t)(slash - eboot_path) < sizeof(source)) {
		memcpy(source, eboot_path, (size_t)(slash - eboot_path));
		source[slash - eboot_path] = '\0';
	}
}

const char *vitals_install_source(void)
{
	return source;
}

static void notef(VitalsNote note, const char *format, ...) __attribute__((format(printf, 2, 3)));
static void notef(VitalsNote note, const char *format, ...)
{
	char line[192];
	va_list arguments;
	va_start(arguments, format);
	vsnprintf(line, sizeof(line), format, arguments);
	va_end(arguments);
	note(line);
}

static int exists(const char *path)
{
	CellFsStat status;
	return cellFsStat(path, &status) == CELL_FS_SUCCEEDED;
}

/* A whole file, at most limit bytes, NUL-terminated; NULL when it can't be read */
static char *read_file(const char *path, size_t limit, size_t *length)
{
	int fd;
	CellFsStat status;
	*length = 0;
	if (cellFsOpen(path, CELL_FS_O_RDONLY, &fd, NULL, 0) != CELL_FS_SUCCEEDED)
		return NULL;
	char *data = NULL;
	if (cellFsFstat(fd, &status) == CELL_FS_SUCCEEDED && status.st_size <= limit &&
	    (data = malloc((size_t)status.st_size + 1)) != NULL) {
		uint64_t done = 0, read = 0;
		while (done < status.st_size && cellFsRead(fd, data + done, status.st_size - done, &read) == CELL_FS_SUCCEEDED &&
		       read != 0)
			done += read;
		if (done != status.st_size) {
			free(data);
			data = NULL;
		} else {
			data[done] = '\0';
			*length = (size_t)done;
		}
	}
	cellFsClose(fd);
	return data;
}

/* data into path through path.new, then renamed over it: 0, or cellFs's error */
static int write_file(const char *path, const void *data, size_t length)
{
	char temporary[160];
	snprintf(temporary, sizeof(temporary), "%s.new", path);
	int fd, rc = cellFsOpen(temporary, CELL_FS_O_WRONLY | CELL_FS_O_CREAT | CELL_FS_O_TRUNC, &fd, NULL, 0);
	if (rc != CELL_FS_SUCCEEDED)
		return rc;
	uint64_t done = 0, written = 0;
	while (rc == CELL_FS_SUCCEEDED && done < length) {
		rc = cellFsWrite(fd, (const char *)data + done, length - done, &written);
		if (rc == CELL_FS_SUCCEEDED && written == 0)
			rc = -1;
		done += written;
	}
	if (rc == CELL_FS_SUCCEEDED)
		rc = cellFsFsync(fd);
	if (cellFsClose(fd) != CELL_FS_SUCCEEDED && rc == CELL_FS_SUCCEEDED)
		rc = -1;
	if (rc == CELL_FS_SUCCEEDED) {
		cellFsUnlink(path);
		rc = cellFsRename(temporary, path);
	}
	if (rc != CELL_FS_SUCCEEDED)
		cellFsUnlink(temporary);
	return rc;
}

/* One of the app's files to its place on the console */
static int copy_file(const char *name, const char *to, VitalsNote note)
{
	char from[320];
	snprintf(from, sizeof(from), "%s/%s", source, name);
	size_t length;
	char *data = read_file(from, 16u * 1024u * 1024u, &length);
	if (data == NULL) {
		notef(note, "Can't read %s", from);
		return -1;
	}
	int rc = write_file(to, data, length);
	free(data);
	if (rc != CELL_FS_SUCCEEDED)
		notef(note, "Can't write %s (0x%08X)", to, (unsigned)rc);
	else
		notef(note, "Copied %s to %s", name, to);
	return rc == CELL_FS_SUCCEEDED ? 0 : -1;
}

static void make_directory(const char *path)
{
	if (!exists(path))
		cellFsMkdir(path, CELL_FS_S_IFDIR | 0777);
}

/* A list's lines without entry's, then with it when add (boot_plugins.c), a copy of the list kept
 * next to vitals' own files (backup) when it changes: 0, or an error */
static int edit_list(const char *list, const char *entry, const char *backup, int add, VitalsNote note)
{
	size_t length;
	char *current = read_file(list, 64 * 1024, &length);
	char *edited = NULL;
	size_t used = 0;
	int had = 0;
	if (boot_plugins_edit(current, current != NULL ? length : 0, entry, add, &edited, &used, &had) != 0) {
		free(current);
		return -1;
	}
	int rc = 0;
	if (add && had)
		notef(note, "%s already lists %s", list, entry);
	else if (!add && !had)
		notef(note, "%s doesn't list %s", list, entry);
	else {
		if (current != NULL)
			(void)write_file(backup, current, length);
		rc = write_file(list, edited, used);
		if (rc != CELL_FS_SUCCEEDED)
			notef(note, "Can't write %s (0x%08X)", list, (unsigned)rc);
		else
			notef(note, add ? "Added %s to %s" : "Removed %s from %s", entry, list);
	}
	free(current);
	free(edited);
	return rc == CELL_FS_SUCCEEDED ? 0 : -1;
}

/* The boot plugin's line in boot_plugins.txt. The DNS plugin's line comes out of
 * boot_plugins_kernel.txt either way, where an earlier version put it: loaded at boot from there, it
 * froze the console at every boot; the boot plugin loads it now, later */
static int edit_boot_plugins(int add, VitalsNote note)
{
	int rc = edit_list(VITALS_BOOT_PLUGINS, VITALS_PLUGIN, VITALS_SYSTEM_DIRECTORY "/boot_plugins.txt.bak", add, note);
	if (rc == 0)
		rc = edit_list(VITALS_BOOT_PLUGINS_KERNEL, VITALS_DIRECTORY "/vitals_dns.bin",
		               VITALS_SYSTEM_DIRECTORY "/boot_plugins_kernel.txt.bak", 0, note);
	if (rc == 0)
		rc = edit_list(VITALS_BOOT_PLUGINS_KERNEL, VITALS_DNS_PLUGIN, VITALS_SYSTEM_DIRECTORY "/boot_plugins_kernel.txt.bak",
		               0, note);
	return rc;
}

int vitals_install_detect(void)
{
	size_t length;
	char *list = read_file(VITALS_BOOT_PLUGINS, 64 * 1024, &length);
	int listed = list != NULL && strstr(list, VITALS_PLUGIN) != NULL;
	free(list);
	return listed && exists(VITALS_PLUGIN) && exists(VITALS_LIBSSL);
}

int vitals_install_read(char *version, size_t size, int *debug_level)
{
	*debug_level = vitals_debug_read();
	return vitals_installed_read(version, size);
}

/* The release that installed vitals, and its modules' level as flags/debug.<level> (installed.h) */
static int write_installed(int debug_level)
{
	return vitals_installed_write() < 0 || vitals_debug_write(debug_level) < 0 ? -1 : 0;
}

/* The debug level's builds of the four modules, as the Vita's has one per level of each */
static int copy_builds(int debug_level, VitalsNote note)
{
	if (copy_file(libssl_builds[debug_level], VITALS_LIBSSL, note) < 0 ||
	    copy_file(libhttp_builds[debug_level], VITALS_LIBHTTP, note) < 0 ||
	    copy_file(boot_builds[debug_level], VITALS_PLUGIN, note) < 0 ||
	    copy_file(dns_builds[debug_level], VITALS_DNS_PLUGIN, note) < 0)
		return -1;
	return 0;
}

/* vitals' folders (common/vitals_paths.h) */
static void make_directories(void)
{
	make_directory(VITALS_DIRECTORY);
	make_directory(VITALS_SYSTEM_DIRECTORY);
	make_directory(VITALS_FLAGS_DIRECTORY);
	make_directory(VITALS_LOGS_DIRECTORY);
	make_directory(VITALS_REPORTS_DIRECTORY);
	make_directory("/dev_hdd0/plugins");
}

/* Earlier versions kept everything in /dev_hdd0/vitals itself, and the logs in /dev_hdd0/tmp, and the
 * boot plugin left markers in system/: what
 * the user chose or got (the certificate update's bundle, dns.off, the reports, xmb.off as xmb-tls.off) moves to its
 * folder; the rest goes, the installer having put its own in place */
static void move_earlier_layout(VitalsNote note)
{
	static const char *const moved[][2] = {{VITALS_DIRECTORY "/cacert.pem", VITALS_BUNDLE},
	                                       {VITALS_BUNDLE_EARLIER, VITALS_BUNDLE},
	                                       {VITALS_DIRECTORY "/dns.off", VITALS_DNS_OFF},
	                                       {VITALS_XMB_OLD_OFF, VITALS_XMB_TLS_OFF}};
	for (unsigned i = 0; i < sizeof(moved) / sizeof(moved[0]); ++i) {
		if (!exists(moved[i][0]))
			continue;
		if (!exists(moved[i][1]) && cellFsRename(moved[i][0], moved[i][1]) == CELL_FS_SUCCEEDED)
			notef(note, "Moved %s to %s", moved[i][0], moved[i][1]);
		else
			(void)cellFsUnlink(moved[i][0]);
	}
	static const char *const gone[] = {
	    VITALS_DIRECTORY "/libssl.sprx",       VITALS_DIRECTORY "/libhttp.sprx",   VITALS_DIRECTORY "/vitals_dns.bin",
	    VITALS_DIRECTORY "/installed.txt",     VITALS_DIRECTORY "/libhttp.active", VITALS_DIRECTORY "/libhttp.once",
	    VITALS_DIRECTORY "/dns.once",          VITALS_DIRECTORY "/dns.loading",    VITALS_DIRECTORY "/dns.delay",
	    VITALS_DIRECTORY "/boot_plugins.txt.bak", VITALS_DIRECTORY "/boot_plugins_kernel.txt.bak",
	    "/dev_hdd0/tmp/vitals.log",            "/dev_hdd0/tmp/vitals-app.log",
	    /* The boot plugin's markers of what it mapped, which the app no longer reads */
	    VITALS_SYSTEM_DIRECTORY "/libhttp.active", VITALS_SYSTEM_DIRECTORY "/libssl.active"};
	for (unsigned i = 0; i < sizeof(gone) / sizeof(gone[0]); ++i)
		if (cellFsUnlink(gone[i]) == CELL_FS_SUCCEEDED)
			notef(note, "Deleted %s (an earlier version's place)", gone[i]);
	/* The connection test's reports, into reports/ (shared/app/installed.c, as the Vita's) */
	vitals_move_earlier_reports(note);
}

static int write_mozilla(const char *bundle, size_t bundle_length, int keep_date, VitalsNote note);

int vitals_install_run(int debug_level, VitalsNote note)
{
	if (debug_level < 0 || debug_level >= VITALS_DEBUG_LEVEL_COUNT)
		debug_level = 0;
	make_directories();
	move_earlier_layout(note);
	notef(note, "Debug output: %s", level_names[debug_level]);
	if (copy_builds(debug_level, note) < 0)
		return -1;
	/* A bundle the certificate update wrote stays, as it's newer than the app's: only Sony's, and
	 * what an earlier version merged in of the user's, are taken out */
	size_t bundle_length = 0;
	int kept = exists(VITALS_BUNDLE);
	char *bundle = NULL;
	if (kept) {
		note("Kept Mozilla's certificates already in " VITALS_BUNDLE);
		bundle = read_file(VITALS_BUNDLE, VITALS_CA_BUNDLE_LIMIT, &bundle_length);
	} else {
		char from[320];
		snprintf(from, sizeof(from), "%s/" VITALS_APP_CA_BUNDLE, source);
		bundle = read_file(from, VITALS_CA_BUNDLE_LIMIT, &bundle_length);
	}
	if (bundle == NULL) {
		notef(note, "Can't read Mozilla's certificates (%s)", kept ? VITALS_BUNDLE : VITALS_APP_CA_BUNDLE);
		return -1;
	}
	int written = write_mozilla(bundle, bundle_length, kept, note);
	free(bundle);
	if (written < 0)
		return -1;
	/* The example lists, only where there are none: what's there is the user's */
	static const char *const examples[][2] = {{"redirects.txt", VITALS_REDIRECTS}, {"dns.txt", VITALS_DNS}};
	for (unsigned i = 0; i < sizeof(examples) / sizeof(examples[0]); ++i)
		if (exists(examples[i][1]))
			notef(note, "Kept %s", examples[i][1]);
		else if (copy_file(examples[i][0], examples[i][1], note) < 0)
			return -1;
	if (edit_boot_plugins(1, note) < 0 || write_installed(debug_level) < 0)
		return -1;
	if (cellFsUnlink(VITALS_LOG_FILE) == CELL_FS_SUCCEEDED)
		note("Deleted the old log, " VITALS_LOG_FILE);
	return 0;
}

int vitals_uninstall_run(VitalsNote note)
{
	if (edit_boot_plugins(0, note) < 0)
		return -1;
	/* The modules' level goes with them; the Options' other switches stay */
	(void)vitals_debug_write(0);
	/* An earlier version's files first, into their folders (dns.off and the reports stay) */
	move_earlier_layout(note);
	/* system/ and logs/ go; the user's lists, flags/ and reports/ stay, as on the Vita, and so does
	 * the folder when anything's left in it */
	static const char *const files[] = {VITALS_PLUGIN,      VITALS_LIBSSL,  VITALS_LIBHTTP,
	                                    VITALS_DNS_PLUGIN,  VITALS_BUNDLE,  VITALS_BUNDLE_EARLIER, VITALS_INSTALLED,
	                                    VITALS_SYSTEM_DIRECTORY "/boot_plugins.txt.bak",
	                                    VITALS_SYSTEM_DIRECTORY "/boot_plugins_kernel.txt.bak", VITALS_LOG_FILE,
	                                    VITALS_APP_LOG};
	for (unsigned i = 0; i < sizeof(files) / sizeof(files[0]); ++i)
		if (cellFsUnlink(files[i]) == CELL_FS_SUCCEEDED)
			notef(note, "Deleted %s", files[i]);
	static const char *const folders[] = {VITALS_SYSTEM_DIRECTORY, VITALS_LOGS_DIRECTORY, VITALS_FLAGS_DIRECTORY,
	                                      VITALS_REPORTS_DIRECTORY, VITALS_DIRECTORY};
	for (unsigned i = 0; i < sizeof(folders) / sizeof(folders[0]); ++i)
		if (cellFsRmdir(folders[i]) == CELL_FS_SUCCEEDED)
			notef(note, "Deleted %s", folders[i]);
	return 0;
}

int vitals_install_set_debug_level(int debug_level, VitalsNote note)
{
	if (debug_level < 0 || debug_level >= VITALS_DEBUG_LEVEL_COUNT)
		return -1;
	notef(note, "Debug output: %s", level_names[debug_level]);
	make_directories();
	if (copy_builds(debug_level, note) < 0 || write_installed(debug_level) < 0)
		return -1;
	if (debug_level != 0)
		note("The log will be " VITALS_LOG_FILE);
	return 0;
}

/* Sony's CAs, as libssl reads them from flash (common/sony_cas.h), one after another as PEM text:
 * what Mozilla's file leaves out. NULL when none can be read (then nothing is left out) */
static char *read_sony_cas(size_t *length)
{
	size_t used = 0, capacity = 0, list_length = 0;
	char *text = NULL, *list = NULL;
	*length = 0;
	for (size_t i = 0; i < VS_SONY_CAS; ++i) {
		const SonyCa *ca = &k_sony_cas[i];
		char path[64];
		size_t part_length = 0;
		char *part = NULL;
		const char *from = NULL;
		if (ca->number != 0) {
			snprintf(path, sizeof(path), "/dev_flash/data/cert/CA%02u.cer", (unsigned)ca->number);
			part = read_file(path, 64u * 1024u, &part_length);
			from = part;
		} else {
			if (list == NULL)
				list = read_file("/dev_flash/data/cert/CA_LIST.cer", 256u * 1024u, &list_length);
			if (list != NULL && (size_t)ca->offset + ca->length <= list_length) {
				from = list + ca->offset;
				part_length = ca->length;
			}
		}
		if (from != NULL && part_length != 0) {
			if (used + part_length + 2 > capacity) {
				size_t grown = (used + part_length + 2) * 2;
				char *bigger = realloc(text, grown);
				if (bigger == NULL) {
					free(part);
					break;
				}
				text = bigger;
				capacity = grown;
			}
			memcpy(text + used, from, part_length);
			used += part_length;
			text[used++] = '\n';
			text[used] = '\0';
		}
		free(part);
	}
	free(list);
	*length = used;
	return text;
}

/* Mozilla's part of the store (store_certs.h): bundle without Sony's CAs, and without the user's
 * certificates an earlier version merged in, into VITALS_BUNDLE when that changes it. keep_date
 * keeps the file's time, the menu's "Last update", when the bundle is the one already there. 0, or
 * -1 when it can't be written */
static int write_mozilla(const char *bundle, size_t bundle_length, int keep_date, VitalsNote note)
{
	size_t sony_length = 0;
	char *sony = read_sony_cas(&sony_length);
	if (sony == NULL)
		note("Sony's certificates can't be read: Mozilla's are kept whole");
	char *out = malloc(bundle_length + 1);
	VitalsStoreFilter filter;
	size_t length = 0;
	int filtered = out != NULL ? vitals_store_mozilla(bundle, bundle_length, sony, sony_length, out, bundle_length + 1, &length, &filter) : -1;
	free(sony);
	if (filtered < 0) {
		free(out);
		note("Mozilla's certificates weren't written: out of memory");
		return -1;
	}
	int rc = CELL_FS_SUCCEEDED;
	CellFsStat status;
	int dated = keep_date && cellFsStat(VITALS_BUNDLE, &status) == CELL_FS_SUCCEEDED;
	if (!(keep_date && length == bundle_length && memcmp(out, bundle, length) == 0)) {
		rc = write_file(VITALS_BUNDLE, out, length);
		if (rc != CELL_FS_SUCCEEDED)
			notef(note, "Can't write " VITALS_BUNDLE " (0x%08X)", (unsigned)rc);
		else if (dated) {
			CellFsUtimbuf times = {status.st_atime, status.st_mtime};
			cellFsUtime(VITALS_BUNDLE, &times);
		}
	}
	free(out);
	if (rc != CELL_FS_SUCCEEDED)
		return -1;
	notef(note, "Mozilla's certificates in " VITALS_BUNDLE ": %u, and %u Sony's already has left out", filter.kept,
	      filter.sony);
	if (filter.cut_custom)
		note("Took out the copy of your certificates an earlier version merged in: " VITALS_CUSTOM_CERTS
		     " is read as it is now");
	return 0;
}

/* curl's notes on the download, into the app's log */
static void log_line(const char *line)
{
	VITALS_LOG("%s", line);
}

/* The update, through curl on the app's own Mbed TLS, trusting only the Mozilla bundle the app carries,
 * checked and without Sony's CAs (ca_update.h): written over VITALS_BUNDLE only when all of that
 * worked, so a failed update leaves the store as it was */
static int download_certificates(VitalsNote note)
{
	note("Connecting to the network...");
	int rc = console_network_start(NULL);
	if (rc < 0) {
		notef(note, "The network didn't start (0x%08X)", (unsigned)rc);
		return rc;
	}
	char trust_path[320];
	size_t trust_length = 0, sony_length = 0;
	snprintf(trust_path, sizeof(trust_path), "%s/" VITALS_APP_CA_BUNDLE, vitals_install_source());
	char *trust = read_file(trust_path, VITALS_CA_BUNDLE_LIMIT, &trust_length);
	if (trust == NULL) {
		notef(note, "Can't read %s", trust_path);
		return -1;
	}
	char *sony = read_sony_cas(&sony_length);
	if (sony == NULL)
		note("Sony's certificates can't be read: Mozilla's are kept whole");
	VitalsCaBundle bundle;
	rc = vitals_ca_download(trust, trust_length, "vitals/" VITALS_VERSION " (PS3)", log_line, sony, sony_length,
	                        &bundle, note);
	free(trust);
	free(sony);
	if (rc < 0) {
		note("The certificates weren't changed");
		return -1;
	}
	make_directories();
	rc = write_file(VITALS_BUNDLE, bundle.data, bundle.size);
	vitals_ca_free(&bundle);
	if (rc != CELL_FS_SUCCEEDED) {
		notef(note, "Can't write " VITALS_BUNDLE " (0x%08X)", (unsigned)rc);
		return -1;
	}
	note("Written to " VITALS_BUNDLE);
	return 0;
}

void vitals_certificates_date(char *text, size_t size, int *stale)
{
	CellFsStat status;
	*stale = 0;
	if (size == 0)
		return;
	text[0] = '\0';
	if (cellFsStat(VITALS_BUNDLE, &status) != CELL_FS_SUCCEEDED)
		return;
	time_t when = status.st_mtime;
	struct tm *utc = gmtime(&when);
	if (utc == NULL)
		return;
	struct tm written = *utc;
	strftime(text, size, "%Y-%m-%d", &written);
	/* Today from lv2's clock (sys_time_get_current_time, syscall 145): cellRtc's module isn't loaded
	 * this early (calling it before the connection test's modules load left the app on a black
	 * screen) */
	int64_t seconds = 0, nanoseconds = 0;
	lv2syscall2(145, (uint64_t)(uintptr_t)&seconds, (uint64_t)(uintptr_t)&nanoseconds);
	time_t now = (time_t)seconds;
	struct tm *today = p1 == 0 && seconds > 0 ? gmtime(&now) : NULL;
	if (today != NULL)
		*stale = vitals_older_than_three_months(written.tm_year, written.tm_mon + 1, written.tm_mday, today->tm_year,
		                                 today->tm_mon + 1, today->tm_mday);
}

/* The system keeps this file while it runs and deletes it when it shuts down properly; found at the
 * next start, it says "The system was not turned off properly". webMAN MOD deletes it before its own
 * reboots, as a reboot through sys_sm_shutdown doesn't */
#define TURNOFF_MARKER "/dev_hdd0/tmp/turnoff"

int vitals_update_certificates(VitalsNote note)
{
	return download_certificates(note);
}

void vitals_reboot(void)
{
	int rc = cellFsUnlink(TURNOFF_MARKER);
	VITALS_LOG("reboot: %s 0x%08X", TURNOFF_MARKER, (unsigned)rc);
	/* sys_sm_shutdown: 0x1200 is a hard reboot, as webMAN MOD's /restart.ps3?hard */
	lv2syscall3(379, 0x1200, 0, 0);
}

int vitals_switch_is_off(const char *path)
{
	return exists(path);
}

int vitals_switch_set(const char *path, int off)
{
	if (!off) {
		int rc = cellFsUnlink(path);
		return rc == CELL_FS_SUCCEEDED || !exists(path) ? 0 : rc;
	}
	make_directories();
	if (exists(path))
		return 0;
	int fd;
	int rc = cellFsOpen(path, CELL_FS_O_WRONLY | CELL_FS_O_CREAT | CELL_FS_O_TRUNC, &fd, NULL, 0);
	if (rc == CELL_FS_SUCCEEDED)
		cellFsClose(fd);
	return rc;
}
