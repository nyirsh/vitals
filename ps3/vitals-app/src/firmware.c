#include "firmware.h"

#include "console.h"

#include "app_log.h"
#include "vitals_paths.h"

#include <cell/cell_fs.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/lv2_syscall.h>

/* lv2's console type (webMAN MOD's SC_GET_CONSOLE_TYPE): 1 CEX, 2 DEX, 3 DECR */
#define LV2_GET_CONSOLE_TYPE 985
/* Cobra's and PS3HEN's syscall 8, and what webMAN MOD asks it */
#define SYSCALL8 8
#define SYSCALL8_IS_HEN 0x1337
#define SYSCALL8_HEN_REVISION 0x1339
#define SYSCALL8_GET_VERSION2 0x7001

#define VERSION_TXT "/dev_flash/vsh/etc/version.txt"

static ConsoleInfo g_info;
static int g_read;

/* "release:04.9300:" -> 4 and 93 */
static void read_firmware(unsigned *major, unsigned *minor)
{
	char text[512];
	int fd;
	uint64_t got = 0;
	*major = *minor = 0;
	if (cellFsOpen(VERSION_TXT, CELL_FS_O_RDONLY, &fd, NULL, 0) != CELL_FS_SUCCEEDED)
		return;
	if (cellFsRead(fd, text, sizeof(text) - 1, &got) != CELL_FS_SUCCEEDED)
		got = 0;
	cellFsClose(fd);
	text[got] = '\0';
	const char *release = strstr(text, "release:");
	unsigned a = 0, b = 0;
	if (release != NULL && sscanf(release + 8, "%2u.%2u", &a, &b) == 2) {
		*major = a;
		*minor = b;
	}
}

/* Cobra's version as webMAN MOD shows it: 0x0850 -> "8.5", 0x0851 -> "8.51" */
static void version_text(char *out, size_t size, unsigned version)
{
	if ((version & 0x0F) == 0)
		snprintf(out, size, "%X.%X", version >> 8, (version & 0xF0) >> 4);
	else
		snprintf(out, size, "%X.%02X", version >> 8, version & 0xFF);
}

const ConsoleInfo *console_info(void)
{
	if (g_read)
		return &g_info;
	g_read = 1;
	ConsoleInfo *info = &g_info;
	read_firmware(&info->major, &info->minor);

	uint64_t type = 0;
	{
		lv2syscall1(LV2_GET_CONSOLE_TYPE, (uint64_t)(uintptr_t)&type);
		if (p1 != 0)
			type = 0;
	}
	info->type = type == 1 ? CONSOLE_TYPE_CEX : type == 2 ? CONSOLE_TYPE_DEX : type == 3 ? CONSOLE_TYPE_DECR
	                                                                                   : CONSOLE_TYPE_UNKNOWN;
	{
		lv2syscall1(SYSCALL8, SYSCALL8_IS_HEN);
		info->hen = (uint32_t)p1 == SYSCALL8_IS_HEN;
	}
	if (info->hen) {
		lv2syscall1(SYSCALL8, SYSCALL8_HEN_REVISION);
		info->hen_revision = (uint32_t)p1;
	} else {
		/* Read into a local first: the lv2syscall macros set their registers one by one */
		static uint16_t version __attribute__((aligned(8)));
		uint64_t where = (uint64_t)(uintptr_t)&version;
		version = 0;
		lv2syscall2(SYSCALL8, SYSCALL8_GET_VERSION2, where);
		info->cobra = p1 == 0 && version != 0;
		info->cobra_version = version;
	}
	app_log("console: version.txt %u.%02u, type %llu, hen %d (0x%X), cobra %d (0x%X)", info->major, info->minor,
	        (unsigned long long)type, info->hen, info->hen_revision, info->cobra, info->cobra_version);

	char firmware[24], payload[32], version[16];
	if (info->major != 0)
		snprintf(firmware, sizeof(firmware), "%u.%02u", info->major, info->minor);
	else
		snprintf(firmware, sizeof(firmware), "unknown firmware");
	if (info->hen) {
		version_text(version, sizeof(version), info->hen_revision);
		snprintf(payload, sizeof(payload), "PS3HEN %s", version);
	} else if (info->cobra) {
		version_text(version, sizeof(version), info->cobra_version);
		snprintf(payload, sizeof(payload), "Cobra %s", version);
	} else {
		snprintf(payload, sizeof(payload), "no Cobra");
	}
	static const char *const types[] = {"", " CEX", " DEX", " DECR"};
	snprintf(info->text, sizeof(info->text), "%s%s, %s", firmware, types[info->type], payload);
	info->supported = info->major == 4 && info->minor == 93 && info->type == CONSOLE_TYPE_CEX && !info->hen &&
	                  info->cobra;
	return info;
}

int console_unsupported_allowed(void)
{
	CellFsStat status;
	return cellFsStat(VITALS_UNSUPPORTED_OK, &status) == CELL_FS_SUCCEEDED;
}
