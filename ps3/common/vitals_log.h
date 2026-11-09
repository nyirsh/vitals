#ifndef VITALS_LOG_H
#define VITALS_LOG_H

/* A line in /dev_hdd0/vitals/logs/vitals.log and on the TTY (RPCS3's TTY log, a debug console), written
 * with lv2's own calls, so a module that logs imports nothing for it. Each line is opened, appended
 * and closed, so it survives the process ending right after. */

#include <stdint.h>

#include <ppu-lv2.h>

#include "vitals_log_format.h"
#include "vitals_paths.h"

#define VITALS_LOG_PATH VITALS_LOG_FILE

/* lv2: sys_tty_write 403, sys_fs_open 801, sys_fs_write 803, sys_fs_close 804 */
#define VITALS_LV2_TTY_WRITE 403
#define VITALS_LV2_FS_OPEN 801
#define VITALS_LV2_FS_WRITE 803
#define VITALS_LV2_FS_CLOSE 804
#define VITALS_FS_APPEND_CREATE (01 | 0100 | 02000) /* write only, create, append */

static inline uint32_t vitals_log_length(const char *text)
{
	uint32_t length = 0;
	while (text[length] != '\0')
		++length;
	return length;
}

static inline void vitals_log_tty(const char *text, uint32_t length)
{
	uint32_t written = 0;
	lv2syscall4(VITALS_LV2_TTY_WRITE, 0, (uint64_t)(uintptr_t)text, length, (uint64_t)(uintptr_t)&written);
}

static inline int vitals_log_open(void)
{
	int fd = -1;
	lv2syscall6(VITALS_LV2_FS_OPEN, (uint64_t)(uintptr_t)VITALS_LOG_PATH, VITALS_FS_APPEND_CREATE,
	            (uint64_t)(uintptr_t)&fd, 0666, 0, 0);
	return p1 == 0 ? fd : -1;
}

static inline void vitals_log_append(int fd, const char *text, uint32_t length)
{
	uint64_t written = 0;
	lv2syscall4(VITALS_LV2_FS_WRITE, fd, (uint64_t)(uintptr_t)text, length, (uint64_t)(uintptr_t)&written);
}

static inline void vitals_log_close(int fd)
{
	lv2syscall1(VITALS_LV2_FS_CLOSE, fd);
}

/* "<who>: [<ms> ms] <text>\n" */
static inline void vitals_log(const char *who, const char *text)
{
	char stamp[32];
	vitals_log_stamp(stamp, sizeof(stamp), vitals_log_now_ms());
	const char *parts[] = {who, ": ", stamp, text, "\n"};
	int fd = vitals_log_open();
	for (unsigned i = 0; i < sizeof(parts) / sizeof(parts[0]); ++i) {
		uint32_t length = vitals_log_length(parts[i]);
		vitals_log_tty(parts[i], length);
		if (fd >= 0)
			vitals_log_append(fd, parts[i], length);
	}
	if (fd >= 0)
		vitals_log_close(fd);
}

/* A value as eight hex digits, into out[9] */
static inline const char *vitals_log_hex(uint32_t value, char out[9])
{
	static const char digits[] = "0123456789ABCDEF";
	for (int i = 7; i >= 0; --i, value >>= 4)
		out[i] = digits[value & 15];
	out[8] = '\0';
	return out;
}

#endif
