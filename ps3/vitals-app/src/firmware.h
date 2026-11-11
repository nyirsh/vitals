#ifndef VITALS_APP_FIRMWARE_H
#define VITALS_APP_FIRMWARE_H

/* What the console runs: its firmware, CEX or DEX, and Cobra or PS3HEN, the way webMAN MOD finds
 * them (its include/init/firmware.h and cpursx.h). Read once, at the first call */

enum { CONSOLE_TYPE_UNKNOWN, CONSOLE_TYPE_CEX, CONSOLE_TYPE_DEX, CONSOLE_TYPE_DECR };

typedef struct {
	/* The firmware, from /dev_flash/vsh/etc/version.txt: 4 and 93 for 4.93; 0 and 0 when unknown */
	unsigned major, minor;
	int type;
	/* PS3HEN's payload answers (its revision in hen_revision), else Cobra's (its version) */
	int hen, cobra;
	unsigned hen_revision, cobra_version;
	/* RPCS3 rather than a console (rpcs3_answers in firmware.c) */
	int rpcs3;
	/* What vitals is made and tested for: 4.93 CEX with Cobra */
	int supported;
	/* "4.93 CEX, Cobra 8.5", with "unknown" for what didn't answer; in RPCS3, "RPCS3, 4.93" */
	char text[64];
} ConsoleInfo;

const ConsoleInfo *console_info(void);

/* console_unsupported_allowed (console.h): while flags/unsupported.ok is there, for testers */

#endif
