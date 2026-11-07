/* The PS3's part of the shared app (console.h): what the system is (firmware.c), the words that
 * are the PS3's, the four switches in /dev_hdd0/vitals/flags, the network for the app's downloads, and
 * where the app's files are. vitals' operations themselves are install.c's */

#include "console.h"

#include "crypto_platform.h"
#include "firmware.h"
#include "http.h"
#include "install.h"

#include <stdio.h>

const char *console_system_text(void)
{
	return console_info()->text;
}

int console_supported(void)
{
	return console_info()->supported;
}

static const ConsoleWords words = {
    .name = "PS3",
    .made_for = "4.93 CEX with Cobra",
    .install_description = "Lets games and apps connect to modern secure (TLS 1.2 and 1.3) sites",
    .debug_purposes =
        {
            "Logs nothing, the build for everyday use",
            "Logs calls and connections to /dev_hdd0/vitals/logs/vitals.log",
            "Also every read and write, and the HTTP headers, secrets as their length",
        },
};

const ConsoleWords *console_words(void)
{
	return &words;
}

/* Each one's .off in /dev_hdd0/vitals/flags, which the boot plugin and vitals' libhttp read at the
 * next boot (common/vitals_paths.h). The XMB's own TLS and HTTP stay Sony's: no switch here
 * (vitals-boot/src/boot.c) */
static const ConsoleSwitch switches[] = {
    {"TLS", "vitals TLS enabled", "Sony TLS enabled", VITALS_TLS_OFF},
    {"HTTP", "vitals HTTP enabled", "Sony HTTP enabled", VITALS_HTTP_OFF},
    {"DNS rules", "vitals DNS rules enabled", "vitals DNS rules disabled", VITALS_DNS_OFF},
    {"Redirects", "vitals redirects enabled", "vitals redirects disabled", VITALS_REDIRECTS_OFF},
};

unsigned console_switch_count(void)
{
	return sizeof(switches) / sizeof(switches[0]);
}

const ConsoleSwitch *console_switch(unsigned index)
{
	return &switches[index];
}

int console_switch_is_off(unsigned index)
{
	return vitals_switch_is_off(switches[index].file);
}

int console_switch_set(unsigned index, int off)
{
	return vitals_switch_set(switches[index].file, off);
}

/* ---- the network, for the app's own downloads ---- */

/* curl's TLS is Mbed TLS (vitals-app/curl), whose mutexes are liblv2's: set once, before its first use */
int console_network_start(int (*stop)(void))
{
	static int crypto_ready;
	if (!crypto_ready) {
		if (vitals_crypto_platform_init() < 0)
			return -1;
		crypto_ready = 1;
	}
	return http_network_wait(stop);
}

/* Next to the EBOOT.BIN, in the app's USRDIR */
void console_app_file(const char *name, char *path, size_t size)
{
	snprintf(path, size, "%s/%s", vitals_install_source(), name);
}

void console_close(void)
{
	http_close();
}
