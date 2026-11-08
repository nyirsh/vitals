/* Host-only exercise of the release check's fetch (release_fetch.c) and so of the shared download,
 * against test servers (release_fetch_tests.py): ca url [url]. Built on the apps' curl and Mbed TLS by
 * both consoles' tests: the Vita's with the host's defaults, the PS3's with its own crypto options
 * (VITALS_MBEDTLS_PLATFORM: Mbed TLS's mutexes first, as its console_network_start sets them) */

#include "release_check.h"

#ifdef VITALS_MBEDTLS_PLATFORM
#include "crypto_platform.h"
#endif

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	char version[16];
	if (argc < 3 || argc > 4)
		return 2;
#ifdef VITALS_MBEDTLS_PLATFORM
	if (vitals_crypto_platform_init() != 0)
		return 2;
#endif
	FILE *file = fopen(argv[1], "rb");
	if (file == NULL)
		return 2;
	static char ca[1024 * 1024];
	size_t length = fread(ca, 1, sizeof(ca), file);
	fclose(file);
	const char *urls[] = {argv[2], argc == 4 ? argv[3] : NULL};
	if (vitals_release_fetch_from(urls, (size_t)argc - 2, ca, length, "vitals-test", NULL, version, sizeof(version)) != 0) {
		puts("latest=none");
		return 0;
	}
	printf("latest=%s\n", version);
	return 0;
}
