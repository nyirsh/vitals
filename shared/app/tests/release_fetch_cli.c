/* Host-only exercise of the release check's fetch (release_fetch.c) against test servers, for the
 * Vita's tests/test_version_check.py: ca url [url] */

#include "release_check.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	char version[16];
	if (argc < 3 || argc > 4)
		return 2;
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
