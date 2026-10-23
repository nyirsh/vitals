#include "version_check.h"

#include <stdio.h>
#include <stdlib.h>

/* Host-only exercise of the release check against test servers: ca url [url] */
int main(int argc, char **argv) {
    char version[16];
    if (argc < 3 || argc > 4) return 2;
    const char *urls[] = {argv[2], argc == 4 ? argv[3] : NULL};
    if (vitals_fetch_latest_release(urls, (size_t)argc - 2, argv[1], "vitals-test", 3, NULL, version,
            sizeof(version)) != 0) {
        puts("latest=none");
        return 0;
    }
    printf("latest=%s\n", version);
    return 0;
}
