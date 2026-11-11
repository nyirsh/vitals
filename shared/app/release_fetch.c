/* The latest release's number, through curl (release_check.h's vitals_release_fetch): apart from the
 * check's thread (release_check.c), so the host tests can make it against their own servers */

#include "download.h"
#include "release_check.h"
#include "release_version.h"

/* Far larger than a release response; anything bigger is not one */
#define RELEASE_RESPONSE_LIMIT (256u * 1024u)

int vitals_release_fetch(const char *ca, size_t ca_size, const char *user_agent, const volatile int *cancel,
                         char *version, size_t size)
{
	static const char *const urls[] = {VITALS_RELEASE_URL_GITHUB, VITALS_RELEASE_URL_GITLAB};
	return vitals_release_fetch_from(urls, sizeof(urls) / sizeof(urls[0]), ca, ca_size, user_agent, cancel, version,
	                                 size);
}

int vitals_release_fetch_from(const char *const *urls, size_t count, const char *ca, size_t ca_size,
                              const char *user_agent, const volatile int *cancel, char *version, size_t size)
{
	if (version == NULL || size == 0)
		return -1;
	version[0] = '\0';
	for (size_t i = 0; i < count && !(cancel != NULL && *cancel); ++i) {
		if (urls[i] == NULL)
			continue;
		VitalsDownload request = {urls[i], ca, ca_size, user_agent, "Accept: application/json", 6,
		                          RELEASE_RESPONSE_LIMIT, cancel, NULL};
		VitalsDownloaded result;
		int found = vitals_download(&request, &result) == 0 &&
		            vitals_release_tag(result.data, result.size, version, size) == 0;
		vitals_download_free(&result);
		if (found)
			return 0;
	}
	version[0] = '\0';
	return -1;
}
