#ifndef VITALS_APP_VERSION_CHECK_H
#define VITALS_APP_VERSION_CHECK_H

#include <stddef.h>

/* The latest published release, from GitHub and then GitLab; only reads it, nothing is downloaded
 * or installed */
#define VITALS_RELEASE_URL_GITHUB "https://api.github.com/repos/nyirsh/vitals/releases/latest"
#define VITALS_RELEASE_URL_GITLAB "https://gitlab.com/api/v4/projects/nyirsh%2Fvitals/releases?per_page=1"

/* Asks each URL in turn for its latest release and copies the first valid release number to
 * version; certificates are checked against ca_path, and *cancel set to nonzero by another thread
 * stops the transfer at once
 * Returns 0, or -1 when no URL gave a release number */
int vitals_fetch_latest_release(const char *const *urls, size_t count, const char *ca_path,
    const char *user_agent, long timeout_seconds, const volatile int *cancel, char *version, size_t size);

#endif
