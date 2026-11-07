#ifndef VITALS_APP_RELEASE_CHECK_H
#define VITALS_APP_RELEASE_CHECK_H

#include <stddef.h>

/* The new-release notice's check, the same on every console: a thread of its own asks GitHub, then
 * GitLab, for the latest release (release_version.h's URLs) through curl (download.h), trusting only
 * the Mozilla bundle the app carries (vitals_paths.h's VITALS_APP_CA_BUNDLE) */

/* Asks for the latest release's number, trusting only ca (PEM): 0 with it in version, or -1 when
 * neither answered with one. *cancel set to nonzero by another thread ends it at once */
int vitals_release_fetch(const char *ca, size_t ca_size, const char *user_agent, const volatile int *cancel,
                         char *version, size_t size);

/* The same from the given URLs, in turn: for the host tests */
int vitals_release_fetch_from(const char *const *urls, size_t count, const char *ca, size_t ca_size,
                              const char *user_agent, const volatile int *cancel, char *version, size_t size);

/* Starts the check, once; nothing else waits for it */
void release_check_start(void);
/* The latest release's number once the check found one ("2.2"), NULL until then and when it found
 * none */
const char *release_check_latest(void);
/* Ends the check at once and waits for its thread, before anything else uses the network: the test,
 * an operation, the app exiting. Nothing when it isn't running */
void release_check_stop(void);

#endif
