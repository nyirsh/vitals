/* The new-release notice's check (release_check.h): a thread of its own reads the Mozilla bundle the
 * app carries, waits for the console's network and asks GitHub, then GitLab (release_fetch.c) */

#include "release_check.h"

#include "vitals/log.h"
#include "console.h"
#include "platform.h"
#include "vitals_paths.h"

#include <stdlib.h>
#include <string.h>

/* Mozilla's bundle is some 230 KB */
#define CA_BUNDLE_LIMIT (1024u * 1024u)

static PlatformThread *thread;
static volatile int cancel, done;
static char latest[16];

static int stopped(void)
{
	return cancel;
}

static void run(void *argument)
{
	char path[320], version[16];
	(void)argument;
	console_app_file(VITALS_APP_CA_BUNDLE, path, sizeof(path));
	char *ca = malloc(CA_BUNDLE_LIMIT);
	long length = ca != NULL ? platform_read_file(path, ca, CA_BUNDLE_LIMIT) : -1;
	if (length > 0 && (size_t)length < CA_BUNDLE_LIMIT && console_network_start(stopped) == 0 &&
	    vitals_release_fetch(ca, (size_t)length, "vitals/" VITALS_VERSION, &cancel, version, sizeof(version)) == 0)
		memcpy(latest, version, sizeof(latest));
	VITALS_VERBOSE("release check: %s", latest[0] != '\0' ? latest : "no answer");
	free(ca);
	__atomic_store_n(&done, 1, __ATOMIC_RELEASE);
}

void release_check_start(void)
{
	if (thread != NULL)
		return;
	cancel = 0;
	/* curl's TLS handshake runs deep */
	thread = platform_thread_start("vitals release check", run, NULL, 256 * 1024);
	/* No thread, no check: nothing is being looked for */
	if (thread == NULL)
		__atomic_store_n(&done, 1, __ATOMIC_RELEASE);
}

int release_check_searching(void)
{
	return !__atomic_load_n(&done, __ATOMIC_ACQUIRE);
}

const char *release_check_latest(void)
{
	return __atomic_load_n(&done, __ATOMIC_ACQUIRE) && latest[0] != '\0' ? latest : NULL;
}

void release_check_stop(void)
{
	if (thread == NULL)
		return;
	cancel = 1;
	platform_thread_join(thread);
	thread = NULL;
}
