/* The connection test for every console (check.h): the run on a worker thread, its results for the
 * screen under one lock, cancelling it and saving its report. The console's part is check_console
 * (its check.c) */

#include "check.h"

#include "platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The report's parser keeps its tokens static, but the requests nest deep in each HTTP library */
#define WORKER_STACK (256 * 1024)

static PlatformMutex *guard;
static PlatformThread *worker;
static CheckService service;
/* A run is going; the lock couldn't be made, so no run can start */
static int busy, start_failed;
/* Why the last run stopped early, for the screen */
static char notice[120];

void check_lock(void)
{
	if (guard != NULL)
		platform_mutex_lock(guard);
}

void check_unlock(void)
{
	if (guard != NULL)
		platform_mutex_unlock(guard);
}

/* Results before any are known */
static void clear(CheckService *s)
{
	memset(s, 0, sizeof(*s));
	s->vitals_enabled = s->libhttp_active = s->tls_active = s->redirects_off = -1;
}

static void run(void *argument)
{
	(void)argument;
	char text[sizeof(notice)] = "";
	check_run(check_console.backend, &service, text, sizeof(text));
	check_lock();
	if (text[0] != '\0')
		snprintf(notice, sizeof(notice), "%s", text);
	busy = 0;
	check_unlock();
}

static void join_worker(void)
{
	if (worker != NULL) {
		platform_thread_join(worker);
		worker = NULL;
	}
}

void vitals_check_start(void)
{
	if (guard == NULL) {
		guard = platform_mutex_create("vitals test");
		if (guard == NULL) {
			start_failed = 1;
			return;
		}
	}
	check_lock();
	int running = busy;
	check_unlock();
	if (running)
		return;
	join_worker();
	check_lock();
	clear(&service);
	service.started = 1;
	notice[0] = '\0';
	busy = 1;
	check_unlock();
	check_console.reset();
	worker = platform_thread_start("vitals connection test", run, NULL, WORKER_STACK);
	if (worker == NULL) {
		check_lock();
		busy = 0;
		snprintf(notice, sizeof(notice), "The test's thread couldn't start");
		check_unlock();
	}
}

void vitals_check_cancel(void)
{
	if (guard != NULL)
		check_console.cancel();
}

int vitals_check_poll(CheckService *view, char *message, size_t size)
{
	if (guard == NULL) {
		clear(view);
		if (size != 0)
			snprintf(message, size, "%s", start_failed ? "The test couldn't start" : "");
		return 0;
	}
	check_lock();
	int running = busy;
	check_unlock();
	/* Outside the lock, which the console's watch takes itself */
	if (running && check_console.watch != NULL)
		check_console.watch();
	check_lock();
	*view = service;
	if (size != 0)
		snprintf(message, size, "%s", notice);
	running = busy;
	check_unlock();
	return running;
}

int vitals_check_save_report(void)
{
	if (guard == NULL)
		return -1;
	check_lock();
	const int saved = service.report_saved == 1;
	const int ready = !busy && service.started && service.complete && !service.interrupted;
	check_unlock();
	if (saved)
		return 1;
	if (!ready)
		return -1;
	/* The finished run's results, copied so the report is written without holding the lock */
	CheckService *snapshot = malloc(sizeof(*snapshot));
	if (snapshot == NULL)
		return -1;
	check_lock();
	*snapshot = service;
	check_unlock();
	char path[sizeof(service.report)];
	int result = check_console.save(snapshot, path, sizeof(path)) == 0 ? 0 : -1;
	free(snapshot);
	check_lock();
	service.report_saved = result == 0 ? 1 : -1;
	if (result == 0)
		snprintf(service.report, sizeof(service.report), "%s", path);
	check_unlock();
	return result;
}

void vitals_check_stop(void)
{
	if (guard == NULL)
		return;
	check_console.cancel();
	join_worker();
}
