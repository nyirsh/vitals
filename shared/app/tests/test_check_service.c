/* The connection test's lifecycle (shared/app/check_service.c) on this machine's threads: a run on
 * its worker, its results while it goes, a second start while one runs, cancelling, the console's
 * watchdog, saving the report once and only for a finished run, and stopping. The run is a stand-in
 * the test lets go of, as check_run.c's requests would end; built against each console's
 * check_result.h */

#include "check.h"
#include "platform.h"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---- the platform's threads and lock, with pthreads ---- */

struct PlatformThread {
	pthread_t id;
	void (*run)(void *);
	void *argument;
};
struct PlatformMutex {
	pthread_mutex_t id;
};
static int thread_fails;

static void *thread_entry(void *argument)
{
	PlatformThread *thread = argument;
	thread->run(thread->argument);
	return NULL;
}

PlatformThread *platform_thread_start(const char *name, void (*run)(void *), void *argument, size_t stack_size)
{
	(void)name, (void)stack_size;
	if (thread_fails)
		return NULL;
	PlatformThread *thread = malloc(sizeof(*thread));
	assert(thread != NULL);
	thread->run = run;
	thread->argument = argument;
	assert(pthread_create(&thread->id, NULL, thread_entry, thread) == 0);
	return thread;
}

void platform_thread_join(PlatformThread *thread)
{
	pthread_join(thread->id, NULL);
	free(thread);
}

PlatformMutex *platform_mutex_create(const char *name)
{
	(void)name;
	PlatformMutex *mutex = malloc(sizeof(*mutex));
	assert(mutex != NULL && pthread_mutex_init(&mutex->id, NULL) == 0);
	return mutex;
}

void platform_mutex_lock(PlatformMutex *mutex)
{
	pthread_mutex_lock(&mutex->id);
}

void platform_mutex_unlock(PlatformMutex *mutex)
{
	pthread_mutex_unlock(&mutex->id);
}

/* ---- the run: it waits until the test lets it end, or it's cancelled ---- */

static pthread_mutex_t gate_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate = PTHREAD_COND_INITIALIZER;
static int released, cancelled, runs, resets, cancels, watches, saves, save_fails;
static const char *run_notice = "";

void check_run(const CheckBackend *backend, CheckService *service, char *notice, size_t size)
{
	(void)backend;
	pthread_mutex_lock(&gate_lock);
	++runs;
	while (!released && !cancelled)
		pthread_cond_wait(&gate, &gate_lock);
	int stopped = cancelled;
	pthread_mutex_unlock(&gate_lock);
	check_lock();
	service->protocols[3].state = CHECK_PASS;
	service->complete = 1;
	service->interrupted = stopped;
	check_unlock();
	snprintf(notice, size, "%s", run_notice);
}

static void let_go(void)
{
	pthread_mutex_lock(&gate_lock);
	released = 1;
	pthread_cond_broadcast(&gate);
	pthread_mutex_unlock(&gate_lock);
}

/* ---- the console ---- */

static void reset(void)
{
	pthread_mutex_lock(&gate_lock);
	++resets;
	released = cancelled = 0;
	pthread_mutex_unlock(&gate_lock);
}

static void cancel(void)
{
	pthread_mutex_lock(&gate_lock);
	++cancels;
	cancelled = 1;
	pthread_cond_broadcast(&gate);
	pthread_mutex_unlock(&gate_lock);
}

static void watch(void)
{
	++watches;
}

static int save(const CheckService *service, char *path, size_t size)
{
	assert(service->complete && !service->interrupted);
	++saves;
	snprintf(path, size, "reports/connection-test-%d.txt", saves);
	return save_fails ? -1 : 0;
}

static const CheckBackend backend;
const CheckConsole check_console = {&backend, reset, cancel, watch, save};

/* Polls until the run has ended */
static void wait_done(CheckService *view, char *notice, size_t size)
{
	for (int i = 0; i < 2000 && vitals_check_poll(view, notice, size); ++i)
		usleep(1000);
	assert(!vitals_check_poll(view, notice, size));
}

int main(void)
{
	CheckService view;
	char notice[120];

	/* Before any run: nothing known, nothing to cancel, stop or save */
	vitals_check_cancel();
	vitals_check_stop();
	assert(vitals_check_poll(&view, notice, sizeof(notice)) == 0);
	assert(view.vitals_enabled == -1 && view.tls_active == -1 && !view.started && notice[0] == '\0');
	assert(vitals_check_save_report() == -1 && cancels == 0);

	/* A run: going while it isn't let go, the console's watchdog asked at each poll */
	vitals_check_start();
	assert(vitals_check_poll(&view, notice, sizeof(notice)) == 1 && view.started && !view.complete);
	assert(view.libhttp_active == -1 && watches == 1 && resets == 1);
	/* A second start while it goes changes nothing */
	vitals_check_start();
	assert(resets == 1);
	/* Nothing to save while it goes */
	assert(vitals_check_save_report() == -1 && saves == 0);
	let_go();
	wait_done(&view, notice, sizeof(notice));
	assert(view.complete && !view.interrupted && view.protocols[3].state == CHECK_PASS && runs == 1);

	/* Saved once: the path kept for the screen, then "saved already" */
	assert(vitals_check_save_report() == 0 && saves == 1);
	vitals_check_poll(&view, notice, sizeof(notice));
	assert(view.report_saved == 1 && strcmp(view.report, "reports/connection-test-1.txt") == 0);
	assert(vitals_check_save_report() == 1 && saves == 1);

	/* A new run clears the last one's results, its report included */
	vitals_check_start();
	vitals_check_poll(&view, notice, sizeof(notice));
	assert(view.started && !view.complete && view.report_saved == 0 && view.report[0] == '\0' && resets == 2);
	/* Cancelled: the run ends interrupted, with its notice, and isn't saved */
	run_notice = "Cancelled / not tested";
	vitals_check_cancel();
	wait_done(&view, notice, sizeof(notice));
	assert(view.interrupted && strcmp(notice, "Cancelled / not tested") == 0 && cancels == 1);
	assert(vitals_check_save_report() == -1 && saves == 1);
	run_notice = "";

	/* A report that can't be written says so, and can be tried again */
	vitals_check_start();
	let_go();
	wait_done(&view, notice, sizeof(notice));
	assert(notice[0] == '\0');
	save_fails = 1;
	assert(vitals_check_save_report() == -1);
	vitals_check_poll(&view, notice, sizeof(notice));
	assert(view.report_saved == -1);
	save_fails = 0;
	assert(vitals_check_save_report() == 0 && saves == 3);

	/* Stopping cancels a run that goes and waits for its thread */
	vitals_check_start();
	vitals_check_stop();
	assert(vitals_check_poll(&view, notice, sizeof(notice)) == 0 && view.interrupted && cancels == 2);

	/* A thread that can't start: the run doesn't go, and the screen says why */
	thread_fails = 1;
	vitals_check_start();
	assert(vitals_check_poll(&view, notice, sizeof(notice)) == 0);
	assert(strcmp(notice, "The test's thread couldn't start") == 0);
	thread_fails = 0;

	puts("connection test's lifecycle: run, second start, polling, saving once, cancel, failed save, stop, "
	     "failed thread PASS");
	return 0;
}
