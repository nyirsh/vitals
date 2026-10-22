#include "post_start.h"
#include <kernel_mock.h>
#include <assert.h>
#include <stdio.h>

static int mutex_live, locked, create_failure, lock_failure, delete_failure;
static unsigned int locks, injections, pid_queries, http_injections, reauths;
static SceUID expected_pid = 99, expected_module = 88;
static const char *expected_path = "wb0:/vitals/vitals.suprx";
static int injection_result;

SceUID ksceKernelGetProcessId(void) { ++pid_queries; return 99; }
SceUID ksceKernelCreateMutex(const char *name, unsigned int attr, int count, const void *options) {
    assert(name != NULL && attr == 0 && count == 0 && options == NULL && !mutex_live);
    if (create_failure) return -61;
    mutex_live = 1;
    return 17;
}
int ksceKernelDeleteMutex(SceUID id) {
    assert(id == 17 && mutex_live && !locked);
    if (delete_failure) return -62;
    mutex_live = 0;
    return 0;
}
int ksceKernelLockMutex(SceUID id, int count, unsigned int *timeout) {
    assert(id == 17 && mutex_live && !locked && count == 1 && timeout == NULL);
    ++locks;
    if (lock_failure) return -63;
    locked = 1;
    return 0;
}
int ksceKernelUnlockMutex(SceUID id, int count) {
    assert(id == 17 && count == 1 && locked);
    locked = 0;
    return 0;
}
int ksceDebugPrintf(const char *format, ...) { (void)format; return 0; }
int vitals_kernel_inject_browser_for_pid(SceUID pid, SceUID module, const char *path) {
    assert(!locked && pid == expected_pid && module == expected_module);
    assert(strcmp(path, expected_path) == 0);
    ++injections;
    assert(vitals_post_start_complete(pid, module, 0) == 0);
    return injection_result;
}

int vitals_reauth_inject(SceUID pid) {
    assert(!locked && pid == expected_pid);
    ++reauths;
    return -91;
}

int vitals_kernel_inject_for_pid(SceUID pid, SceUID module) {
    assert(!locked && pid == expected_pid && module == expected_module);
    ++http_injections;
    assert(vitals_post_start_complete(pid, module, 0) == 0);
    return injection_result;
}

int main(void) {
    assert(vitals_post_start_complete(0, 88, 0) == 0 && locks == 0 && pid_queries == 0);
    assert(vitals_post_start_defer(99, 88, expected_path) < 0);
    create_failure = 1;
    assert(vitals_post_start_init() == -61);
    create_failure = 0;
    assert(vitals_post_start_init() == 0);
    assert(vitals_post_start_init() < 0);
    char path[VITALS_PENDING_BROWSER_PATH_SIZE];
    strcpy(path, expected_path);
    assert(vitals_post_start_defer(99, 88, path) == 0 && injections == 0);
    path[0] = 'X';
    assert(vitals_post_start_defer(99, 88, expected_path) == 1);
    assert(vitals_post_start_defer(99, 88, path) < 0);
    assert(vitals_post_start_complete(100, 88, 0) == 0);
    assert(vitals_post_start_complete(99, 89, 0) == 0 && injections == 0);
    assert(vitals_post_start_complete(0, 88, 0) == 0 && injections == 1 && pid_queries == 1);
    unsigned int before_locks = locks;
    assert(vitals_post_start_complete(0, 88, 0) == 0 && locks == before_locks && injections == 1);
    for (unsigned int i = 0; i < VITALS_PENDING_BROWSER_LIMIT; ++i)
        assert(vitals_post_start_defer(99, 88 + (SceUID)i, expected_path) == 0);
    assert(vitals_post_start_defer(99, 123, expected_path) < 0);
    for (unsigned int i = 0; i < VITALS_PENDING_BROWSER_LIMIT; ++i) {
        expected_module = 88 + (SceUID)i;
        assert(vitals_post_start_complete(99, expected_module, -73) < 0);
    }
    expected_module = 88;
    assert(injections == 1);
    assert(vitals_post_start_defer(99, 88, expected_path) == 0);
    lock_failure = 1;
    assert(vitals_post_start_complete(99, 88, 0) < 0 && injections == 1);
    lock_failure = 0;
    assert(vitals_post_start_complete(99, 88, 0) == 0 && injections == 2);
    assert(vitals_post_start_defer_http(99, 88) == 0 && http_injections == 0);
    assert(vitals_post_start_defer_http(99, 88) == 1);
    assert(vitals_post_start_defer(99, 88, expected_path) < 0);
    assert(vitals_post_start_complete(99, 88, -73) == -73 && http_injections == 0);
    assert(vitals_post_start_defer_http(99, 88) == 0);
    assert(vitals_post_start_complete(99, 88, 0) == 0 && http_injections == 1);
    assert(vitals_post_start_complete(99, 88, 0) == 0 && http_injections == 1);
    injection_result = -81;
    assert(vitals_post_start_defer_http(99, 88) == 0);
    assert(vitals_post_start_complete(99, 88, 0) == -81 && http_injections == 2);
    assert(vitals_post_start_defer(99, 88, expected_path) == 0);
    assert(vitals_post_start_complete(99, 88, 0) == -81);
    assert(vitals_post_start_defer(0, 88, expected_path) < 0);
    assert(vitals_post_start_defer(99, 0, expected_path) < 0);
    assert(vitals_post_start_defer(99, 88, NULL) < 0);
    assert(vitals_post_start_defer(99, 88, "") < 0);
    memset(path, 'x', sizeof(path));
    assert(vitals_post_start_defer(99, 88, path) < 0);

    /* A redirect alone: injected after start, with its own result */
    injection_result = 0;
    unsigned int before_http = http_injections, before_browser = injections;
    assert(vitals_post_start_defer_reauth(99, 88) == 0);
    assert(vitals_post_start_defer_reauth(99, 88) == 1);
    assert(vitals_post_start_complete(99, 88, -73) == -73 && reauths == 0);
    assert(vitals_post_start_defer_reauth(99, 88) == 0);
    assert(vitals_post_start_complete(99, 88, 0) == -91 && reauths == 1);
    assert(http_injections == before_http && injections == before_browser);
    /* Combined with the provider injection of the same module, in either order; the provider's
     * result is the one returned */
    assert(vitals_post_start_defer_http(99, 88) == 0);
    assert(vitals_post_start_defer_reauth(99, 88) == 0);
    assert(vitals_post_start_complete(99, 88, 0) == 0 && reauths == 2 && http_injections == before_http + 1);
    assert(vitals_post_start_defer_reauth(99, 88) == 0);
    assert(vitals_post_start_defer_http(99, 88) == 0);
    assert(vitals_post_start_defer(99, 88, expected_path) < 0);
    assert(vitals_post_start_complete(99, 88, 0) == 0 && reauths == 3 && http_injections == before_http + 2);
    assert(vitals_post_start_defer_reauth(99, 88) == 0);
    assert(vitals_post_start_defer(99, 88, expected_path) == 0);
    assert(vitals_post_start_complete(99, 88, 0) == 0 && reauths == 4 && injections == before_browser + 1);
    assert(vitals_post_start_complete(99, 88, 0) == 0 && reauths == 4);
    assert(vitals_post_start_defer_reauth(0, 88) < 0 && vitals_post_start_defer_reauth(99, 0) < 0);
    delete_failure = 1;
    assert(vitals_post_start_destroy() == -62 && mutex_live);
    delete_failure = 0;
    assert(vitals_post_start_destroy() == 0 && !mutex_live);
    assert(vitals_post_start_init() == 0 && vitals_post_start_destroy() == 0);
    assert(vitals_post_start_defer_reauth(99, 88) < 0);
    puts("post-start queue: native completion precedes injection; ownership, bounds, cleanup and reentry PASS");
    return 0;
}
