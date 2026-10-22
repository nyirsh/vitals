#include "post_start.h"
#include "reauth.h"
#include "tls13_loader.h"

#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/threadmgr/misc.h>
#include <psp2kern/kernel/threadmgr/mutex.h>
#include <stdint.h>

typedef struct PendingBrowser
{
    SceUID pid;
    SceUID module;
    int http;
    int reauth;
    char path[VITALS_PENDING_BROWSER_PATH_SIZE];
} PendingBrowser;

static PendingBrowser pending[VITALS_PENDING_BROWSER_LIMIT];
static SceUID pending_mutex = -1;
static uint32_t pending_count;

int vitals_post_start_init(void)
{
    if (pending_mutex >= 0)
        return -1;
    SceUID created = ksceKernelCreateMutex("vitals browser start", 0, 0, NULL);
    if (created < 0)
        return created;
    memset(pending, 0, sizeof(pending));
    __atomic_store_n(&pending_count, 0, __ATOMIC_RELEASE);
    pending_mutex = created;
    return 0;
}

int vitals_post_start_destroy(void)
{
    if (pending_mutex < 0)
        return 0;
    int result = ksceKernelDeleteMutex(pending_mutex);
    if (result < 0)
        return result;
    pending_mutex = -1;
    memset(pending, 0, sizeof(pending));
    __atomic_store_n(&pending_count, 0, __ATOMIC_RELEASE);
    return 0;
}

static void fill_target(PendingBrowser *item, const char *path, size_t length, int http)
{
    item->http = http;
    if (http)
        item->path[0] = '\0';
    else
        memcpy(item->path, path, length + 1);
}

static int defer_target(SceUID pid, SceUID module, const char *path, int http)
{
    if (pending_mutex < 0 || pid <= 0 || module <= 0 || (!http && path == NULL))
        return -1;
    size_t length = http ? 0 : strnlen(path, VITALS_PENDING_BROWSER_PATH_SIZE);
    if (!http && (length == 0 || length == VITALS_PENDING_BROWSER_PATH_SIZE))
        return -1;
    int result = ksceKernelLockMutex(pending_mutex, 1, NULL);
    if (result < 0)
        return result;
    size_t available = VITALS_PENDING_BROWSER_LIMIT;
    result = -1;
    for (size_t i = 0; i < VITALS_PENDING_BROWSER_LIMIT; ++i)
    {
        if (pending[i].pid == pid && pending[i].module == module)
        {
            /* An entry holding only a reAuth injection takes the provider injection as well */
            if (!pending[i].http && pending[i].path[0] == '\0')
            {
                fill_target(&pending[i], path, length, http);
                result = 0;
                goto done;
            }
            result = pending[i].http == http && (http || strcmp(pending[i].path, path) == 0) ? 1 : -1;
            goto done;
        }
        if (pending[i].pid == 0 && available == VITALS_PENDING_BROWSER_LIMIT)
            available = i;
    }
    if (available != VITALS_PENDING_BROWSER_LIMIT)
    {
        PendingBrowser *item = &pending[available];
        item->pid = pid;
        item->module = module;
        item->reauth = 0;
        fill_target(item, path, length, http);
        (void)__atomic_add_fetch(&pending_count, 1, __ATOMIC_RELEASE);
        result = 0;
    }
done:
    if (ksceKernelUnlockMutex(pending_mutex, 1) < 0)
        return -1;
    return result;
}

int vitals_post_start_defer(SceUID pid, SceUID module, const char *path)
{
    return defer_target(pid, module, path, 0);
}

int vitals_post_start_defer_http(SceUID pid, SceUID module)
{
    return defer_target(pid, module, NULL, 1);
}

int vitals_post_start_defer_reauth(SceUID pid, SceUID module)
{
    if (pending_mutex < 0 || pid <= 0 || module <= 0)
        return -1;
    int result = ksceKernelLockMutex(pending_mutex, 1, NULL);
    if (result < 0)
        return result;
    size_t available = VITALS_PENDING_BROWSER_LIMIT;
    result = -1;
    for (size_t i = 0; i < VITALS_PENDING_BROWSER_LIMIT; ++i)
    {
        if (pending[i].pid == pid && pending[i].module == module)
        {
            result = pending[i].reauth ? 1 : 0;
            pending[i].reauth = 1;
            goto done;
        }
        if (pending[i].pid == 0 && available == VITALS_PENDING_BROWSER_LIMIT)
            available = i;
    }
    if (available != VITALS_PENDING_BROWSER_LIMIT)
    {
        PendingBrowser *item = &pending[available];
        item->pid = pid;
        item->module = module;
        item->http = 0;
        item->reauth = 1;
        item->path[0] = '\0';
        (void)__atomic_add_fetch(&pending_count, 1, __ATOMIC_RELEASE);
        result = 0;
    }
done:
    if (ksceKernelUnlockMutex(pending_mutex, 1) < 0)
        return -1;
    return result;
}

int vitals_post_start_complete(SceUID pid, SceUID module, int native_result)
{
    char path[VITALS_PENDING_BROWSER_PATH_SIZE];
    int found = 0, http = 0, reauth = 0;
    if (__atomic_load_n(&pending_count, __ATOMIC_ACQUIRE) == 0)
        return 0;
    if (pid == 0)
        pid = ksceKernelGetProcessId();
    if (pending_mutex < 0 || pid <= 0 || module <= 0)
        return -1;
    int result = ksceKernelLockMutex(pending_mutex, 1, NULL);
    if (result < 0)
        return result;
    for (size_t i = 0; i < VITALS_PENDING_BROWSER_LIMIT; ++i)
    {
        if (pending[i].pid != pid || pending[i].module != module)
            continue;
        memcpy(path, pending[i].path, sizeof(path));
        http = pending[i].http;
        reauth = pending[i].reauth;
        memset(&pending[i], 0, sizeof(pending[i]));
        (void)__atomic_sub_fetch(&pending_count, 1, __ATOMIC_RELEASE);
        found = 1;
        break;
    }
    if (ksceKernelUnlockMutex(pending_mutex, 1) < 0)
        return -1;
    if (!found)
        return 0;
    ksceDebugPrintf("vitals: post_start pid=0x%X mod=0x%X native=0x%08X http=%d reauth=%d\n",
                    pid, module, native_result, http, reauth);

    /* Both targets must finish native import linking and startup before injection */
    if (native_result != 0)
        return native_result < 0 ? native_result : -1;
    result = 0;
    if (http)
        result = vitals_kernel_inject_for_pid(pid, module);
    else if (path[0] != '\0')
        result = vitals_kernel_inject_browser_for_pid(pid, module, path);
    /* The reAuth injection is independent of the providers; its result counts only when it is alone */
    if (reauth)
    {
        int reauth_result = vitals_reauth_inject(pid);
        if (!http && path[0] == '\0')
            result = reauth_result;
    }
    return result;
}
