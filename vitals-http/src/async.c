#include "vh.h"

#include "diagnostics.h"

#include <string.h>

/* Non-blocking requests: a send or read the app starts runs on a worker thread, the call returns
 * VH_ERROR_EAGAIN, and the app calls again for the result. An epoll set on the request (or on what
 * it was created from) reports each finished call once to sceHttpWaitRequest, laid out as Sony's
 * libhttp does it */

#define VH_EPOLL_MAX 32u

typedef struct VhEpoll
{
    /* sceHttpAbortWaitRequest was called; the next wait returns at once */
    int aborted;
} VhEpoll;

static VhEpoll *g_epolls[VH_EPOLL_MAX];

static void worker(void *argument)
{
    VhObject *object = argument;
    VhRequest *request = &object->as.request;
    int result;

    VITALS_VERBOSE("worker request %d %s", object->id, request->async == VH_ASYNC_SEND ? "send" : "read");
    if (request->async == VH_ASYNC_SEND)
        result = vh_request_perform(object, request->async_data, request->async_size);
    else
        result = vh_request_read(request, request->async_data, request->async_size);
    vh_lock();
    request->async_result = result;
    if (request->async == VH_ASYNC_READ)
        request->async_size = result > 0 ? (unsigned int)result : 0;
    request->async_done = 1;
    /* The object is freed here when the app deleted it meanwhile */
    if (request->async == VH_ASYNC_SEND)
        vh_request_sent(object, result);
    else
        vh_request_read_done(object, result);
    vh_platform_notify();
    vh_unlock();
}

int vh_async_start(VhObject *object)
{
    int result = vh_platform_thread(worker, object);
    VITALS_VERBOSE("worker start request %d rc=%08X", object->id, (unsigned int)result);
    return result;
}

/* ---- epoll ---- */

/* The epoll the handle is, with the lock held; NULL when it isn't one */
static VhEpoll *epoll_of(SceHttpEpollHandle handle)
{
    for (unsigned int i = 0; handle != NULL && i < VH_EPOLL_MAX; ++i)
        if (g_epolls[i] == handle)
            return g_epolls[i];
    return NULL;
}

void vh_epoll_forget(SceHttpEpollHandle epoll)
{
    for (unsigned int slot = 0; slot < VH_OBJECT_MAX; ++slot) {
        VhObject *object = vh_object_at(slot);
        if (object != NULL && object->settings.epoll == epoll)
            object->settings.epoll = NULL;
    }
}

void vh_epoll_clear(void)
{
    for (unsigned int i = 0; i < VH_EPOLL_MAX; ++i) {
        vh_free(g_epolls[i]);
        g_epolls[i] = NULL;
    }
}

int sceHttpCreateEpoll(SceHttpEpollHandle *eh)
{
    VH_TRACE();
    if (eh == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    vh_lock();
    int result = vh_initialized();
    unsigned int slot = 0;
    while (result == 0 && slot < VH_EPOLL_MAX && g_epolls[slot] != NULL)
        ++slot;
    if (result == 0 && slot == VH_EPOLL_MAX)
        result = (int)SCE_HTTP_ERROR_OUT_OF_SIZE;
    if (result == 0) {
        VhEpoll *epoll = vh_alloc(sizeof(*epoll));
        if (epoll == NULL)
            result = (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
        else {
            memset(epoll, 0, sizeof(*epoll));
            g_epolls[slot] = epoll;
            *eh = epoll;
        }
    }
    vh_unlock();
    return result;
}

int sceHttpDestroyEpoll(SceHttpEpollHandle eh)
{
    VH_TRACE();
    vh_lock();
    int result = vh_initialized();
    VhEpoll *epoll = result == 0 ? epoll_of(eh) : NULL;
    if (result == 0 && epoll == NULL)
        result = (int)SCE_HTTP_ERROR_INVALID_ID;
    if (epoll != NULL) {
        vh_epoll_forget(eh);
        for (unsigned int i = 0; i < VH_EPOLL_MAX; ++i)
            if (g_epolls[i] == epoll)
                g_epolls[i] = NULL;
        vh_free(epoll);
        /* A thread waiting on it returns */
        vh_platform_notify();
    }
    vh_unlock();
    return result;
}

/* The settings of the object with that ID, with the lock held; NULL and *result set otherwise */
static VhSettings *settings_of(int id, int *result)
{
    *result = vh_initialized();
    if (*result != 0)
        return NULL;
    VhObject *object = vh_find(id, VH_FREE);
    if (object == NULL)
        *result = (int)SCE_HTTP_ERROR_INVALID_ID;
    return object != NULL ? &object->settings : NULL;
}

int sceHttpSetEpoll(int id, SceHttpEpollHandle eh, void *userArg)
{
    VH_TRACE();
    int result;
    vh_lock();
    VhSettings *settings = settings_of(id, &result);
    if (settings != NULL && epoll_of(eh) == NULL)
        result = (int)SCE_HTTP_ERROR_INVALID_VALUE;
    else if (settings != NULL) {
        settings->epoll = eh;
        settings->epoll_argument = userArg;
    }
    vh_unlock();
    return result;
}

int sceHttpUnsetEpoll(int id)
{
    VH_TRACE();
    int result;
    vh_lock();
    VhSettings *settings = settings_of(id, &result);
    if (settings != NULL) {
        settings->epoll = NULL;
        settings->epoll_argument = NULL;
    }
    vh_unlock();
    return result;
}

int sceHttpGetEpoll(int id, SceHttpEpollHandle *eh, void **userArg)
{
    VH_TRACE();
    int result;
    if (eh == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    vh_lock();
    VhSettings *settings = settings_of(id, &result);
    if (settings != NULL) {
        *eh = settings->epoll;
        if (userArg != NULL)
            *userArg = settings->epoll_argument;
    }
    vh_unlock();
    return result;
}

/* Kept and returned; the requests' sockets aren't in an epoll of the app's own */
int sceHttpSetEpollId(int id, int epollId)
{
    VH_TRACE();
    int result;
    vh_lock();
    VhSettings *settings = settings_of(id, &result);
    if (settings != NULL)
        settings->epoll_id = epollId;
    vh_unlock();
    return result;
}

int sceHttpGetEpollId(int id, int *epollId)
{
    VH_TRACE();
    int result;
    if (epollId == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    vh_lock();
    VhSettings *settings = settings_of(id, &result);
    if (settings != NULL)
        *epollId = settings->epoll_id;
    vh_unlock();
    return result;
}

/* The finished calls of the epoll's requests not reported yet, with the lock held */
static int collect(SceHttpEpollHandle eh, SceHttpNBEvent *events, int max)
{
    int count = 0;
    for (unsigned int slot = 0; slot < VH_OBJECT_MAX && count < max; ++slot) {
        VhObject *object = vh_object_at(slot);
        if (object == NULL || object->kind != VH_REQUEST || object->doomed || object->settings.epoll != eh)
            continue;
        VhRequest *request = &object->as.request;
        if (request->async == VH_ASYNC_NONE || !request->async_done || request->async_reported)
            continue;
        unsigned int flags;
        if (request->async_result < 0)
            flags = SCE_HTTP_NB_EVENT_SOCK_ERR;
        else if (request->async == VH_ASYNC_SEND)
            /* The response's headers are in: the body can be read */
            flags = SCE_HTTP_NB_EVENT_OUT | SCE_HTTP_NB_EVENT_IN;
        else
            flags = SCE_HTTP_NB_EVENT_IN | (request->async_result == 0 ? SCE_HTTP_NB_EVENT_HUP : 0u);
        events[count].events = flags;
        events[count].eventDetail = 0;
        events[count].id = object->id;
        events[count].userArg = object->settings.epoll_argument;
        request->async_reported = 1;
        ++count;
    }
    return count;
}

/* The number of events, 0 when the timeout (microseconds; negative: none) passed first */
static int wait_request(SceHttpEpollHandle eh, SceHttpNBEvent *nbev, int maxevents, int timeout)
{
    if (nbev == NULL || maxevents <= 0)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    unsigned long long start = vh_platform_clock_us();
    for (;;) {
        unsigned int generation = vh_platform_generation();
        vh_lock();
        int result = vh_initialized();
        VhEpoll *epoll = result == 0 ? epoll_of(eh) : NULL;
        if (result == 0 && epoll == NULL)
            result = (int)SCE_HTTP_ERROR_INVALID_ID;
        else if (epoll != NULL && epoll->aborted) {
            epoll->aborted = 0;
            result = (int)SCE_HTTP_ERROR_ABORTED;
        } else if (epoll != NULL)
            result = collect(eh, nbev, maxevents);
        vh_unlock();
        if (result != 0)
            return result;
        long long left = -1;
        if (timeout >= 0) {
            left = (long long)timeout - (long long)(vh_platform_clock_us() - start);
            if (left <= 0)
                return 0;
        }
        vh_platform_wait(generation, left);
    }
}

int sceHttpWaitRequest(SceHttpEpollHandle eh, SceHttpNBEvent *nbev, int maxevents, int timeout)
{
    VH_TRACE();
    return wait_request(eh, nbev, maxevents, timeout);
}

/* The same: this library's waits run no callbacks of their own */
int sceHttpWaitRequestCB(SceHttpEpollHandle eh, SceHttpNBEvent *nbev, int maxevents, int timeout)
{
    VH_TRACE();
    return wait_request(eh, nbev, maxevents, timeout);
}

int sceHttpAbortWaitRequest(SceHttpEpollHandle eh)
{
    VH_TRACE();
    vh_lock();
    int result = vh_initialized();
    VhEpoll *epoll = result == 0 ? epoll_of(eh) : NULL;
    if (result == 0 && epoll == NULL)
        result = (int)SCE_HTTP_ERROR_INVALID_ID;
    if (epoll != NULL) {
        epoll->aborted = 1;
        vh_platform_notify();
    }
    vh_unlock();
    return result;
}
