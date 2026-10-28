/* The libhttp exports <psp2/net/http.h> leaves out, which vitals_http_api.yml.in lists */
#ifndef VH_HTTP_EXTRA_H
#define VH_HTTP_EXTRA_H

#include <psp2/net/http.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Not in the SDK header; signatures as the PS4 libhttp has them, where the Vita's is known to match */
int sceHttpAbortRequestForce(int reqId);
int sceHttpAddRequestHeaderRaw(int id, const char *name, const char *value, unsigned int mode);
int sceHttpAuthCacheFlush(void);
int sceHttpRedirectCacheFlush(void);
int sceHttpCreateRequest2(int connId, const char *method, const char *path, unsigned long long int contentLength);
int sceHttpCreateRequestWithURL2(int connId, const char *method, const char *url, unsigned long long int contentLength);
int sceHttpRequestGetAllHeaders(int reqId, char **header, unsigned int *headerSize);
int sceHttpGetLastErrno(int reqId, int *errNum);
int sceHttpSetNonblock(int id, int enable);
int sceHttpGetNonblock(int id, int *enable);
int sceHttpSetAcceptEncodingGZIPEnabled(int id, int enable);
int sceHttpGetAcceptEncodingGZIPEnabled(int id, int *enable);
int sceHttpSetDefaultAcceptEncodingGZIPEnabled(int enable);
int sceHttpSetInflateGZIPEnabled(int id, int enable);
int sceHttpSetIcmOption(int id, int value);
int sceHttpGetIcmOption(int id, int *value);
int sceHttpsEnableOption2(int id, unsigned int sslFlags);
int sceHttpsDisableOption2(int id, unsigned int sslFlags);
int sceHttpsEnableOptionPrivate(int id, unsigned int sslFlags);
int sceHttpsDisableOptionPrivate(int id, unsigned int sslFlags);
int sceHttpSslIsCtxCreated(int id, int *isCreated);

/* The cookie jar's limits and persistence */
int sceHttpCookieFlush(void);
int sceHttpCookieExport(void *buffer, unsigned int bufferSize, unsigned int *exportSize);
int sceHttpCookieImport(const void *buffer, unsigned int bufferSize);
int sceHttpGetCookieStats(void *stats);
int sceHttpSetCookieMaxNum(unsigned int num);
int sceHttpSetCookieMaxNumPerDomain(unsigned int num);
int sceHttpSetCookieMaxSize(unsigned int size);
int sceHttpSetCookieTotalMaxSize(unsigned int size);

/* Non-blocking requests */
typedef void *SceHttpEpollHandle;

/* What sceHttpWaitRequest reports for a request, as Sony's libhttp lays it out */
typedef struct SceHttpNBEvent
{
    unsigned int events;
    unsigned int eventDetail;
    int id;
    void *userArg;
} SceHttpNBEvent;

#define SCE_HTTP_NB_EVENT_IN 0x00000001u
#define SCE_HTTP_NB_EVENT_OUT 0x00000002u
#define SCE_HTTP_NB_EVENT_SOCK_ERR 0x00000008u
#define SCE_HTTP_NB_EVENT_HUP 0x00000010u
#define SCE_HTTP_NB_EVENT_ICM 0x00000020u
#define SCE_HTTP_NB_EVENT_RESOLVED 0x00010000u
#define SCE_HTTP_NB_EVENT_RESOLVER_ERR 0x00020000u
int sceHttpCreateEpoll(SceHttpEpollHandle *eh);
int sceHttpDestroyEpoll(SceHttpEpollHandle eh);
int sceHttpSetEpoll(int id, SceHttpEpollHandle eh, void *userArg);
int sceHttpUnsetEpoll(int id);
int sceHttpGetEpoll(int id, SceHttpEpollHandle *eh, void **userArg);
int sceHttpSetEpollId(int id, int epollId);
int sceHttpGetEpollId(int id, int *epollId);
int sceHttpWaitRequest(SceHttpEpollHandle eh, SceHttpNBEvent *nbev, int maxevents, int timeout);
int sceHttpWaitRequestCB(SceHttpEpollHandle eh, SceHttpNBEvent *nbev, int maxevents, int timeout);
int sceHttpAbortWaitRequest(SceHttpEpollHandle eh);

#ifdef __cplusplus
}
#endif

#endif
