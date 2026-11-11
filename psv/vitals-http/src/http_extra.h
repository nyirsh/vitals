/* The libhttp exports <psp2/net/http.h> leaves out, which vitals_http_api.yml.in lists */
#ifndef VH_HTTP_EXTRA_H
#define VH_HTTP_EXTRA_H

#include <psp2/net/http.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A request header, as sceHttpRequestGetAllHeaders lists them */
typedef struct SceHttpHeaderPair
{
    const char *name;
    const char *value;
} SceHttpHeaderPair;

/* Not in the SDK header; signatures as the PS4 libhttp has them, where the Vita's is known to match,
 * and as Sony's code takes them otherwise */
int sceHttpAbortRequestForce(int reqId);
/* One "Name: value" line, added as sceHttpAddRequestHeader adds it; mode must be
 * SCE_HTTP_HEADER_ADD */
int sceHttpAddRequestHeaderRaw(int id, const char *header, unsigned int mode);
int sceHttpAuthCacheFlush(void);
int sceHttpRedirectCacheFlush(void);
int sceHttpCreateRequest2(int connId, const char *method, const char *path, unsigned long long int contentLength);
int sceHttpCreateRequestWithURL2(int connId, const char *method, const char *url, unsigned long long int contentLength);
/* The request's headers as name/value pairs, *count of them; pairs may be NULL to count them. The
 * Content-Length value is written to lengthBuffer; without it, *lengthBufferSize is set to the size
 * it needs. The pointers last until the request's headers change */
int sceHttpRequestGetAllHeaders(int reqId, SceHttpHeaderPair *pairs, unsigned int *count, char *lengthBuffer,
                                unsigned int *lengthBufferSize);
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

/* The exports no header or NID database names, as Sony's code takes them (private.c) */
typedef struct SceHttpPrivateConnectionStats
{
    int alive;      /* its socket is connected, and wasn't shut down */
    int shut_down;
    int socket;     /* -1 without one */
    int first_socket;
} SceHttpPrivateConnectionStats;
typedef struct SceHttpPrivateRequestStats
{
    int socket;     /* its connection's, -1 without one */
    int own_socket; /* Sony's per-request socket; vitals-http has none, so -1 */
    int first_socket;
} SceHttpPrivateRequestStats;
typedef void *(*SceHttpPrivateAlloc)(unsigned int size);
typedef void (*SceHttpPrivateFree)(void *pointer);

int sceHttpPrivateDebugNothing(void);
void sceHttpPrivateDumpRequests(void);
void sceHttpPrivateDumpConnections(void);
void sceHttpPrivateDumpMemoryPool(void);
void sceHttpPrivateDumpDebugInfo(void);
int sceHttpPrivateGetConnectionStats(int connId, SceHttpPrivateConnectionStats *stats);
int sceHttpPrivateGetRequestStats(int reqId, SceHttpPrivateRequestStats *stats);
int sceHttpPrivateSetOption19(int id, int value);
int sceHttpPrivateSetMode(int id, int mode);
int sceHttpPrivateSetSocketOption(int id, unsigned char value);
int sceHttpPrivateGetSocketOption(int id, int *value);
int sceHttpPrivateSetProxy(int id, int mode, int version, const char *host, unsigned short port);
int sceHttpPrivateSetOption21(int id, int value);
int sceHttpPrivateSetSslContextOption(int value);
int sceHttpPrivateLoadedCertInit(SceHttpPrivateAlloc allocate, SceHttpPrivateFree release);
int sceHttpPrivateLoadedCertClearClient(void);
int sceHttpPrivateLoadedCertClearCa(void);
int sceHttpPrivateLoadedCertTerm(void);
int sceHttpPrivateLoadedCertAddCa(const void *data, unsigned int size);
int sceHttpPrivateLoadedCertSetClientCert(const void *data, unsigned int size);
int sceHttpPrivateLoadedCertSetClientKey(const void *data, unsigned int size);
int sceHttpPrivateSslContextAddCertCheck(void *context, void *argument);
int sceHttpPrivateCertCheckNothing(void);

#ifdef __cplusplus
}
#endif

#endif
