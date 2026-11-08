#include "check.h"
#include "check_vita.h"
#include "check_run.h"
#include "network.h"
#include "probe.h"
#include "vitals/redirect_list.h"
#include "vitals/switches.h"
#include "vitals_http.h"
#include <taihen.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/libssl.h>
#include <psp2/net/http.h>
#include <psp2/rtc.h>
#include <psp2/sysmodule.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The connection test from Vital Signs: BrowserLeaks TLS 1.0-1.3, the BrowserLeaks TLS report,
 * the badssl.com battery and each host redirect, each over a fresh sceHttp connection on a worker
 * thread, which first starts the network and the HTTP libraries */
#define REPORT_DIR VITALS_REPORTS_DIRECTORY
/* VitaSDK has the stub, not the prototype: the HTTPS options of one template, connection or request */
int sceHttpsDisableOption2(int id, unsigned int sslFlags);

/* vitals-http's vitalsHttpGetUrl (vitals_http.h), found once in SceLibHttp's exports: NULL with
 * Sony's libhttp or a vitals-http that predates it, which then can't say where a request went */
typedef int (*GetUrl)(int reqId, char *url, unsigned int size, unsigned int *required);
static GetUrl get_url(void)
{
    static int looked;
    static GetUrl found;
    if (!looked)
    {
        uintptr_t address = 0;
        looked = 1;
        if (taiGetModuleExportFunc("SceLibHttp", VITALS_HTTP_LIBRARY_NID, VITALS_HTTP_GET_URL_NID, &address) >= 0 &&
            address != 0)
            found = (GetUrl)address;
    }
    return found;
}
/* The URL the last request went to, as vitals-http sent it (after the host redirects); empty when
 * that isn't known */
static char reached_url[CHECK_HOST_MAX + 64];

/* The retry's SSL callback where certificate checks can't be turned off: whatever was found is
 * accepted, so only the protocol decides */
static int accept_certificate(unsigned int bits, void *const certificates[], int count, void *argument)
{
    (void)bits, (void)certificates, (void)count, (void)argument;
    return 0;
}

static CheckService service = {.vitals_enabled = -1};
/* Which of vitals' libraries this process has: vitals-http (the Options' http.off keeps Sony's) and
 * vitals-ssl (tls.off keeps Sony's); -1 until looked for. service.vitals_enabled is either */
static int vitals_http = -1, vitals_tls = -1;
static SceUID guard = -1, worker = -1;
static int busy, active_request = -1, cancelled, abort_sent, https_loaded, ssl_ready, http_ready;
static uint64_t request_begin;
static char notice[120];
/* A request that times out is made again, up to this many times in all */
#define FETCH_ATTEMPTS 3
#define ERROR_TIMED_OUT 0x80431068
#define VERIFY_FLAGS (SCE_HTTPS_FLAG_SERVER_VERIFY | SCE_HTTPS_FLAG_CN_CHECK | \
                      SCE_HTTPS_FLAG_NOT_AFTER_CHECK | SCE_HTTPS_FLAG_NOT_BEFORE_CHECK | SCE_HTTPS_FLAG_KNOWN_CA_CHECK)
static uint64_t now_ms(void) { return sceKernelGetSystemTimeWide() / 1000; }
static void lock(void) { sceKernelLockMutex(guard, 1, NULL); }
static void unlock(void) { sceKernelUnlockMutex(guard, 1); }
#define REPORT_NAME "vitals-testresults"
static int stopped(void)
{
    lock();
    int c = cancelled;
    unlock();
    return c;
}
/* Keep request ownership locked across abort/delete, but never across blocking I/O */
static void abort_current(int user_cancel)
{
    lock();
    if (user_cancel)
        cancelled = 1;
    /* Recheck the current deadline under ownership lock; a new request may have started */
    if (active_request >= 0 && !abort_sent && (user_cancel || now_ms() - request_begin > 20000))
    {
        abort_sent = 1;
        (void)sceHttpAbortRequest(active_request);
    }
    unlock();
}
/* One request to url; status_only accepts any final HTTP status without reading the body, and
 * unverified_allowed permits the protocol checks' retries without certificate checks */
static int fetch_once(const char *url, int verify, int unverified_allowed, int status_only, char *body,
                      size_t *length, CheckResult *r)
{
    int tmpl = -1, conn = -1, req = -1, rc = 0;
    uint64_t begin = now_ms();
    memset(r, 0, sizeof(*r));
    r->state = CHECK_FAIL;
    r->vitals_active = vitals_http == 1;
    r->vitals_tls = vitals_tls == 1;
    *length = 0;
#define REQUIRE(call)  \
    do                 \
    {                  \
        rc = (call);   \
        if (rc < 0)    \
            goto done; \
    } while (0)
    if (stopped())
    {
        rc = (int)0x80431080;
        goto done;
    }
    if (!verify && !unverified_allowed)
    {
        rc = -1;
        snprintf(r->message, sizeof(r->message), "Unverified request refused for this endpoint");
        goto done;
    }
    /* sceHttps policy is global to this process
     * Only this worker sends HTTP
     * Reset it before every fresh attempt, and restore it on every retry exit */
    REQUIRE(sceHttpsEnableOption(VERIFY_FLAGS));
    /* Sony's libhttp (the Options' http.off) refuses to turn the server's check off, process-wide
     * or for a template (0x8043506B): then the template's SSL callback accepts what the check
     * found, as apps on Sony's libhttp accept a certificate */
    int per_template = 0;
    if (!verify)
    {
        if (sceHttpsDisableOption(VERIFY_FLAGS) >= 0)
            r->verification_disabled = 1;
        else
            per_template = 1;
    }
    REQUIRE(tmpl = sceHttpCreateTemplate("vitals/" VITALS_VERSION, SCE_HTTP_VERSION_1_1, 0));
    if (per_template)
    {
        if (sceHttpsDisableOption2(tmpl, VERIFY_FLAGS) < 0)
            REQUIRE(sceHttpsSetSslCallback(tmpl, accept_certificate, NULL));
        r->verification_disabled = 1;
    }
    REQUIRE(sceHttpSetResolveTimeOut(tmpl, 3000000));
    REQUIRE(sceHttpSetResolveRetry(tmpl, 1));
    REQUIRE(sceHttpSetConnectTimeOut(tmpl, 5000000));
    REQUIRE(sceHttpSetSendTimeOut(tmpl, 5000000));
    REQUIRE(sceHttpSetRecvTimeOut(tmpl, 5000000));
    REQUIRE(sceHttpSetAutoRedirect(tmpl, SCE_HTTP_DISABLE));
    REQUIRE(sceHttpSetCookieEnabled(tmpl, SCE_HTTP_DISABLE));
    REQUIRE(sceHttpSetResponseHeaderMaxSize(tmpl, 16384));
    REQUIRE(conn = sceHttpCreateConnectionWithURL(tmpl, url, SCE_HTTP_DISABLE));
    REQUIRE(req = sceHttpCreateRequestWithURL(conn, SCE_HTTP_METHOD_GET, url, 0));
    reached_url[0] = '\0';
    if (vitals_http == 1 && get_url() != NULL)
    {
        unsigned int required = 0;
        if (get_url()(req, reached_url, sizeof(reached_url), &required) < 0)
            reached_url[0] = '\0';
    }
    REQUIRE(sceHttpAddRequestHeader(req, "Accept-Encoding", "identity", SCE_HTTP_HEADER_OVERWRITE));
    REQUIRE(sceHttpAddRequestHeader(req, "Cache-Control", "no-cache", SCE_HTTP_HEADER_OVERWRITE));
    lock();
    active_request = req;
    request_begin = now_ms();
    abort_sent = 0;
    int stop = cancelled;
    unlock();
    if (stop)
    {
        rc = (int)0x80431080;
        goto done;
    }
    REQUIRE(sceHttpSendRequest(req, NULL, 0));
    REQUIRE(sceHttpGetStatusCode(req, &r->http_code));
    if (status_only)
    {
        /* Any final HTTP response, including 403/404/503, proves verified HTTPS reachability
         * Do not read its body */
        if (r->http_code >= 200 && r->http_code <= 599)
        {
            r->state = CHECK_PASS;
            snprintf(r->message, sizeof(r->message), "Connected (HTTP %d)", r->http_code);
        }
        else
        {
            rc = -1;
            snprintf(r->message, sizeof(r->message), "Unexpected HTTP status %d", r->http_code);
        }
        goto done;
    }
    while (*length < CHECK_BODY_MAX)
    {
        if (stopped())
        {
            rc = (int)0x80431080;
            goto done;
        }
        if (now_ms() - begin > 20000)
        {
            rc = (int)0x80431068;
            goto done;
        }
        int n = sceHttpReadData(req, body + *length, (unsigned)(CHECK_BODY_MAX - *length));
        if (n < 0)
        {
            rc = n;
            goto done;
        }
        if (!n)
            break;
        *length += (unsigned)n;
    }
    if (*length == CHECK_BODY_MAX)
    {
        snprintf(r->message, sizeof(r->message), "Response exceeds 96 KiB");
        rc = -1;
        goto done;
    }
    body[*length] = 0;
    if (r->http_code != 200)
    {
        snprintf(r->message, sizeof(r->message), "HTTP %d (no redirect followed)", r->http_code);
        rc = -1;
        goto done;
    }
    r->state = CHECK_PASS;
done:
    r->error = rc;
    r->elapsed_ms = (unsigned)(now_ms() - begin);
    if (req >= 0)
    {
        if (rc < 0)
            (void)sceHttpsGetSslError(req, &r->ssl_error, &r->ssl_detail);
        lock();
        active_request = -1;
        int del = sceHttpDeleteRequest(req);
        unlock();
        if (del < 0 && rc >= 0)
        {
            rc = del;
            r->error = del;
            r->state = CHECK_FAIL;
        }
    }
    if (conn >= 0)
    {
        int del = sceHttpDeleteConnection(conn);
        if (del < 0 && rc >= 0)
        {
            rc = del;
            r->error = del;
            r->state = CHECK_FAIL;
        }
    }
    if (tmpl >= 0)
    {
        int del = sceHttpDeleteTemplate(tmpl);
        if (del < 0 && rc >= 0)
        {
            rc = del;
            r->error = del;
            r->state = CHECK_FAIL;
        }
    }
    if (!verify)
    {
        r->restore_error = sceHttpsEnableOption(VERIFY_FLAGS);
        if (r->restore_error < 0)
        {
            rc = r->error = r->restore_error;
            r->state = CHECK_FAIL;
            snprintf(r->message, sizeof(r->message), "Could not restore certificate checks");
        }
    }
    if (rc < 0 && !r->message[0])
        snprintf(r->message, sizeof(r->message), "%s",
                 check_error_name(rc, r->ssl_error, r->ssl_detail));
    return rc;
#undef REQUIRE
}
/* fetch_once, made again while it times out: servers and the network are slow at times, which
 * says nothing about TLS; the result is the last attempt's, with every attempt's time */
static int fetch_url(const char *url, int verify, int unverified_allowed, int status_only, char *body,
                     size_t *length, CheckResult *r)
{
    unsigned elapsed = 0, attempts = 0;
    int rc;
    do
    {
        rc = fetch_once(url, verify, unverified_allowed, status_only, body, length, r);
        elapsed += r->elapsed_ms;
        ++attempts;
    } while ((uint32_t)rc == ERROR_TIMED_OUT && attempts < FETCH_ATTEMPTS && !r->restore_error &&
             !stopped());
    r->elapsed_ms = elapsed;
    r->attempts = attempts;
    return rc;
}
static int fetch(void *context, unsigned test, int verify, char *body, size_t *length,
                 CheckResult *r)
{
    char url[320];
    const char *endpoint = check_endpoint(test);
    (void)context;
    snprintf(url, sizeof(url), "%s%ccheck=%llu", endpoint, strchr(endpoint, '?') ? '&' : '?',
             (unsigned long long)sceKernelGetSystemTimeWide());
    return fetch_url(url, verify, test < 4, 0, body, length, r);
}

/* The host redirect list, read the way vitals' provider reads it (the app may open ux0:data
 * itself), so the test sees the same rules */
static FILE *redirect_file;
static int read_redirects(unsigned int offset, void *buffer, unsigned int size)
{
    if (fseek(redirect_file, (long)offset, SEEK_SET) != 0)
        return -1;
    size_t count = fread(buffer, 1, size, redirect_file);
    return ferror(redirect_file) ? -1 : (int)count;
}
typedef struct
{
    CheckRedirect *list;
    unsigned count, max;
} RedirectCollection;
static int keep_redirect(void *context, const VitalsHostRule *rule)
{
    RedirectCollection *collection = context;
    CheckRedirect *redirect = &collection->list[collection->count++];
    memset(redirect, 0, sizeof(*redirect));
    memcpy(redirect->from, rule->from, rule->from_length);
    memcpy(redirect->to, rule->to, rule->to_length);
    return collection->count == collection->max;
}
/* The rules in the list at path (the redirects, or the DNS rules, which are written the same way), at
 * most max; none when the file is missing or unreadable */
static unsigned load_redirects(const char *path, CheckRedirect *list, unsigned max)
{
    RedirectCollection collection = {list, 0, max};
    char *work = malloc(VITALS_REDIRECT_LIST_WORK_SIZE);
    redirect_file = fopen(path, "rb");
    if (work != NULL && redirect_file != NULL &&
        vitals_redirect_list_read(read_redirects, work, keep_redirect, &collection) < 0)
        collection.count = 0;
    if (redirect_file != NULL)
        fclose(redirect_file);
    redirect_file = NULL;
    free(work);
    return collection.count;
}
/* Which of vitals' libraries are this process's: 1 vitals-http, 2 vitals-ssl, both, or none */
static int detect_vitals(void)
{
    SceUID ids[128];
    SceSize count = sizeof(ids) / sizeof(ids[0]);
    int found = 0;
    int rc = sceKernelGetModuleList(0xff, ids, &count);
    if (rc >= 0)
    {
        for (unsigned i = 0; i < count && i < 128; ++i)
        {
            SceKernelModuleInfo info = {0};
            info.size = sizeof(info);
            if (sceKernelGetModuleInfo(ids[i], &info) != 0)
                continue;
            if (check_http_module_active(info.module_name, info.path, info.state))
                found |= 1;
            if (check_ssl_module_active(info.module_name, info.path, info.state))
                found |= 2;
        }
    }
    return found;
}
/* Writes s's log; 0 when written, negative when the file couldn't be */
static int save_report(const CheckService *s)
{
    char path[160];
    /* Named after the console's local time; without it, after the system timer */
    SceDateTime now;
    if (sceRtcGetCurrentClockLocalTime(&now) == 0)
        snprintf(path, sizeof(path), REPORT_DIR "/" REPORT_NAME "-%04u-%02u-%02u_%02u-%02u-%02u.txt", now.year,
                 now.month, now.day, now.hour, now.minute, now.second);
    else
        snprintf(path, sizeof(path), REPORT_DIR "/" REPORT_NAME "-%llu.txt",
                 (unsigned long long)sceKernelGetSystemTimeWide());
    (void)sceIoMkdir(REPORT_DIR, 0777);
    FILE *f = fopen(path, "w");
    if (!f)
    {
        lock();
        service.report_saved = -1;
        unlock();
        return -1;
    }
    fprintf(f,
            "vitals " VITALS_VERSION " connection test\nAPI=sceHttp\nservice=%s\nCertificate "
            "verification=enabled for primary requests\nConnection "
            "reuse=disabled\nRedirects=disabled\nProtocol-only diagnostic retries may disable "
            "certificate checks; both attempts are recorded.\n",
            "BrowserLeaks + badssl.com");
    fprintf(f, "vitals=%s (HTTP: %s, TLS: %s in this process)\n",
            s->vitals_enabled < 0 ? "checking" : s->vitals_enabled ? "enabled" : "not enabled",
            vitals_http < 0 ? "?" : vitals_http ? "vitals-http" : "Sony's libhttp",
            vitals_tls < 0 ? "?" : vitals_tls ? "vitals-ssl" : "Sony's libssl");
    for (unsigned i = 0; i < CHECK_TEST_COUNT; ++i)
    {
        const CheckResult *r = i == CHECK_REPORT ? &s->connection : &s->protocols[i];
        fprintf(f,
                "\nURL=%s\nstate=%d\nHTTP=%d\nerror=0x%08X\nssl_error=0x%08X\nssl_"
                "detail=0x%"
                "08X\nelapsed_ms=%u\nresult=%s\n",
                check_endpoint(i), r->state,
                r->http_code, (unsigned)r->error, (unsigned)r->ssl_error, r->ssl_detail,
                r->elapsed_ms, r->message);
        fprintf(f, "attempts=%u\nprotocol_confirmed=%d\nverification_restore_error=0x%08X\n",
                r->attempts, r->protocol_confirmed, (unsigned)r->restore_error);
        if (i < 4)
        {
            char detail[128];
            check_protocol_detail(i, r, detail, sizeof(detail));
            fprintf(f, "classification=%s\ndetail=%s\n",
                    check_protocol_display(i, r, s->vitals_enabled).label, detail);
            fprintf(f, "expected_vitals_policy_block=%d\n",
                    check_expected_legacy_block(i, r));
        }
        if (r->retry.attempted)
            fprintf(f, "retry_verification=%s\nretry_protocol_confirmed=%d\n"
                       "retry_HTTP=%d\nretry_error=0x%08X\nretry_ssl_error=0x%08X\n"
                       "retry_ssl_detail=0x%08X\nretry_elapsed_ms=%u\n"
                       "retry_restore_error=0x%08X\n",
                    r->retry.verification_disabled ? "disabled" : "unavailable",
                    r->retry.protocol_confirmed,
                    r->retry.http_code, (unsigned)r->retry.error, (unsigned)r->retry.ssl_error,
                    r->retry.ssl_detail, r->retry.elapsed_ms, (unsigned)r->retry.restore_error);
    }
    fprintf(f, "\nbadssl.com=%u\n", CHECK_BADSSL_COUNT);
    for (unsigned i = 0; i < CHECK_BADSSL_COUNT; ++i)
    {
        const CheckBadssl *test = check_badssl(i);
        const CheckResult *r = &s->badssl[i];
        fprintf(f, "%s (%s, expected %s)\nstate=%d\nHTTP=%d\nerror=0x%08X\nssl_error=0x%08X\n"
                   "ssl_detail=0x%08X\nelapsed_ms=%u\nattempts=%u\nresult=%s\n",
                test->host, test->label, test->refuse ? "refused" : "loaded", r->state, r->http_code,
                (unsigned)r->error, (unsigned)r->ssl_error, r->ssl_detail, r->elapsed_ms, r->attempts,
                r->message);
    }
    fprintf(f, "\nHost redirects (" VITALS_REDIRECTS_PATH ")=%u\n", s->redirect_count);
    for (unsigned i = 0; i < s->redirect_count; ++i)
    {
        const CheckRedirect *redirect = &s->redirects[i];
        fprintf(f, "%s -> %s\nstate=%d\nHTTP=%d\nerror=0x%08X\nssl_error=0x%08X\nssl_detail=0x%08X\n"
                   "elapsed_ms=%u\nattempts=%u\nresult=%s\n",
                redirect->from, redirect->to, redirect->result.state, redirect->result.http_code,
                (unsigned)redirect->result.error, (unsigned)redirect->result.ssl_error,
                redirect->result.ssl_detail, redirect->result.elapsed_ms, redirect->result.attempts,
                redirect->result.message);
    }
    const CheckHandshake *h = &s->handshake;
    fprintf(f,
            "\nSelected protocol=%04X %s\nSelected cipher=%04X %s\nKey exchange=%04X "
            "%s\nSignature=%04X %s\nALPN offered=%s\nJA3=%s\nJA4=%s\n",
            h->version.id, h->version.name, h->cipher.id, h->cipher.name, h->group.id,
            h->group.name, h->signature.id, h->signature.name, h->alpn, h->ja3, h->ja4);
    const CheckNamed *lists[] = {h->ciphers, h->groups, h->extensions};
    const unsigned counts[] = {h->cipher_count, h->group_count, h->extension_count};
    const char *labels[] = {"Offered ciphers (not individually negotiated)", "Offered groups",
                            "Offered extensions"};
    for (unsigned l = 0; l < 3; ++l)
    {
        fprintf(f, "\n%s\n", labels[l]);
        for (unsigned n = 0; n < counts[l]; ++n)
            fprintf(f, "%04X %s\n", lists[l][n].id, lists[l][n].name);
    }
    int failed = ferror(f);
    if (fclose(f))
        failed = 1;
    /* A partly written log isn't kept */
    if (failed)
        (void)sceIoRemove(path);
    lock();
    service.report_saved = failed ? -1 : 1;
    if (!failed)
        snprintf(service.report, sizeof(service.report), "%s", path);
    unlock();
    return failed ? -1 : 0;
}

int vitals_check_save_report(void)
{
    if (guard < 0)
        return -1;
    lock();
    const int saved = service.report_saved == 1;
    const int ready = !busy && service.started && service.complete && !service.interrupted;
    unlock();
    if (saved)
        return 1;
    if (!ready)
        return -1;
    /* The finished run's results, copied so the log is written without holding the lock */
    CheckService *snapshot = malloc(sizeof(*snapshot));
    if (snapshot == NULL)
        return -1;
    lock();
    *snapshot = service;
    unlock();
    int result = save_report(snapshot);
    free(snapshot);
    return result;
}
/* Loads HTTPS and starts sceSsl and sceHttp, once: 0, or the failing call's result, with what was
 * set up released again. Only the worker calls it */
static void close_libraries(void)
{
    if (http_ready)
        sceHttpTerm();
    if (ssl_ready)
        sceSslTerm();
    if (https_loaded)
        sceSysmoduleUnloadModule(SCE_SYSMODULE_HTTPS);
    http_ready = ssl_ready = https_loaded = 0;
}
static int open_libraries(void)
{
    int rc = 0;
    /* Loading HTTPS brings in libhttp, which vitals (when installed) replaces for this app */
    if (!https_loaded)
    {
        rc = sceSysmoduleLoadModule(SCE_SYSMODULE_HTTPS);
        if (rc < 0)
            goto failed;
        https_loaded = 1;
    }
    if (!ssl_ready)
    {
        rc = sceSslInit(1024 * 1024);
        if (rc < 0)
            goto failed;
        ssl_ready = 1;
    }
    if (!http_ready)
    {
        rc = sceHttpInit(1024 * 1024);
        if (rc < 0)
            goto failed;
        http_ready = 1;
    }
    rc = sceHttpsEnableOption(VERIFY_FLAGS);
    if (rc < 0)
        goto failed;
    return 0;
failed:
    close_libraries();
    return rc;
}

/* ---- the Vita's side of the shared run (shared/app/check_run.c) ---- */

static int backend_open(char *text, size_t size)
{
    /* The network and the HTTP libraries, the first time */
    int rc = network_start(stopped);
    if (rc < 0)
    {
        snprintf(text, size, "No network connection (0x%08X)", (unsigned)rc);
        return rc;
    }
    rc = open_libraries();
    if (rc < 0)
        snprintf(text, size, "Sony network initialization failed: 0x%08X", (unsigned)rc);
    return rc;
}

static int flag_there(const char *path)
{
    SceIoStat status;
    return sceIoGetstat(path, &status) >= 0;
}

static void backend_parts(CheckParts *parts)
{
    int enabled = detect_vitals();
    lock();
    vitals_http = (enabled & 1) != 0;
    vitals_tls = (enabled & 2) != 0;
    unlock();
    parts->http = vitals_http;
    parts->tls = vitals_tls;
    parts->redirects_off = flag_there(VITALS_REDIRECTS_OFF);
    parts->dns_off = flag_there(VITALS_DNS_OFF);
    parts->vitals = enabled != 0;
    /* A vitals-http without vitalsHttpGetUrl can't say which host answered */
    parts->http_outdated = vitals_http && get_url() == NULL;
}

static void backend_protocol(unsigned test, char *body, CheckResult *r)
{
    size_t n = 0;
    check_run_protocol(test, fetch, NULL, body, &n, r);
}

static int backend_fetch(const char *url, int status_only, char *body, size_t *length, char *reached, size_t reached_size,
                         CheckResult *r)
{
    int rc = fetch_url(url, 1, 0, status_only, body, length, r);
    snprintf(reached, reached_size, "%s", reached_url);
    return rc;
}

static int backend_policy_failed(const CheckResult *r)
{
    return r->restore_error < 0;
}

static const CheckBackend backend = {
    .open = backend_open,
    .parts = backend_parts,
    .load = load_redirects,
    .protocol = backend_protocol,
    .fetch = backend_fetch,
    .judge_badssl = check_badssl_judge,
    .judge_redirect = check_redirect_judge,
    /* The Vita's test doesn't look the DNS rules up yet */
    .dns = NULL,
    .stopped = stopped,
    .policy_failed = backend_policy_failed,
    .log = NULL,
    .lock = lock,
    .unlock = unlock,
    .now_ms = now_ms,
};

static int run_checks(SceSize argc, void *argv)
{
    (void)argc;
    (void)argv;
    char text[sizeof(notice)] = "";
    check_run(&backend, &service, text, sizeof(text));
    /* The log is saved only on request (vitals_check_save_report), and only for a run that
     * wasn't cancelled */
    lock();
    if (text[0] != '\0')
        snprintf(notice, sizeof(notice), "%s", text);
    busy = 0;
    unlock();
    return 0;
}
static void join_worker(void)
{
    if (worker >= 0)
    {
        sceKernelWaitThreadEnd(worker, NULL, NULL);
        sceKernelDeleteThread(worker);
        worker = -1;
    }
}

void vitals_check_stop(void)
{
    if (guard >= 0)
        abort_current(1);
    join_worker();
    busy = 0;
}

void vitals_check_close(void)
{
    vitals_check_stop();
    close_libraries();
}

void vitals_check_start(void)
{
    if (guard < 0)
    {
        guard = sceKernelCreateMutex("vitals test state", 0, 0, NULL);
        if (guard < 0)
            return;
    }
    lock();
    int running = busy;
    unlock();
    if (running)
        return;
    join_worker();
    lock();
    memset(&service, 0, sizeof(service));
    service.vitals_enabled = service.libhttp_active = -1;
    service.started = 1;
    busy = 1;
    cancelled = 0;
    notice[0] = 0;
    unlock();
    worker =
        sceKernelCreateThread("vitals connection test", run_checks, 0x10000100, 256 * 1024, 0, 0, NULL);
    int rc = worker < 0 ? worker : sceKernelStartThread(worker, 0, NULL);
    if (rc < 0)
    {
        if (worker >= 0)
            sceKernelDeleteThread(worker);
        worker = -1;
        lock();
        busy = 0;
        snprintf(notice, sizeof(notice), "Could not start network worker: %08X", (unsigned)rc);
        unlock();
    }
}

void vitals_check_cancel(void) { abort_current(1); }

int vitals_check_poll(CheckService *view, char *message, size_t size)
{
    if (guard < 0)
    {
        memset(view, 0, sizeof(*view));
        view->vitals_enabled = view->libhttp_active = -1;
        snprintf(message, size, "%s", "The test couldn't start");
        return 0;
    }
    lock();
    int is_busy = busy;
    uint64_t started = request_begin;
    int request = active_request;
    unlock();
    /* A request that hangs past its deadline is aborted so the test always finishes */
    if (is_busy && request >= 0 && now_ms() - started > 20000)
        abort_current(0);
    lock();
    *view = service;
    snprintf(message, size, "%s", notice);
    unlock();
    return is_busy;
}
