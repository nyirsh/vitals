#include "check.h"
#include "check_vita.h"
#include "check_report.h"
#include "vitals/log.h"
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
#include <psp2/net/net.h>
#include <psp2/net/http.h>
#include <psp2/rtc.h>
#include <psp2/sysmodule.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The Vita's part of the connection test (check.h): its requests, each over a fresh sceHttp
 * connection once the network and the HTTP libraries are started, its judges, its lookups through
 * sceNetResolver, which of vitals' libraries this process has, and its report's own lines. The run
 * itself, its thread and its results are shared with the PS3 (check_run.c, check_service.c) */
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

/* Which of vitals' libraries this process has: vitals-http (the Options' http.off keeps Sony's) and
 * vitals-ssl (tls.off keeps Sony's); -1 until looked for. service.vitals_enabled is either */
static int vitals_http = -1, vitals_tls = -1;
/* The run's request and lookup, which a cancel or the watchdog ends; under check_lock */
static int active_request = -1, active_resolver = -1, cancelled, abort_sent, https_loaded, ssl_ready, http_ready;
static uint64_t request_begin;
/* A request that times out is made again, up to this many times in all */
#define FETCH_ATTEMPTS 3
#define ERROR_TIMED_OUT 0x80431068
#define VERIFY_FLAGS (SCE_HTTPS_FLAG_SERVER_VERIFY | SCE_HTTPS_FLAG_CN_CHECK | \
                      SCE_HTTPS_FLAG_NOT_AFTER_CHECK | SCE_HTTPS_FLAG_NOT_BEFORE_CHECK | SCE_HTTPS_FLAG_KNOWN_CA_CHECK)
static uint64_t now_ms(void) { return sceKernelGetSystemTimeWide() / 1000; }
static void lock(void) { check_lock(); }
static void unlock(void) { check_unlock(); }
#define REPORT_NAME "connection-test"
/* Room for the whole report, the longest lists included */
#define REPORT_MAX (96 * 1024)
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
    /* A DNS rule's lookup ends at the resolver's own timeout, or at once when cancelled */
    if (user_cancel && active_resolver >= 0)
        (void)sceNetResolverAbort(active_resolver, 0);
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
/* The rules in the list at path (the redirects, or the DNS rules, which are written the same way), as
 * vitals reads them (check_run_read_rules); none when the file is missing or unreadable */
static unsigned load_redirects(const char *path, CheckRedirect *list, unsigned max)
{
    redirect_file = fopen(path, "rb");
    if (redirect_file == NULL)
        return 0;
    unsigned count = check_run_read_rules(read_redirects, list, max);
    fclose(redirect_file);
    redirect_file = NULL;
    VITALS_VERBOSE("%s: %u rules", path, count);
    return count;
}
/* A name looked up through sceNetResolver, as a game would: its query goes out through sendto,
 * where the kernel plugin applies the DNS rules. The resolver gives one address, and its errors
 * in the PS3's resolver's words (check_dns_judge) */
static void look_up(const char *name, CheckLookup *out)
{
    memset(out, 0, sizeof(*out));
    int resolver = sceNetResolverCreate("vitals-check", NULL, 0);
    if (resolver < 0)
    {
        out->error = CHECK_LOOKUP_FAILED;
        return;
    }
    lock();
    active_resolver = resolver;
    int stop = cancelled;
    unlock();
    SceNetInAddr address = {0};
    int rc = stop ? -1 : sceNetResolverStartNtoa(resolver, name, &address, 0, 0, 0);
    lock();
    active_resolver = -1;
    unlock();
    (void)sceNetResolverDestroy(resolver);
    if (rc >= 0)
    {
        /* In network order, as it went over the wire */
        memcpy(out->addresses[0], &address.s_addr, 4);
        out->count = 1;
        out->found = 1;
        return;
    }
    switch ((unsigned)rc & 0xffu)
    {
    case SCE_NET_RESOLVER_ENOHOST:
        out->error = CHECK_LOOKUP_NO_HOST;
        break;
    case SCE_NET_RESOLVER_ENORECORD:
        out->error = CHECK_LOOKUP_NO_ADDRESS;
        break;
    case SCE_NET_RESOLVER_ETIMEDOUT:
    case SCE_NET_RESOLVER_ESERVERFAILURE:
    case SCE_NET_RESOLVER_ENODNS:
        out->error = CHECK_LOOKUP_TRY_AGAIN;
        break;
    default:
        out->error = CHECK_LOOKUP_FAILED;
    }
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
/* The report's Vita parts (check_report.h): how requests are made, which of vitals' libraries this
 * process has, and sceHttp's and sceSsl's fields of a request */
static void report_about(CheckReport *report, const CheckService *s)
{
    (void)s;
    check_report_add(report, "Certificate verification=enabled for primary requests\n"
                             "Protocol-only diagnostic retries may disable certificate checks; both attempts are "
                             "recorded.\nTimeouts are retried, up to %u attempts in all.\n",
                     FETCH_ATTEMPTS);
    check_report_add(report, "parts=HTTP: %s, TLS: %s in this process\n",
                     vitals_http < 0 ? "?" : vitals_http ? "vitals-http" : "Sony's libhttp",
                     vitals_tls < 0 ? "?" : vitals_tls ? "vitals-ssl" : "Sony's libssl");
}
static void report_result(CheckReport *report, const CheckResult *r)
{
    check_report_add(report, "ssl_error=0x%08X\nssl_detail=0x%08X\n", (unsigned)r->ssl_error, r->ssl_detail);
}
static void report_protocol(CheckReport *report, unsigned test, const CheckResult *r)
{
    check_report_add(report, "protocol_confirmed=%d\nverification_restore_error=0x%08X\n"
                             "expected_vitals_policy_block=%d\n",
                     r->protocol_confirmed, (unsigned)r->restore_error, check_expected_legacy_block(test, r));
    if (r->retry.attempted)
        check_report_add(report, "retry_verification=%s\nretry_protocol_confirmed=%d\n"
                                 "retry_HTTP=%d\nretry_error=0x%08X\nretry_ssl_error=0x%08X\n"
                                 "retry_ssl_detail=0x%08X\nretry_elapsed_ms=%u\n"
                                 "retry_restore_error=0x%08X\n",
                         r->retry.verification_disabled ? "disabled" : "unavailable", r->retry.protocol_confirmed,
                         r->retry.http_code, (unsigned)r->retry.error, (unsigned)r->retry.ssl_error,
                         r->retry.ssl_detail, r->retry.elapsed_ms, (unsigned)r->retry.restore_error);
}
static const CheckReportFormat report_format = {"PS Vita", "sceHttp", report_about, report_result, report_protocol};

/* Writes s's report; 0 when written, negative when the file couldn't be */
static int save_report(const CheckService *s, char *path, size_t path_size)
{
    /* Named after the console's local time; without it, after the system timer */
    SceDateTime now;
    CheckReportTime local = {0};
    int have_time = sceRtcGetCurrentClockLocalTime(&now) == 0;
    if (have_time)
        local = (CheckReportTime){now.year, now.month, now.day, now.hour, now.minute, now.second};
    check_report_path(path, path_size, REPORT_DIR, REPORT_NAME, have_time ? &local : NULL,
                      (uint64_t)sceKernelGetSystemTimeWide());
    CheckReport report = {malloc(REPORT_MAX), 0, REPORT_MAX};
    int failed = report.data == NULL;
    if (!failed)
    {
        check_report_write(&report_format, s, &report);
        (void)sceIoMkdir(VITALS_DIRECTORY, 0777);
        (void)sceIoMkdir(REPORT_DIR, 0777);
        FILE *f = fopen(path, "w");
        failed = f == NULL;
        if (f != NULL)
        {
            failed = fwrite(report.data, 1, report.used, f) != report.used || ferror(f);
            if (fclose(f))
                failed = 1;
            /* A partly written report isn't kept */
            if (failed)
                (void)sceIoRemove(path);
        }
    }
    free(report.data);
    VITALS_LOG("report: %s, %d", path, failed);
    return failed ? -1 : 0;
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
    VITALS_LOG("libssl: %s, libhttp: %s%s%s", parts->tls ? "vitals'" : "Sony's", parts->http ? "vitals'" : "Sony's",
               parts->redirects_off ? ", redirects off" : "", parts->dns_off ? ", DNS rules off" : "");
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

/* A finished check, in the app's log */
static void log_result(const char *what, const CheckResult *r)
{
    VITALS_LOG("test %s: state %d, HTTP %d, error 0x%08X, ssl 0x%08X, detail 0x%04X, %u ms, %s", what, r->state,
               r->http_code, (unsigned)r->error, (unsigned)r->ssl_error, r->ssl_detail, r->elapsed_ms, r->message);
}

static const CheckBackend backend = {
    .open = backend_open,
    .parts = backend_parts,
    .load = load_redirects,
    .protocol = backend_protocol,
    .fetch = backend_fetch,
    .lookup = look_up,
    .stopped = stopped,
    .policy_failed = backend_policy_failed,
    .log = log_result,
    .lock = lock,
    .unlock = unlock,
    .now_ms = now_ms,
};

/* Before each run: not cancelled */
static void reset(void)
{
    lock();
    cancelled = 0;
    unlock();
}

static void cancel(void) { abort_current(1); }

/* A request that hangs past its deadline is aborted so the test always finishes */
static void watch(void)
{
    lock();
    uint64_t started = request_begin;
    int request = active_request;
    unlock();
    if (request >= 0 && now_ms() - started > 20000)
        abort_current(0);
}

const CheckConsole check_console = {&backend, reset, cancel, watch, save_report};

/* Leaving the app: the run ended, then the HTTP libraries */
void vitals_check_close(void)
{
    vitals_check_stop();
    close_libraries();
}
