#include "vh.h"

#include "diagnostics.h"

#include <string.h>

/* The cookie jar (RFC 6265): the cookies of every server, oldest first, in the pool */
typedef struct VhCookie
{
    struct VhCookie *next;
    char *name, *value, *domain, *path;
    int host_only, secure;
    /* Seconds since 1970 it expires at; 0 when it lasts until sceHttpTerm */
    long long expires;
} VhCookie;

static VhCookie *g_cookies;
static unsigned int g_count, g_total_size;
static unsigned int g_max_num = 300, g_max_per_domain = 50, g_max_size = 4096, g_total_max_size = 0x100000;

static char lower(char c)
{
    return c >= 'A' && c <= 'Z' ? (char)(c - 'A' + 'a') : c;
}

static unsigned int cookie_size(const VhCookie *cookie)
{
    return (unsigned int)(strlen(cookie->name) + strlen(cookie->value));
}

static void free_cookie(VhCookie *cookie)
{
    vh_free(cookie->name);
    vh_free(cookie->value);
    vh_free(cookie->domain);
    vh_free(cookie->path);
    vh_free(cookie);
}

/* Takes the cookie after *link out of the jar and frees it */
static void remove_at(VhCookie **link)
{
    VhCookie *cookie = *link;
    *link = cookie->next;
    --g_count;
    g_total_size -= cookie_size(cookie);
    free_cookie(cookie);
}

void vh_cookie_clear(void)
{
    while (g_cookies != NULL)
        remove_at(&g_cookies);
}

static int is_ip_address(const char *host)
{
    if (host[0] == '[')
        return 1;
    for (; *host != '\0'; ++host)
        if (!((*host >= '0' && *host <= '9') || *host == '.'))
            return 0;
    return 1;
}

/* RFC 6265, 5.1.3 */
static int domain_match(const char *host, const char *domain)
{
    size_t host_length = strlen(host), domain_length = strlen(domain);
    if (host_length == domain_length)
        return vh_equal_nocase(host, domain, host_length);
    return host_length > domain_length && host[host_length - domain_length - 1] == '.' &&
           vh_equal_nocase(host + host_length - domain_length, domain, domain_length) && !is_ip_address(host);
}

/* The path part of a request target, without its query */
static size_t path_length(const char *path)
{
    size_t length = 0;
    while (path[length] != '\0' && path[length] != '?' && path[length] != '#')
        ++length;
    return length;
}

/* RFC 6265, 5.1.4 */
static int path_match(const char *request_path, const char *cookie_path)
{
    size_t length = path_length(request_path), cookie_length = strlen(cookie_path);
    if (length == 0) {
        request_path = "/";
        length = 1;
    }
    if (cookie_length > length || memcmp(request_path, cookie_path, cookie_length) != 0)
        return 0;
    return cookie_length == length || cookie_path[cookie_length - 1] == '/' || request_path[cookie_length] == '/';
}

static int expired(const VhCookie *cookie, long long now)
{
    return cookie->expires != 0 && cookie->expires <= now;
}

char *vh_cookie_header(const char *host, const char *path, int https)
{
    long long now = vh_platform_time();
    size_t size = 0;

    for (VhCookie **link = &g_cookies; *link != NULL;) {
        if (expired(*link, now)) {
            remove_at(link);
            continue;
        }
        link = &(*link)->next;
    }
    /* Measured first, then written */
    for (int pass = 0; pass < 2; ++pass) {
        char *header = pass == 0 ? NULL : vh_alloc(size + 1);
        size_t at = 0;
        if (pass == 1 && header == NULL)
            return NULL;
        for (const VhCookie *cookie = g_cookies; cookie != NULL; cookie = cookie->next) {
            int host_matches = cookie->host_only ? strlen(host) == strlen(cookie->domain) &&
                                                       vh_equal_nocase(host, cookie->domain, strlen(host))
                                                 : domain_match(host, cookie->domain);
            if (!host_matches || !path_match(path, cookie->path) || (cookie->secure && !https))
                continue;
            size_t name_length = strlen(cookie->name), value_length = strlen(cookie->value);
            size_t start = at != 0 ? at + 2 : 0;
            if (header != NULL) {
                if (at != 0)
                    memcpy(header + at, "; ", 2);
                memcpy(header + start, cookie->name, name_length);
                header[start + name_length] = '=';
                memcpy(header + start + name_length + 1, cookie->value, value_length);
            }
            at = start + name_length + 1 + value_length;
        }
        if (at == 0)
            return NULL;
        if (header != NULL) {
            header[at] = '\0';
            return header;
        }
        size = at;
    }
    return NULL;
}

/* ---- Set-Cookie ---- */

static const char *trim(const char *start, const char *end, const char **trimmed_end)
{
    while (start < end && (*start == ' ' || *start == '\t'))
        ++start;
    while (end > start && (end[-1] == ' ' || end[-1] == '\t'))
        --end;
    *trimmed_end = end;
    return start;
}

static long long days_from_civil(long long year, unsigned int month, unsigned int day)
{
    year -= month <= 2;
    long long era = (year >= 0 ? year : year - 399) / 400;
    unsigned int year_of_era = (unsigned int)(year - era * 400);
    unsigned int day_of_year = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1;
    unsigned int day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    return era * 146097 + (long long)day_of_era - 719468;
}

/* An HTTP date, in any of its forms (RFC 6265, 5.1.1): seconds since 1970, or -1 */
static long long parse_date(const char *text, size_t length)
{
    static const char months[] = "janfebmaraprmayjunjulaugsepoctnovdec";
    int day = -1, month = -1, year = -1, hour = -1, minute = 0, second = 0;
    size_t at = 0;

    while (at < length) {
        while (at < length && (text[at] == ' ' || text[at] == ',' || text[at] == '-' || text[at] == '\t'))
            ++at;
        size_t start = at;
        while (at < length && text[at] != ' ' && text[at] != ',' && text[at] != '-' && text[at] != '\t')
            ++at;
        size_t token = at - start;
        if (token == 0)
            break;
        const char *t = text + start;
        if (memchr(t, ':', token) != NULL && hour < 0) {
            int parts[3] = {0, 0, 0}, part = 0;
            for (size_t i = 0; i < token && part < 3; ++i) {
                if (t[i] == ':')
                    ++part;
                else if (t[i] >= '0' && t[i] <= '9')
                    parts[part] = parts[part] * 10 + (t[i] - '0');
                else
                    return -1;
            }
            hour = parts[0], minute = parts[1], second = parts[2];
        } else if (t[0] >= '0' && t[0] <= '9') {
            int number = 0;
            for (size_t i = 0; i < token && t[i] >= '0' && t[i] <= '9'; ++i)
                number = number * 10 + (t[i] - '0');
            if (day < 0 && token <= 2)
                day = number;
            else if (year < 0)
                year = token <= 2 ? (number >= 70 ? 1900 + number : 2000 + number) : number;
        } else if (month < 0 && token >= 3) {
            for (int m = 0; m < 12; ++m)
                if (lower(t[0]) == months[m * 3] && lower(t[1]) == months[m * 3 + 1] && lower(t[2]) == months[m * 3 + 2])
                    month = m + 1;
        }
    }
    if (day < 1 || day > 31 || month < 1 || year < 1601 || hour < 0 || hour > 23 || minute > 59 || second > 59)
        return -1;
    return days_from_civil(year, (unsigned int)month, (unsigned int)day) * 86400 + hour * 3600 + minute * 60 + second;
}

/* The default path of a cookie (RFC 6265, 5.1.4): the request path up to its last '/' */
static char *default_path(const char *request_path)
{
    size_t length = path_length(request_path), last = 0;
    for (size_t i = 0; i < length; ++i)
        if (request_path[i] == '/')
            last = i;
    if (length == 0 || request_path[0] != '/' || last == 0)
        return vh_strdup("/", 1);
    return vh_strdup(request_path, last);
}

/* Puts a cookie in the jar, in place of the one with its name, domain and path, and drops the
 * oldest ones over the limits */
static void insert(VhCookie *cookie)
{
    VhCookie **link = &g_cookies, **tail;
    while (*link != NULL) {
        VhCookie *other = *link;
        if (strcmp(other->name, cookie->name) == 0 && strcmp(other->path, cookie->path) == 0 &&
            strlen(other->domain) == strlen(cookie->domain) &&
            vh_equal_nocase(other->domain, cookie->domain, strlen(cookie->domain)))
            remove_at(link);
        else
            link = &other->next;
    }
    if (expired(cookie, vh_platform_time())) {
        free_cookie(cookie);
        return;
    }
    for (tail = &g_cookies; *tail != NULL; tail = &(*tail)->next) {
    }
    *tail = cookie;
    cookie->next = NULL;
    ++g_count;
    g_total_size += cookie_size(cookie);

    unsigned int same_domain = 0;
    for (const VhCookie *other = g_cookies; other != NULL; other = other->next)
        if (strcmp(other->domain, cookie->domain) == 0)
            ++same_domain;
    for (link = &g_cookies; same_domain > g_max_per_domain && *link != cookie;) {
        if (strcmp((*link)->domain, cookie->domain) == 0) {
            remove_at(link);
            --same_domain;
        } else
            link = &(*link)->next;
    }
    while ((g_count > g_max_num || g_total_size > g_total_max_size) && g_cookies != cookie)
        remove_at(&g_cookies);
}

static VhCookie *new_cookie(const char *name, size_t name_length, const char *value, size_t value_length)
{
    VhCookie *cookie = vh_alloc(sizeof(*cookie));
    if (cookie == NULL)
        return NULL;
    memset(cookie, 0, sizeof(*cookie));
    cookie->name = vh_strdup(name, name_length);
    cookie->value = vh_strdup(value, value_length);
    if (cookie->name == NULL || cookie->value == NULL) {
        free_cookie(cookie);
        return NULL;
    }
    return cookie;
}

void vh_cookie_store(const char *host, const char *path, const char *text, size_t length)
{
    const char *end = text + length, *pair_end = text, *name_end, *value_end;
    while (pair_end < end && *pair_end != ';')
        ++pair_end;
    const char *equals = memchr(text, '=', (size_t)(pair_end - text));
    if (equals == NULL)
        return;
    const char *name = trim(text, equals, &name_end);
    const char *value = trim(equals + 1, pair_end, &value_end);
    if (name == name_end || (size_t)(name_end - name) + (size_t)(value_end - value) > g_max_size)
        return;
    /* A quoted value keeps its quotes, as it is sent back */
    VhCookie *cookie = new_cookie(name, (size_t)(name_end - name), value, (size_t)(value_end - value));
    if (cookie == NULL)
        return;

    long long max_age = 0, expires = 0;
    int has_max_age = 0;
    const char *attribute = pair_end;
    while (attribute < end) {
        const char *start = attribute + 1, *stop = start, *key_end, *argument_end;
        while (stop < end && *stop != ';')
            ++stop;
        const char *eq = memchr(start, '=', (size_t)(stop - start));
        const char *key = trim(start, eq != NULL ? eq : stop, &key_end);
        const char *argument = eq != NULL ? trim(eq + 1, stop, &argument_end) : stop;
        if (eq == NULL)
            argument_end = stop;
        size_t key_length = (size_t)(key_end - key), argument_length = (size_t)(argument_end - argument);
        if (key_length == 6 && vh_equal_nocase(key, "Domain", 6) && argument_length != 0) {
            if (*argument == '.')
                ++argument, --argument_length;
            vh_free(cookie->domain);
            cookie->domain = vh_strdup(argument, argument_length);
            for (size_t i = 0; cookie->domain != NULL && i < argument_length; ++i)
                cookie->domain[i] = lower(cookie->domain[i]);
        } else if (key_length == 4 && vh_equal_nocase(key, "Path", 4) && argument_length != 0 && *argument == '/') {
            vh_free(cookie->path);
            cookie->path = vh_strdup(argument, argument_length);
        } else if (key_length == 7 && vh_equal_nocase(key, "Max-Age", 7) && argument_length != 0) {
            int negative = *argument == '-';
            long long seconds = 0;
            for (size_t i = negative; i < argument_length && argument[i] >= '0' && argument[i] <= '9'; ++i)
                if (seconds < 0x7fffffffll)
                    seconds = seconds * 10 + (argument[i] - '0');
            max_age = negative ? -seconds : seconds;
            has_max_age = 1;
        } else if (key_length == 7 && vh_equal_nocase(key, "Expires", 7)) {
            long long date = parse_date(argument, argument_length);
            if (date >= 0)
                expires = date > 0 ? date : 1;
        } else if (key_length == 6 && vh_equal_nocase(key, "Secure", 6))
            cookie->secure = 1;
        attribute = stop;
    }

    /* Max-Age wins over Expires; a past date drops the cookie */
    if (has_max_age)
        cookie->expires = max_age <= 0 ? 1 : vh_platform_time() + max_age;
    else
        cookie->expires = expires;
    if (cookie->domain != NULL && cookie->domain[0] != '\0') {
        /* Not for another server, nor for a whole top-level domain */
        if (!domain_match(host, cookie->domain) ||
            (strchr(cookie->domain, '.') == NULL && strlen(host) != strlen(cookie->domain))) {
            free_cookie(cookie);
            return;
        }
    } else {
        vh_free(cookie->domain);
        cookie->domain = vh_strdup(host, strlen(host));
        cookie->host_only = 1;
    }
    if (cookie->path == NULL)
        cookie->path = default_path(path);
    if (cookie->domain == NULL || cookie->path == NULL) {
        free_cookie(cookie);
        return;
    }
    insert(cookie);
}

/* ---- the API ---- */

/* The host and path of a URL, NUL-terminated, into host and path */
static int split_url(const char *url, char *host, char **path)
{
    VhUrl parts;
    int result = vh_parse_url(url, &parts);
    if (result < 0)
        return result;
    memcpy(host, parts.host, parts.host_length);
    host[parts.host_length] = '\0';
    *path = vh_strdup(parts.path_length != 0 ? parts.path : "/", parts.path_length != 0 ? parts.path_length : 1);
    return *path == NULL ? (int)SCE_HTTP_ERROR_OUT_OF_MEMORY : parts.https;
}

int sceHttpGetCookie(const char *url, char *cookie, unsigned int *cookieLength, unsigned int prepare, int secure)
{
    VH_TRACE();
    char host[VH_HOST_MAX];
    char *path;
    if (url == NULL || cookieLength == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    vh_lock();
    int result = vh_initialized();
    if (result == 0 && (result = split_url(url, host, &path)) >= 0) {
        char *header = vh_cookie_header(host, path, secure != 0);
        size_t length = header != NULL ? strlen(header) : 0;
        *cookieLength = (unsigned int)length;
        result = 0;
        if (cookie != NULL) {
            if (prepare < length + 1)
                result = (int)SCE_HTTP_ERROR_OUT_OF_SIZE;
            else {
                if (length != 0)
                    memcpy(cookie, header, length);
                cookie[length] = '\0';
            }
        }
        vh_free(header);
        vh_free(path);
    }
    vh_unlock();
    return result;
}

int sceHttpAddCookie(const char *url, const char *cookie, unsigned int cookieLength)
{
    VH_TRACE();
    char host[VH_HOST_MAX];
    char *path;
    if (url == NULL || cookie == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    vh_lock();
    int result = vh_initialized();
    if (result == 0 && (result = split_url(url, host, &path)) >= 0) {
        vh_cookie_store(host, path, cookie, cookieLength != 0 ? cookieLength : strlen(cookie));
        vh_free(path);
        result = 0;
    }
    vh_unlock();
    return result;
}

int sceHttpCookieFlush(void)
{
    VH_TRACE();
    vh_lock();
    int result = vh_initialized();
    if (result == 0)
        vh_cookie_clear();
    vh_unlock();
    return result;
}

/* One line per cookie: domain, host-only, path, secure, expiry, name and value, between tabs */
static size_t export_cookie(const VhCookie *cookie, char *out)
{
    char number[24];
    size_t length = 0, at = 0;
    unsigned long long expires = (unsigned long long)cookie->expires;
    do
        number[length++] = (char)('0' + expires % 10u);
    while ((expires /= 10u) != 0);
    const char *fields[] = {cookie->domain, cookie->host_only ? "1" : "0", cookie->path,
                            cookie->secure ? "1" : "0", NULL, cookie->name, cookie->value};
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
        if (fields[i] == NULL) {
            for (size_t j = 0; j < length; ++j)
                if (out != NULL)
                    out[at + j] = number[length - 1 - j];
            at += length;
        } else {
            size_t field_length = strlen(fields[i]);
            if (out != NULL)
                memcpy(out + at, fields[i], field_length);
            at += field_length;
        }
        if (out != NULL)
            out[at] = i + 1 < sizeof(fields) / sizeof(fields[0]) ? '\t' : '\n';
        ++at;
    }
    return at;
}

int sceHttpCookieExport(void *buffer, unsigned int bufferSize, unsigned int *exportSize)
{
    VH_TRACE();
    if (exportSize == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    vh_lock();
    int result = vh_initialized();
    if (result == 0) {
        size_t size = 0;
        for (const VhCookie *cookie = g_cookies; cookie != NULL; cookie = cookie->next)
            size += export_cookie(cookie, NULL);
        *exportSize = (unsigned int)size;
        if (buffer != NULL && bufferSize < size)
            result = (int)SCE_HTTP_ERROR_OUT_OF_SIZE;
        else if (buffer != NULL) {
            size_t at = 0;
            for (const VhCookie *cookie = g_cookies; cookie != NULL; cookie = cookie->next)
                at += export_cookie(cookie, (char *)buffer + at);
        }
    }
    vh_unlock();
    return result;
}

int sceHttpCookieImport(const void *buffer, unsigned int bufferSize)
{
    VH_TRACE();
    if (buffer == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    vh_lock();
    int result = vh_initialized();
    const char *text = buffer, *end = text + bufferSize;
    while (result == 0 && text < end) {
        const char *line_end = memchr(text, '\n', (size_t)(end - text));
        if (line_end == NULL)
            line_end = end;
        const char *fields[7];
        size_t lengths[7], count = 0;
        for (const char *at = text; count < 7 && at <= line_end;) {
            const char *stop = at;
            while (stop < line_end && *stop != '\t')
                ++stop;
            fields[count] = at;
            lengths[count++] = (size_t)(stop - at);
            at = stop + 1;
        }
        if (count == 7 && lengths[0] != 0 && lengths[2] != 0 && lengths[5] != 0) {
            VhCookie *cookie = new_cookie(fields[5], lengths[5], fields[6], lengths[6]);
            if (cookie == NULL)
                result = (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
            else {
                cookie->domain = vh_strdup(fields[0], lengths[0]);
                cookie->path = vh_strdup(fields[2], lengths[2]);
                cookie->host_only = lengths[1] == 1 && fields[1][0] == '1';
                cookie->secure = lengths[3] == 1 && fields[3][0] == '1';
                for (size_t i = 0; i < lengths[4] && fields[4][i] >= '0' && fields[4][i] <= '9'; ++i)
                    cookie->expires = cookie->expires * 10 + (fields[4][i] - '0');
                if (cookie->domain == NULL || cookie->path == NULL) {
                    free_cookie(cookie);
                    result = (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
                } else
                    insert(cookie);
            }
        }
        text = line_end + 1;
    }
    vh_unlock();
    return result;
}

int sceHttpGetCookieStats(void *stats)
{
    VH_TRACE();
    (void)stats;
    return VH_ERROR_UNSUPPORTED;
}

static int set_limit(unsigned int *limit, unsigned int value)
{
    if (value == 0)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    vh_lock();
    *limit = value;
    vh_unlock();
    return 0;
}

int sceHttpSetCookieMaxNum(unsigned int num)
{
    VH_TRACE();
    return set_limit(&g_max_num, num);
}

int sceHttpSetCookieMaxNumPerDomain(unsigned int num)
{
    VH_TRACE();
    return set_limit(&g_max_per_domain, num);
}

int sceHttpSetCookieMaxSize(unsigned int size)
{
    VH_TRACE();
    return set_limit(&g_max_size, size);
}

int sceHttpSetCookieTotalMaxSize(unsigned int size)
{
    VH_TRACE();
    return set_limit(&g_total_max_size, size);
}
