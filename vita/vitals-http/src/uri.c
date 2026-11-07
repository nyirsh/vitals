#include "vh.h"

#include "diagnostics.h"

#include <string.h>

/* The parts of a URI, as offsets into it (RFC 3986); a part that isn't there has no offset */
typedef struct UriParts {
    const char *text;
    int has_scheme, has_authority, has_userinfo, has_password, has_port, has_query, has_fragment;
    size_t scheme, scheme_length;
    size_t user, user_length;
    size_t password, password_length;
    size_t host, host_length;
    size_t port_text, port_length;
    size_t path, path_length;
    size_t query, query_length;       /* with its '?' */
    size_t fragment, fragment_length; /* with its '#' */
    unsigned int port;
} UriParts;

static int is_alpha(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
static int is_digit(char c) { return c >= '0' && c <= '9'; }

static void split(const char *uri, UriParts *parts)
{
    size_t at = 0, length = strlen(uri);
    memset(parts, 0, sizeof(*parts));
    parts->text = uri;

    /* scheme ":" */
    size_t scheme_end = 0;
    if (is_alpha(uri[0])) {
        while (is_alpha(uri[scheme_end]) || is_digit(uri[scheme_end]) || uri[scheme_end] == '+' ||
               uri[scheme_end] == '-' || uri[scheme_end] == '.')
            ++scheme_end;
        if (uri[scheme_end] == ':') {
            parts->has_scheme = 1;
            parts->scheme_length = scheme_end;
            at = scheme_end + 1;
        }
    }
    /* "//" authority */
    if (uri[at] == '/' && uri[at + 1] == '/') {
        parts->has_authority = 1;
        at += 2;
        size_t end = at;
        while (end < length && uri[end] != '/' && uri[end] != '?' && uri[end] != '#')
            ++end;
        size_t host = at;
        for (size_t i = at; i < end; ++i)
            if (uri[i] == '@')
                host = i + 1;
        if (host != at) {
            parts->has_userinfo = 1;
            parts->user = at;
            size_t user_end = host - 1;
            for (size_t i = at; i < user_end; ++i)
                if (uri[i] == ':') {
                    parts->has_password = 1;
                    parts->password = i + 1;
                    parts->password_length = user_end - (i + 1);
                    user_end = i;
                    break;
                }
            parts->user_length = user_end - at;
        }
        /* host, or [IPv6], then ":" port */
        size_t host_end = end;
        size_t search = host;
        if (uri[host] == '[') {
            while (search < end && uri[search] != ']')
                ++search;
        }
        for (size_t i = search; i < end; ++i)
            if (uri[i] == ':') {
                host_end = i;
                parts->has_port = 1;
                parts->port_text = i + 1;
                parts->port_length = end - (i + 1);
                break;
            }
        parts->host = host;
        parts->host_length = host_end - host;
        at = end;
    }
    parts->path = at;
    while (at < length && uri[at] != '?' && uri[at] != '#')
        ++at;
    parts->path_length = at - parts->path;
    if (uri[at] == '?') {
        parts->has_query = 1;
        parts->query = at;
        while (at < length && uri[at] != '#')
            ++at;
        parts->query_length = at - parts->query;
    }
    if (uri[at] == '#') {
        parts->has_fragment = 1;
        parts->fragment = at;
        parts->fragment_length = length - at;
    }
}

/* Reads the port into *port, left as it is when there is none; 0 when it isn't a port */
static int read_port(const UriParts *parts, unsigned int *port)
{
    unsigned int value = 0;
    if (!parts->has_port)
        return 1;
    if (parts->port_length == 0 || parts->port_length > 5)
        return 0;
    for (size_t i = 0; i < parts->port_length; ++i) {
        char c = parts->text[parts->port_text + i];
        if (!is_digit(c))
            return 0;
        value = value * 10u + (unsigned int)(c - '0');
    }
    if (value == 0 || value > 65535u)
        return 0;
    *port = value;
    return 1;
}

int vh_parse_url(const char *url, VhUrl *parts)
{
    UriParts uri;
    unsigned int port = 0;

    if (url == NULL || parts == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    split(url, &uri);
    if (!uri.has_scheme || !uri.has_authority || uri.host_length == 0 || uri.host_length >= VH_HOST_MAX ||
        !read_port(&uri, &port))
        return (int)SCE_HTTP_ERROR_INVALID_URL;
    if (uri.scheme_length == 4 && vh_equal_nocase(url, "http", 4))
        parts->https = 0;
    else if (uri.scheme_length == 5 && vh_equal_nocase(url, "https", 5))
        parts->https = 1;
    else
        return (int)SCE_HTTP_ERROR_UNKNOWN_SCHEME;
    parts->scheme = url;
    parts->scheme_length = uri.scheme_length;
    parts->host = url + uri.host;
    parts->host_length = uri.host_length;
    parts->port = (unsigned short)(port != 0 ? port : parts->https ? 443u : 80u);
    /* The request target: the path and query, "/" when the path is empty */
    parts->path = url + uri.path;
    parts->path_length = uri.path_length + uri.query_length;
    return 0;
}

/* ---- escaping ---- */

static int unreserved(unsigned char c)
{
    return is_alpha((char)c) || is_digit((char)c) || c == '-' || c == '.' || c == '_' || c == '~';
}

int sceHttpUriEscape(char *out, unsigned int *require, unsigned int prepare, const char *in)
{
    VH_TRACE();
    static const char hex[] = "0123456789ABCDEF";
    if (in == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    size_t needed = 1;
    for (const unsigned char *c = (const unsigned char *)in; *c != '\0'; ++c)
        needed += unreserved(*c) ? 1u : 3u;
    /* Only sizes: apps escape credentials too */
    VITALS_VERBOSE("uri escape length=%u needed=%u prepare=%u out=%s require=%s", (unsigned int)strlen(in),
                   (unsigned int)needed, prepare, out != NULL ? "yes" : "no", require != NULL ? "yes" : "no");
    if (require != NULL)
        *require = (unsigned int)needed;
    if (out == NULL)
        return 0;
    if (prepare < needed)
        return (int)SCE_HTTP_ERROR_OUT_OF_SIZE;
    size_t at = 0;
    for (const unsigned char *c = (const unsigned char *)in; *c != '\0'; ++c) {
        if (unreserved(*c))
            out[at++] = (char)*c;
        else {
            out[at++] = '%';
            out[at++] = hex[*c >> 4];
            out[at++] = hex[*c & 15u];
        }
    }
    out[at] = '\0';
    return 0;
}

static int hex_value(char c)
{
    return is_digit(c) ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}

int sceHttpUriUnescape(char *out, unsigned int *require, unsigned int prepare, const char *in)
{
    VH_TRACE();
    if (in == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    /* A '%' not followed by two hex digits stays as it is; the string's NUL ends the checks */
    size_t needed = 1, length = strlen(in);
    for (size_t i = 0; i < length; ++i, ++needed)
        if (in[i] == '%' && hex_value(in[i + 1]) >= 0 && hex_value(in[i + 2]) >= 0)
            i += 2;
    if (require != NULL)
        *require = (unsigned int)needed;
    if (out == NULL)
        return 0;
    if (prepare < needed)
        return (int)SCE_HTTP_ERROR_OUT_OF_SIZE;
    size_t at = 0;
    for (size_t i = 0; i < length; ++i) {
        if (in[i] == '%' && hex_value(in[i + 1]) >= 0 && hex_value(in[i + 2]) >= 0) {
            out[at++] = (char)(hex_value(in[i + 1]) * 16 + hex_value(in[i + 2]));
            i += 2;
        } else
            out[at++] = in[i];
    }
    out[at] = '\0';
    return 0;
}

/* ---- parsing and building ---- */

/* Copies a part into the pool, NUL-terminated, and points field at it */
static void place(char **field, const char *text, size_t length, char *pool, size_t *used)
{
    char *copy = pool + *used;
    memcpy(copy, text, length);
    copy[length] = '\0';
    *used += length + 1;
    *field = copy;
}

int sceHttpUriParse(SceHttpUriElement *out, const char *srcUrl, void *pool, unsigned int *require,
                    unsigned int prepare)
{
    VH_TRACE();
    UriParts parts;
    unsigned int port = 0;

    if (srcUrl == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    split(srcUrl, &parts);
    if (!parts.has_scheme || !read_port(&parts, &port))
        return (int)SCE_HTTP_ERROR_INVALID_URL;
    /* Every part has a string, empty when it isn't there */
    size_t needed = parts.scheme_length + parts.user_length + parts.password_length + parts.host_length +
                    parts.path_length + parts.query_length + parts.fragment_length + 7;
    if (require != NULL)
        *require = (unsigned int)needed;
    if (out == NULL || pool == NULL)
        return 0;
    if (prepare < needed)
        return (int)SCE_HTTP_ERROR_OUT_OF_SIZE;
    size_t used = 0;
    memset(out, 0, sizeof(*out));
    out->opaque = !parts.has_authority;
    place(&out->scheme, srcUrl + parts.scheme, parts.scheme_length, pool, &used);
    place(&out->username, srcUrl + parts.user, parts.user_length, pool, &used);
    place(&out->password, srcUrl + parts.password, parts.password_length, pool, &used);
    place(&out->hostname, srcUrl + parts.host, parts.host_length, pool, &used);
    place(&out->path, srcUrl + parts.path, parts.path_length, pool, &used);
    place(&out->query, srcUrl + parts.query, parts.query_length, pool, &used);
    place(&out->fragment, srcUrl + parts.fragment, parts.fragment_length, pool, &used);
    if (port == 0 && parts.scheme_length == 4 && vh_equal_nocase(srcUrl, "http", 4))
        port = 80;
    else if (port == 0 && parts.scheme_length == 5 && vh_equal_nocase(srcUrl, "https", 5))
        port = 443;
    out->port = (unsigned short)port;
    return 0;
}

/* Appends text when out has room, counting the size either way */
static void append(char *out, size_t capacity, size_t *at, const char *text, size_t length)
{
    if (out != NULL && *at + length < capacity)
        memcpy(out + *at, text, length);
    *at += length;
}

static size_t text_length(const char *text)
{
    return text == NULL ? 0 : strlen(text);
}

int sceHttpUriBuild(char *out, unsigned int *require, unsigned int prepare, const SceHttpUriElement *srcElement,
                    unsigned int option)
{
    VH_TRACE();
    char port[8];
    size_t at = 0;

    if (srcElement == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    const SceHttpUriElement *e = srcElement;
    const size_t capacity = out != NULL ? prepare : 0;
    if ((option & SCE_HTTP_URI_BUILD_WITH_SCHEME) && text_length(e->scheme) != 0) {
        append(out, capacity, &at, e->scheme, strlen(e->scheme));
        append(out, capacity, &at, e->opaque ? ":" : "://", e->opaque ? 1 : 3);
    }
    if ((option & SCE_HTTP_URI_BUILD_WITH_USERNAME) && text_length(e->username) != 0) {
        append(out, capacity, &at, e->username, strlen(e->username));
        if ((option & SCE_HTTP_URI_BUILD_WITH_PASSWORD) && text_length(e->password) != 0) {
            append(out, capacity, &at, ":", 1);
            append(out, capacity, &at, e->password, strlen(e->password));
        }
        append(out, capacity, &at, "@", 1);
    }
    if (option & SCE_HTTP_URI_BUILD_WITH_HOSTNAME)
        append(out, capacity, &at, e->hostname != NULL ? e->hostname : "", text_length(e->hostname));
    if ((option & SCE_HTTP_URI_BUILD_WITH_PORT) && e->port != 0) {
        size_t length = 0;
        char digits[8];
        for (unsigned int value = e->port; value != 0; value /= 10u)
            digits[length++] = (char)('0' + value % 10u);
        port[0] = ':';
        for (size_t i = 0; i < length; ++i)
            port[1 + i] = digits[length - 1 - i];
        append(out, capacity, &at, port, length + 1);
    }
    if (option & SCE_HTTP_URI_BUILD_WITH_PATH)
        append(out, capacity, &at, e->path != NULL ? e->path : "", text_length(e->path));
    if (option & SCE_HTTP_URI_BUILD_WITH_QUERY)
        append(out, capacity, &at, e->query != NULL ? e->query : "", text_length(e->query));
    if (option & SCE_HTTP_URI_BUILD_WITH_FRAGMENT)
        append(out, capacity, &at, e->fragment != NULL ? e->fragment : "", text_length(e->fragment));
    if (require != NULL)
        *require = (unsigned int)(at + 1);
    if (out == NULL)
        return 0;
    if (prepare < at + 1)
        return (int)SCE_HTTP_ERROR_OUT_OF_SIZE;
    out[at] = '\0';
    return 0;
}

/* Removes "." and ".." segments from a path (RFC 3986, 5.2.4), into out, which holds length + 1
 * bytes; returns the new length */
static size_t remove_dot_segments(const char *path, size_t length, char *out)
{
    size_t in = 0, at = 0;
    while (in < length) {
        if (length - in >= 3 && memcmp(path + in, "../", 3) == 0)
            in += 3;
        else if (length - in >= 2 && memcmp(path + in, "./", 2) == 0)
            in += 2;
        else if (length - in >= 3 && memcmp(path + in, "/./", 3) == 0)
            in += 2;
        else if (length - in == 2 && memcmp(path + in, "/.", 2) == 0) {
            out[at++] = '/';
            in += 2;
        } else if ((length - in >= 4 && memcmp(path + in, "/../", 4) == 0) ||
                   (length - in == 3 && memcmp(path + in, "/..", 3) == 0)) {
            /* "/../" leaves its last "/" for the next step; "/.." at the end becomes "/" */
            in += 3;
            while (at > 0 && out[at - 1] != '/')
                --at;
            if (at > 0)
                --at;
            if (in == length)
                out[at++] = '/';
        } else if ((length - in == 1 && path[in] == '.') || (length - in == 2 && memcmp(path + in, "..", 2) == 0))
            in = length;
        else {
            do
                out[at++] = path[in++];
            while (in < length && path[in] != '/');
        }
    }
    out[at] = '\0';
    return at;
}

int sceHttpUriSweepPath(char *dst, const char *src, unsigned int srcSize)
{
    VH_TRACE();
    if (dst == NULL || src == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    size_t length = 0;
    while (length < srcSize && src[length] != '\0')
        ++length;
    char *copy = vh_alloc(length + 1);
    if (copy == NULL)
        return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
    /* dst may be src itself */
    memcpy(copy, src, length);
    copy[length] = '\0';
    remove_dot_segments(copy, length, dst);
    vh_free(copy);
    return 0;
}

int sceHttpUriMerge(char *mergedUrl, const char *url, const char *relativeUrl, unsigned int *require,
                    unsigned int prepare, unsigned int option)
{
    VH_TRACE();
    UriParts base, relative;
    (void)option;

    if (url == NULL || relativeUrl == NULL)
        return (int)SCE_HTTP_ERROR_INVALID_VALUE;
    split(url, &base);
    split(relativeUrl, &relative);
    if (!base.has_scheme)
        return (int)SCE_HTTP_ERROR_INVALID_URL;

    /* RFC 3986, 5.2.2: which parts come from where, and the path before dot removal */
    const UriParts *authority = &relative, *query = &relative;
    const char *scheme_text = relativeUrl;
    size_t scheme_length = relative.scheme_length;
    size_t path_capacity = base.path_length + relative.path_length + 2;
    char *path = vh_alloc(path_capacity), *clean = vh_alloc(path_capacity);
    if (path == NULL || clean == NULL) {
        vh_free(path);
        vh_free(clean);
        return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
    }
    size_t path_length;
    if (relative.has_scheme) {
        memcpy(path, relativeUrl + relative.path, relative.path_length);
        path_length = relative.path_length;
    } else {
        scheme_text = url;
        scheme_length = base.scheme_length;
        if (relative.has_authority) {
            memcpy(path, relativeUrl + relative.path, relative.path_length);
            path_length = relative.path_length;
        } else {
            authority = &base;
            if (relative.path_length == 0) {
                memcpy(path, url + base.path, base.path_length);
                path_length = base.path_length;
                if (!relative.has_query)
                    query = &base;
            } else if (relativeUrl[relative.path] == '/') {
                memcpy(path, relativeUrl + relative.path, relative.path_length);
                path_length = relative.path_length;
            } else {
                /* Merge: the base path up to its last '/', then the relative path */
                size_t keep = base.path_length;
                while (keep > 0 && url[base.path + keep - 1] != '/')
                    --keep;
                path_length = 0;
                if (base.has_authority && base.path_length == 0)
                    path[path_length++] = '/';
                memcpy(path + path_length, url + base.path, keep);
                path_length += keep;
                memcpy(path + path_length, relativeUrl + relative.path, relative.path_length);
                path_length += relative.path_length;
            }
        }
    }
    path_length = remove_dot_segments(path, path_length, clean);

    size_t at = 0;
    const size_t capacity = mergedUrl != NULL ? prepare : 0;
    const char *authority_text = authority == &base ? url : relativeUrl;
    append(mergedUrl, capacity, &at, scheme_text, scheme_length);
    append(mergedUrl, capacity, &at, ":", 1);
    if (authority->has_authority) {
        size_t start = authority->has_userinfo ? authority->user : authority->host;
        size_t end = authority->has_port ? authority->port_text + authority->port_length
                                         : authority->host + authority->host_length;
        append(mergedUrl, capacity, &at, "//", 2);
        append(mergedUrl, capacity, &at, authority_text + start, end - start);
    }
    append(mergedUrl, capacity, &at, clean, path_length);
    const char *query_text = query == &base ? url : relativeUrl;
    if (query->has_query)
        append(mergedUrl, capacity, &at, query_text + query->query, query->query_length);
    if (relative.has_fragment)
        append(mergedUrl, capacity, &at, relativeUrl + relative.fragment, relative.fragment_length);
    vh_free(path);
    vh_free(clean);
    if (require != NULL)
        *require = (unsigned int)(at + 1);
    if (mergedUrl == NULL)
        return 0;
    if (prepare < at + 1)
        return (int)SCE_HTTP_ERROR_OUT_OF_SIZE;
    mergedUrl[at] = '\0';
    return 0;
}
