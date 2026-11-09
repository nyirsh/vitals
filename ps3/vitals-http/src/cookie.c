/* The cookie store, as Sony's libhttp keeps it (the probe's cookie half,
 * tests/http-probe/source/cookie.c):
 * - one store for every client, on its own heap on the block cellHttpInitCookie gets (before or
 *   after cellHttpInit); clients with cookies on keep what Set-Cookie gives and send what matches;
 * - a cookie is its host and name: another with them replaces it, whatever its path, and goes last;
 *   cookies without "=" all have the one name between them;
 * - Domain must be the host or a domain it's in, else the cookie is dropped (AddCookieWithClientId
 *   gives 0x80710042); without Path, a cookie's path is its request's up to its last "/";
 * - a request gets the cookies whose domain the host matches, whose path its path starts with (a
 *   plain prefix, as Sony's: "/cook" matches "/cookie"), Secure ones only over https, unexpired;
 *   longest path first, then oldest first (RFC 6265's order: Sony's comes from its store's hash and
 *   sort); in a Cookie header right after Connection;
 * - the game's send callback gets that header's value, twice, as Sony's calls it; a negative answer
 *   fails the request with it. Its receive callback gets each Set-Cookie (after the domain check,
 *   before the expiry's); any answer but 0 drops the cookie;
 * - each cookie remembers the client that stored it (Set-Cookie's, AddCookieWithClientId's or
 *   ImportWithClientId's): ExportWithClientId exports that client's, client 0 (CookieExport) all;
 * - only cookies with Expires or Max-Age are exported, as a big-endian length, the MD5 of what
 *   follows, then a record each: 1 the expiry (8 bytes, microseconds since 0001-01-01), 2 domain,
 *   3 name, 4 value (left out without "="), 5 path, 0xff the end; each a type, a 2-byte length and
 *   the bytes. Secure and HttpOnly aren't kept, as in Sony's export. */

#include "vh.h"

#include <cell/http.h>
#include <stdio.h>
#include <string.h>

#define MIN_POOL 592
#define ERROR_COOKIE_NOT_FOUND ((int)0x80710041)
#define ERROR_COOKIE_INVALID_DOMAIN ((int)0x80710042)
#define UTIL_NO_BUFFER ((int)0x80711002)
/* Seconds from 0001-01-01 to 1970-01-01 */
#define EPOCH_SECONDS 62135596800ll

typedef struct VhCookie {
	struct VhCookie *next;
	char *domain, *path, *name, *value; /* value NULL for a cookie without "=" */
	int secure, persistent;
	int64_t expires; /* seconds since 1970, for a persistent one */
	const void *owner; /* the client that stored it */
} VhCookie;

static int g_cookies;
static VhCookie *g_first, *g_last;

/* ---- the store's memory and list ---- */

static char *cookie_strdup(const char *text, size_t length)
{
	char *copy = vh_platform_cookie_alloc(length + 1);
	if (copy != NULL) {
		memcpy(copy, text, length);
		copy[length] = '\0';
	}
	return copy;
}

static void cookie_free(VhCookie *cookie)
{
	vh_platform_cookie_free(cookie->domain);
	vh_platform_cookie_free(cookie->path);
	vh_platform_cookie_free(cookie->name);
	vh_platform_cookie_free(cookie->value);
	vh_platform_cookie_free(cookie);
}

/* Every cookie for which drop says so */
static void remove_where(int (*drop)(const VhCookie *, const void *), const void *argument)
{
	VhCookie **at = &g_first;
	g_last = NULL;
	while (*at != NULL) {
		VhCookie *cookie = *at;
		if (drop(cookie, argument)) {
			*at = cookie->next;
			cookie_free(cookie);
		} else {
			g_last = cookie;
			at = &cookie->next;
		}
	}
}

static int drop_all(const VhCookie *cookie, const void *argument)
{
	(void)cookie, (void)argument;
	return 1;
}

static int drop_session(const VhCookie *cookie, const void *argument)
{
	(void)argument;
	return !cookie->persistent;
}

static int drop_expired(const VhCookie *cookie, const void *now)
{
	return cookie->persistent && cookie->expires <= *(const int64_t *)now;
}

static int drop_same(const VhCookie *cookie, const void *other)
{
	const VhCookie *new_one = other;
	if (!vh_equal_nocase(cookie->domain, new_one->domain))
		return 0;
	if (cookie->value == NULL || new_one->value == NULL)
		return cookie->value == NULL && new_one->value == NULL;
	return strcmp(cookie->name, new_one->name) == 0;
}

/* cookie into the store, in place of one with its host and name; an expired one only removes */
static void store(VhCookie *cookie)
{
	remove_where(drop_same, cookie);
	if (cookie->persistent && cookie->expires <= vh_platform_now()) {
		cookie_free(cookie);
		return;
	}
	cookie->next = NULL;
	if (g_last != NULL)
		g_last->next = cookie;
	else
		g_first = cookie;
	g_last = cookie;
}

/* ---- Set-Cookie ---- */

static int lower(int c)
{
	return c >= 'A' && c <= 'Z' ? c + 32 : c;
}

static int blank(int c)
{
	return c == ' ' || c == '\t';
}

static void trim(const char **start, const char **end)
{
	while (*start < *end && blank((unsigned char)**start))
		++*start;
	while (*end > *start && blank((unsigned char)(*end)[-1]))
		--*end;
}

static int word_is(const char *start, const char *end, const char *word)
{
	size_t length = strlen(word);
	if ((size_t)(end - start) != length)
		return 0;
	for (size_t i = 0; i < length; ++i)
		if (lower((unsigned char)start[i]) != word[i])
			return 0;
	return 1;
}

/* host is domain, or in it */
static int domain_matches(const char *host, const char *domain)
{
	size_t host_length = strlen(host), domain_length = strlen(domain);
	if (domain_length == 0 || domain_length > host_length)
		return 0;
	const char *tail = host + host_length - domain_length;
	for (size_t i = 0; i < domain_length; ++i)
		if (lower((unsigned char)tail[i]) != lower((unsigned char)domain[i]))
			return 0;
	return domain_length == host_length || tail[-1] == '.';
}

/* Days from 1970-01-01 to a date (Howard Hinnant's) */
static int64_t days_from_civil(int64_t year, int month, int day)
{
	year -= month <= 2;
	int64_t era = (year >= 0 ? year : year - 399) / 400;
	int64_t year_of_era = year - era * 400;
	int64_t day_of_year = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1;
	int64_t day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
	return era * 146097 + day_of_era - 719468;
}

/* An Expires date ("Wed, 01 Jan 2099 00:00:00 GMT", or with "-" between the date's parts and a
 * two-digit year) as seconds since 1970; 0 when it can't be read */
static int parse_date(const char *start, const char *end, int64_t *seconds)
{
	static const char months[] = "janfebmaraprmayjunjulaugsepoctnovdec";
	int day = -1, month = -1, hour = -1, minute = -1, second = -1;
	int64_t year = -1;
	const char *at = start;
	while (at < end) {
		if (*at >= '0' && *at <= '9') {
			int64_t number = 0;
			const char *digits = at;
			while (at < end && *at >= '0' && *at <= '9')
				number = number * 10 + (*at++ - '0');
			if (at < end && *at == ':' && hour < 0) {
				hour = (int)number;
				const char *rest = at + 1;
				minute = second = 0;
				for (int part = 0; part < 2 && rest < end; ++part) {
					int value = 0;
					while (rest < end && *rest >= '0' && *rest <= '9')
						value = value * 10 + (*rest++ - '0');
					if (part == 0)
						minute = value;
					else
						second = value;
					if (rest < end && *rest == ':')
						++rest;
					else
						break;
				}
				at = rest;
			} else if (day < 0 && at - digits <= 2)
				day = (int)number;
			else if (year < 0)
				year = at - digits <= 2 ? (number < 70 ? 2000 + number : 1900 + number) : number;
		} else if (((*at | 32) >= 'a' && (*at | 32) <= 'z')) {
			const char *word = at;
			while (at < end && ((*at | 32) >= 'a' && (*at | 32) <= 'z'))
				++at;
			if (at - word >= 3 && month < 0)
				for (int i = 0; i < 12; ++i)
					if (lower((unsigned char)word[0]) == months[i * 3] && lower((unsigned char)word[1]) == months[i * 3 + 1] &&
					    lower((unsigned char)word[2]) == months[i * 3 + 2])
						month = i + 1;
		} else
			++at;
	}
	if (day < 1 || day > 31 || month < 1 || year < 0 || hour < 0 || hour > 23 || minute > 59 || second > 60)
		return 0;
	*seconds = days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second;
	return 1;
}

/* A Set-Cookie value for host, from a request to path: a new cookie, or 0 when there isn't one,
 * ERROR_COOKIE_INVALID_DOMAIN for a Domain the host isn't in, VH_ERROR_NO_MEMORY */
static int parse_cookie(const char *text, const char *host, const char *path, VhCookie **out)
{
	*out = NULL;
	const char *end = text + strlen(text);
	const char *pair_end = strchr(text, ';');
	if (pair_end == NULL)
		pair_end = end;
	const char *name = text, *name_end = pair_end, *value = NULL, *value_end = NULL;
	const char *equals = memchr(text, '=', (size_t)(pair_end - text));
	if (equals != NULL) {
		name_end = equals;
		value = equals + 1;
		value_end = pair_end;
		trim(&value, &value_end);
	}
	trim(&name, &name_end);
	if (equals == NULL && name == name_end)
		return VH_ERROR_NO_BUFFER;
	const char *domain = NULL, *domain_end = NULL, *cookie_path = NULL, *cookie_path_end = NULL;
	int secure = 0, has_expires = 0, has_max_age = 0;
	int64_t expires = 0, max_age = 0;
	for (const char *at = pair_end; at < end;) {
		const char *attribute = at + 1;
		const char *attribute_end = strchr(attribute, ';');
		if (attribute_end == NULL)
			attribute_end = end;
		at = attribute_end;
		const char *key = attribute, *key_end = attribute_end, *argument = attribute_end, *argument_end = attribute_end;
		const char *sign = memchr(attribute, '=', (size_t)(attribute_end - attribute));
		if (sign != NULL) {
			key_end = sign;
			argument = sign + 1;
		}
		trim(&key, &key_end);
		trim(&argument, &argument_end);
		if (word_is(key, key_end, "domain")) {
			domain = argument;
			domain_end = argument_end;
			if (domain < domain_end && *domain == '.')
				++domain;
		} else if (word_is(key, key_end, "path")) {
			cookie_path = argument;
			cookie_path_end = argument_end;
		} else if (word_is(key, key_end, "secure"))
			secure = 1;
		else if (word_is(key, key_end, "expires"))
			has_expires = parse_date(argument, argument_end, &expires);
		else if (word_is(key, key_end, "max-age")) {
			int negative = argument < argument_end && *argument == '-';
			const char *digit = argument + negative;
			int64_t seconds = 0;
			int count = 0;
			while (digit < argument_end && *digit >= '0' && *digit <= '9' && count < 12)
				seconds = seconds * 10 + (*digit++ - '0'), ++count;
			if (count > 0) {
				has_max_age = 1;
				max_age = negative ? -seconds : seconds;
			}
		}
	}
	char domain_text[256];
	if (domain != NULL && domain < domain_end) {
		size_t length = (size_t)(domain_end - domain);
		if (length >= sizeof(domain_text))
			return ERROR_COOKIE_INVALID_DOMAIN;
		memcpy(domain_text, domain, length);
		domain_text[length] = '\0';
		if (!domain_matches(host, domain_text))
			return ERROR_COOKIE_INVALID_DOMAIN;
	} else
		snprintf(domain_text, sizeof(domain_text), "%s", host);
	/* Without Path: the request's, up to and with its last "/" (before any "?") */
	size_t default_path = 0;
	if (cookie_path == NULL || cookie_path == cookie_path_end) {
		size_t query = strcspn(path, "?#");
		for (size_t i = 0; i < query; ++i)
			if (path[i] == '/')
				default_path = i + 1;
		if (default_path == 0) {
			cookie_path = "/";
			cookie_path_end = cookie_path + 1;
		} else {
			cookie_path = path;
			cookie_path_end = path + default_path;
		}
	}
	VhCookie *cookie = vh_platform_cookie_alloc(sizeof(*cookie));
	if (cookie == NULL)
		return VH_ERROR_NO_MEMORY;
	memset(cookie, 0, sizeof(*cookie));
	cookie->domain = cookie_strdup(domain_text, strlen(domain_text));
	cookie->path = cookie_strdup(cookie_path, (size_t)(cookie_path_end - cookie_path));
	cookie->name = cookie_strdup(name, (size_t)(name_end - name));
	cookie->value = value != NULL ? cookie_strdup(value, (size_t)(value_end - value)) : NULL;
	if (cookie->domain == NULL || cookie->path == NULL || cookie->name == NULL || (value != NULL && cookie->value == NULL)) {
		cookie_free(cookie);
		return VH_ERROR_NO_MEMORY;
	}
	cookie->secure = secure;
	if (has_max_age) {
		cookie->persistent = 1;
		cookie->expires = vh_platform_now() + max_age;
	} else if (has_expires) {
		cookie->persistent = 1;
		cookie->expires = expires;
	}
	*out = cookie;
	return 0;
}

/* The transaction's URI, for the callbacks */
static void transaction_uri(const VhTransaction *t, CellHttpUri *uri)
{
	memset(uri, 0, sizeof(*uri));
	uri->scheme = t->scheme;
	uri->hostname = t->host;
	uri->username = t->username;
	uri->password = t->password;
	uri->path = t->path;
	uri->port = t->port;
}

int vh_cookie_receive(VhTransaction *t, const char *header)
{
	VhClient *client = t->client;
	if (!g_cookies)
		return VH_ERROR_NO_MEMORY;
	VhCookie *cookie = NULL;
	vh_platform_cookie_lock();
	int rc = parse_cookie(header, t->host, t->path, &cookie);
	vh_platform_cookie_unlock();
	if (rc == ERROR_COOKIE_INVALID_DOMAIN || rc == VH_ERROR_NO_BUFFER) {
		VITALS_LOG("transaction %p: a cookie refused for %s (0x%08x)", (void *)t, t->host, (unsigned)rc);
		return 0;
	}
	if (rc != 0)
		return rc;
	if (client->callbacks[VH_CALLBACK_COOKIE_RECV] != NULL) {
		CellHttpUri uri;
		transaction_uri(t, &uri);
		CellHttpCookieRecvCallback callback = (CellHttpCookieRecvCallback)client->callbacks[VH_CALLBACK_COOKIE_RECV];
		int answer = callback((CellHttpTransId)t, &uri, header, client->callback_arguments[VH_CALLBACK_COOKIE_RECV]);
		if (answer != 0) {
			VITALS_LOG("transaction %p: the game's cookie callback said %d", (void *)t, answer);
			vh_platform_cookie_lock();
			cookie_free(cookie);
			vh_platform_cookie_unlock();
			return 0;
		}
	}
	VITALS_LOG("transaction %p: cookie %s (%u bytes) for %s%s%s", (void *)t, cookie->name,
	       cookie->value != NULL ? (unsigned)strlen(cookie->value) : 0, cookie->domain, cookie->path,
	       cookie->persistent ? ", persistent" : "");
	cookie->owner = client;
	vh_platform_cookie_lock();
	if (g_cookies)
		store(cookie);
	else
		cookie_free(cookie);
	vh_platform_cookie_unlock();
	return 0;
}

/* ---- what a request sends ---- */

static int cookie_matches(const VhCookie *cookie, const char *host, const char *path, int secure, int64_t now)
{
	if (cookie->secure && !secure)
		return 0;
	if (cookie->persistent && cookie->expires <= now)
		return 0;
	return domain_matches(host, cookie->domain) && strncmp(path, cookie->path, strlen(cookie->path)) == 0;
}

/* The Cookie value for a request to host and path, into out (size bytes, when there is one):
 * its length, or -1 with none to send */
static long cookie_text(const char *host, const char *path, int secure, char *out, size_t size)
{
	int64_t now = vh_platform_now();
	remove_where(drop_expired, &now);
	const VhCookie *matched[256];
	size_t count = 0;
	for (const VhCookie *cookie = g_first; cookie != NULL && count < sizeof(matched) / sizeof(matched[0]); cookie = cookie->next)
		if (cookie_matches(cookie, host, path, secure, now))
			matched[count++] = cookie;
	if (count == 0)
		return -1;
	/* Longest path first, the store's order (oldest first) among the same length */
	for (size_t i = 1; i < count; ++i)
		for (size_t j = i; j > 0 && strlen(matched[j - 1]->path) < strlen(matched[j]->path); --j) {
			const VhCookie *swap = matched[j];
			matched[j] = matched[j - 1];
			matched[j - 1] = swap;
		}
	size_t used = 0;
#define ADD(text, length)                                         \
	do {                                                      \
		if (out != NULL && used + (length) < size)        \
			memcpy(out + used, (text), (length));     \
		used += (length);                                 \
	} while (0)
	for (size_t i = 0; i < count; ++i) {
		const VhCookie *cookie = matched[i];
		if (i > 0)
			ADD("; ", 2);
		if (cookie->value == NULL)
			ADD(cookie->name, strlen(cookie->name));
		else {
			if (cookie->name[0] != '\0') {
				ADD(cookie->name, strlen(cookie->name));
				ADD("=", 1);
			}
			ADD(cookie->value, strlen(cookie->value));
		}
	}
#undef ADD
	if (out != NULL && size > 0)
		out[used < size ? used : size - 1] = '\0';
	return (long)used;
}

static int secure_scheme(const char *scheme)
{
	return scheme != NULL && vh_equal_nocase(scheme, "https");
}

int vh_cookie_header(VhTransaction *t, char **value)
{
	*value = NULL;
	if (!g_cookies || !t->client->cookies)
		return 0;
	vh_platform_cookie_lock();
	long length = cookie_text(t->host, t->path, secure_scheme(t->scheme), NULL, 0);
	char *text = length >= 0 ? vh_alloc((size_t)length + 1) : NULL;
	if (text != NULL)
		cookie_text(t->host, t->path, secure_scheme(t->scheme), text, (size_t)length + 1);
	vh_platform_cookie_unlock();
	if (length < 0)
		return 0;
	if (text == NULL)
		return VH_ERROR_NO_MEMORY;
	VhClient *client = t->client;
	if (client->callbacks[VH_CALLBACK_COOKIE_SEND] != NULL) {
		CellHttpUri uri;
		transaction_uri(t, &uri);
		CellHttpCookieSendCallback callback = (CellHttpCookieSendCallback)client->callbacks[VH_CALLBACK_COOKIE_SEND];
		for (int call = 0; call < 2; ++call) {
			int answer = callback((CellHttpTransId)t, &uri, text, client->callback_arguments[VH_CALLBACK_COOKIE_SEND]);
			if (answer < 0) {
				VITALS_LOG("transaction %p: the game's cookie callback said %d", (void *)t, answer);
				vh_free(text);
				return answer;
			}
		}
	}
	*value = text;
	return 0;
}

/* ---- the API ---- */

int cellHttpInitCookie(void *pool, size_t size)
{
	VITALS_LOG("cellHttpInitCookie pool %p of %u bytes%s", pool, (unsigned)size, g_cookies ? ": already" : "");
	if (pool == NULL || size == 0)
		return VH_ERROR_NO_BUFFER;
	if (g_cookies)
		return VH_ERROR_ALREADY_INITIALIZED;
	if (size < MIN_POOL || vh_platform_cookie_create(pool, size) != 0)
		return VH_ERROR_NO_MEMORY;
	g_first = g_last = NULL;
	g_cookies = 1;
	return 0;
}

int cellHttpEndCookie(void)
{
	VITALS_LOG("cellHttpEndCookie%s", g_cookies ? "" : ": not initialized");
	if (!g_cookies)
		return VH_ERROR_NOT_INITIALIZED;
	vh_platform_cookie_lock();
	remove_where(drop_all, NULL);
	g_cookies = 0;
	vh_platform_cookie_unlock();
	vh_platform_cookie_delete();
	return 0;
}

int cellHttpCookieFlush(void)
{
	VITALS_LOG("cellHttpCookieFlush%s", g_cookies ? "" : ": not initialized");
	if (!g_cookies)
		return VH_ERROR_NOT_INITIALIZED;
	vh_platform_cookie_lock();
	remove_where(drop_all, NULL);
	vh_platform_cookie_unlock();
	return 0;
}

/* Sony's doesn't check the client, nor that the store is there */
int cellHttpSessionCookieFlush(CellHttpClientId id)
{
	VITALS_LOG("cellHttpSessionCookieFlush %p", (void *)id);
	(void)id;
	if (!g_cookies)
		return 0;
	vh_platform_cookie_lock();
	remove_where(drop_session, NULL);
	vh_platform_cookie_unlock();
	return 0;
}

/* The cookie as a Set-Cookie for uri; the client isn't checked, as Sony's */
int cellHttpAddCookieWithClientId(const CellHttpUri *uri, const char *cookie, CellHttpClientId id)
{
	VITALS_LOG("cellHttpAddCookieWithClientId %p %s", (void *)id, uri != NULL && uri->hostname != NULL ? uri->hostname : "-");
	(void)id;
	if (!g_cookies)
		return VH_ERROR_NO_MEMORY;
	if (uri == NULL || uri->hostname == NULL)
		return VH_ERROR_NO_BUFFER;
	if (cookie == NULL)
		return (int)0x80710005;
	VhCookie *parsed = NULL;
	vh_platform_cookie_lock();
	int rc = parse_cookie(cookie, uri->hostname, uri->path != NULL ? uri->path : "/", &parsed);
	if (rc == 0) {
		parsed->owner = (const void *)id;
		store(parsed);
	}
	vh_platform_cookie_unlock();
	return rc;
}

/* The cookies for uri as one string, then Sony's "\0 \0" after it (its builder ends each with "; "
 * and puts a NUL on the last ';'); *required is all of it. 0x80710041 without any */
int cellHttpGetCookie(const CellHttpUri *uri, char *buffer, size_t size, size_t *required)
{
	VITALS_VERBOSE("cellHttpGetCookie %s", uri != NULL && uri->hostname != NULL ? uri->hostname : "-");
	if (uri == NULL || uri->hostname == NULL)
		return VH_ERROR_NO_BUFFER;
	if (!g_cookies)
		return ERROR_COOKIE_NOT_FOUND;
	const char *path = uri->path != NULL ? uri->path : "/";
	vh_platform_cookie_lock();
	long length = cookie_text(uri->hostname, path, secure_scheme(uri->scheme), NULL, 0);
	int rc = 0;
	size_t need = length >= 0 ? (size_t)length + 3 : 0;
	if (length < 0)
		rc = ERROR_COOKIE_NOT_FOUND;
	else if (buffer == NULL) {
		if (required == NULL)
			rc = UTIL_NO_BUFFER;
		else
			*required = need;
	} else if (size < need)
		rc = VH_ERROR_INSUFFICIENT;
	else {
		cookie_text(uri->hostname, path, secure_scheme(uri->scheme), buffer, size);
		buffer[length] = '\0';
		buffer[length + 1] = ' ';
		buffer[length + 2] = '\0';
		if (required != NULL)
			*required = need;
	}
	vh_platform_cookie_unlock();
	return rc;
}

/* ---- export and import ---- */

static size_t put_field(unsigned char *out, size_t at, int type, const void *data, size_t length)
{
	if (out != NULL) {
		out[at] = (unsigned char)type;
		out[at + 1] = (unsigned char)(length >> 8);
		out[at + 2] = (unsigned char)length;
		if (length > 0)
			memcpy(out + at + 3, data, length);
	}
	return at + 3 + length;
}

/* The records of owner's cookies (everyone's for none), into out when there is one; their size */
static size_t export_records(unsigned char *out, const void *owner)
{
	size_t at = 0;
	int64_t now = vh_platform_now();
	for (const VhCookie *cookie = g_first; cookie != NULL; cookie = cookie->next) {
		if (!cookie->persistent || cookie->expires <= now || (owner != NULL && cookie->owner != owner))
			continue;
		uint64_t ticks = (uint64_t)(cookie->expires + EPOCH_SECONDS) * 1000000u;
		unsigned char expiry[8];
		for (int i = 0; i < 8; ++i)
			expiry[i] = (unsigned char)(ticks >> (56 - 8 * i));
		at = put_field(out, at, 1, expiry, 8);
		at = put_field(out, at, 2, cookie->domain, strlen(cookie->domain));
		at = put_field(out, at, 3, cookie->name, strlen(cookie->name));
		if (cookie->value != NULL)
			at = put_field(out, at, 4, cookie->value, strlen(cookie->value));
		at = put_field(out, at, 5, cookie->path, strlen(cookie->path));
		at = put_field(out, at, 0xff, NULL, 0);
	}
	return at;
}

/* As Sony's but for a buffer too small, which Sony's writes past: what fits is written, and the
 * answer is Sony's (0, *exported the export's size). Under 20 bytes: 0x80710006 */
int cellHttpCookieExportWithClientId(void *buffer, size_t size, size_t *exported, CellHttpClientId id)
{
	VITALS_LOG("cellHttpCookieExportWithClientId %p %u", (void *)id, (unsigned)size);
	if (buffer != NULL && size <= 19)
		return VH_ERROR_INSUFFICIENT;
	if (!g_cookies)
		return VH_ERROR_NOT_INITIALIZED;
	vh_platform_cookie_lock();
	size_t records = export_records(NULL, (const void *)id);
	unsigned char *data = vh_platform_cookie_alloc(records + 20);
	if (data == NULL) {
		vh_platform_cookie_unlock();
		return VH_ERROR_NO_MEMORY;
	}
	export_records(data + 20, (const void *)id);
	vh_platform_cookie_unlock();
	data[0] = (unsigned char)(records >> 24);
	data[1] = (unsigned char)(records >> 16);
	data[2] = (unsigned char)(records >> 8);
	data[3] = (unsigned char)records;
	vh_md5(data + 20, records, data + 4);
	if (exported != NULL)
		*exported = records + 20;
	if (buffer != NULL)
		memcpy(buffer, data, size < records + 20 ? size : records + 20);
	vh_platform_cookie_free(data);
	return 0;
}

int cellHttpCookieExport(void *buffer, size_t size, size_t *exported)
{
	return cellHttpCookieExportWithClientId(buffer, size, exported, 0);
}

/* An export's cookies into the store; anything that isn't one (or doesn't match its MD5) is
 * ignored, as Sony's answers 0 for it */
static void import_records(const unsigned char *data, size_t size, const void *owner)
{
	if (data == NULL || size < 20)
		return;
	size_t records = (size_t)data[0] << 24 | (size_t)data[1] << 16 | (size_t)data[2] << 8 | data[3];
	if (records > size - 20)
		return;
	unsigned char digest[16];
	vh_md5(data + 20, records, digest);
	if (memcmp(digest, data + 4, 16) != 0)
		return;
	const unsigned char *at = data + 20, *end = at + records;
	while (at < end) {
		const unsigned char *field[6] = {NULL};
		size_t length[6] = {0};
		int complete = 0;
		while (at + 3 <= end) {
			int type = at[0];
			size_t field_length = (size_t)at[1] << 8 | at[2];
			if (at + 3 + field_length > end)
				return;
			if (type == 0xff) {
				at += 3;
				complete = 1;
				break;
			}
			if (type >= 1 && type <= 5) {
				field[type] = at + 3;
				length[type] = field_length;
			}
			at += 3 + field_length;
		}
		if (!complete || field[1] == NULL || length[1] != 8 || field[2] == NULL || field[3] == NULL || field[5] == NULL)
			return;
		uint64_t ticks = 0;
		for (int i = 0; i < 8; ++i)
			ticks = ticks << 8 | field[1][i];
		VhCookie *cookie = vh_platform_cookie_alloc(sizeof(*cookie));
		if (cookie == NULL)
			return;
		memset(cookie, 0, sizeof(*cookie));
		cookie->domain = cookie_strdup((const char *)field[2], length[2]);
		cookie->name = cookie_strdup((const char *)field[3], length[3]);
		cookie->value = field[4] != NULL ? cookie_strdup((const char *)field[4], length[4]) : NULL;
		cookie->path = cookie_strdup((const char *)field[5], length[5]);
		cookie->persistent = 1;
		cookie->expires = (int64_t)(ticks / 1000000u) - EPOCH_SECONDS;
		cookie->owner = owner;
		if (cookie->domain == NULL || cookie->name == NULL || cookie->path == NULL ||
		    (field[4] != NULL && cookie->value == NULL)) {
			cookie_free(cookie);
			return;
		}
		store(cookie);
	}
}

int cellHttpCookieImportWithClientId(const void *buffer, size_t size, CellHttpClientId id)
{
	VITALS_LOG("cellHttpCookieImportWithClientId %p %u", (void *)id, (unsigned)size);
	if (!g_cookies)
		return VH_ERROR_NOT_INITIALIZED;
	vh_platform_cookie_lock();
	import_records(buffer, size, (const void *)id);
	vh_platform_cookie_unlock();
	return 0;
}

/* The store flushed first, as Sony's */
int cellHttpCookieImport(const void *buffer, size_t size)
{
	int rc = cellHttpCookieFlush();
	if (rc != 0)
		return rc;
	return cellHttpCookieImportWithClientId(buffer, size, 0);
}
