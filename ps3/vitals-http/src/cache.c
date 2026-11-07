/* The HTTP cache, as Sony's libhttp keeps it (the probe's proxy and cache half,
 * tests/http-probe/source/proxy.c): a revalidating cache, not one that answers by itself.
 * - cellHttpInitCache(size) makes it (0x80710043 a second time), up to size bytes of responses;
 *   the rest give 0x80710044 without it; cellHttpGetCacheInfo gives its size and what's used;
 * - for a client with its cache status on (off by default), a GET's 200 is kept, but for
 *   Cache-Control no-cache, no-store or private (Pragma doesn't count); one store for all clients;
 * - a GET with a kept response asks with If-Modified-Since, when it was kept ("+0000", as Sony's
 *   writes it), whatever max-age, Expires or ETag said; a 304 is answered with what was kept;
 * - what doesn't fit isn't kept: the oldest goes first.
 * Sony's fails a request with 0x80010002 after cellHttpEndCache when the client's cache status is
 * on (its lock is gone); vitals' goes on without the cache */

#include "vh.h"

#include <cell/http.h>
#include <stdio.h>
#include <string.h>

#define ERROR_CACHE_ALREADY ((int)0x80710043)
#define ERROR_CACHE_NOT_INITIALIZED ((int)0x80710044)

typedef struct VhCached {
	struct VhCached *next;
	char *key; /* scheme://host:port/path */
	char date[40];
	VhHeaders headers;
	unsigned char *body;
	size_t length, cost;
} VhCached;

static int g_cache, g_external;
static uint32_t g_size, g_used;
static VhCached *g_first;

static void cached_free(VhCached *entry)
{
	vh_free(entry->key);
	vh_headers_clear(&entry->headers);
	vh_free(entry->body);
	vh_free(entry);
}

static void drop_all(void)
{
	while (g_first != NULL) {
		VhCached *entry = g_first;
		g_first = entry->next;
		cached_free(entry);
	}
	g_used = 0;
}

static void key_of(const VhTransaction *t, char *key, size_t size)
{
	snprintf(key, size, "%s://%s:%u%s", t->scheme, t->host, t->port, t->path);
}

static VhCached *find(const char *key)
{
	for (VhCached *entry = g_first; entry != NULL; entry = entry->next)
		if (strcmp(entry->key, key) == 0)
			return entry;
	return NULL;
}

static void unlink_entry(VhCached *entry)
{
	for (VhCached **at = &g_first; *at != NULL; at = &(*at)->next)
		if (*at == entry) {
			*at = entry->next;
			g_used -= (uint32_t)entry->cost;
			return;
		}
}

/* For a request: a kept response's date to ask If-Modified-Since with, into date; 1 when there is one */
int vh_cache_condition(VhTransaction *t, char date[40])
{
	if (!g_cache || !t->client->cache || !vh_equal_nocase(t->method, "GET"))
		return 0;
	char key[1400];
	key_of(t, key, sizeof(key));
	vh_lock();
	VhCached *entry = find(key);
	if (entry != NULL)
		memcpy(date, entry->date, sizeof(entry->date));
	vh_unlock();
	return entry != NULL;
}

/* A 304 to a request that asked with a kept response: that response, its body to read from
 * memory. 1 when it was there */
int vh_cache_serve(VhTransaction *t)
{
	char key[1400];
	key_of(t, key, sizeof(key));
	vh_lock();
	VhCached *entry = find(key);
	int rc = 0;
	if (entry != NULL) {
		unsigned char *body = vh_alloc(entry->length);
		VhHeaders headers = {0};
		int ok = body != NULL;
		for (unsigned i = 0; ok && i < entry->headers.count; ++i)
			ok = vh_headers_add(&headers, entry->headers.items[i].name, entry->headers.items[i].value) == 0;
		if (ok) {
			memcpy(body, entry->body, entry->length);
			vh_headers_clear(&t->response);
			t->response = headers;
			char *reason = vh_strdup("OK");
			vh_free(t->reason);
			t->reason = reason;
			t->status = 200;
			vh_free(t->cached_body);
			t->cached_body = body;
			t->cached_length = entry->length;
			t->cached_at = 0;
			t->body_done = entry->length == 0;
			rc = 1;
		} else {
			vh_free(body);
			vh_headers_clear(&headers);
		}
	}
	vh_unlock();
	return rc;
}

/* Whether a response may be kept */
static int storable(const VhTransaction *t)
{
	for (unsigned i = 0; i < t->response.count; ++i) {
		const VhHeader *header = &t->response.items[i];
		if (!vh_equal_nocase(header->name, "Cache-Control"))
			continue;
		const char *value = header->value;
		static const char *const refused[] = {"no-cache", "no-store", "private"};
		for (unsigned j = 0; j < 3; ++j) {
			size_t length = strlen(refused[j]);
			for (const char *at = value; *at != '\0'; ++at)
				if (vh_equal_nocase_prefix(at, refused[j]) && (at == value || at[-1] == ' ' || at[-1] == ',') &&
				    (at[length] == '\0' || at[length] == ',' || at[length] == ' ' || at[length] == '='))
					return 0;
		}
	}
	return 1;
}

/* A 200 to a GET: whether its body is to be kept as it's read */
void vh_cache_consider(VhTransaction *t)
{
	t->cache_capture = g_cache && t->client->cache && t->status == 200 && vh_equal_nocase(t->method, "GET") &&
	                   storable(t);
	t->capture_length = 0;
}

void vh_cache_capture(VhTransaction *t, const void *data, size_t size)
{
	if (!t->cache_capture || size == 0)
		return;
	if (t->capture_length + size > g_size) {
		t->cache_capture = 0;
		return;
	}
	if (t->capture_length + size > t->capture_capacity) {
		size_t capacity = t->capture_capacity != 0 ? t->capture_capacity : 1024;
		while (capacity < t->capture_length + size)
			capacity *= 2;
		unsigned char *grown = vh_alloc(capacity);
		if (grown == NULL) {
			t->cache_capture = 0;
			return;
		}
		if (t->capture_length > 0)
			memcpy(grown, t->captured, t->capture_length);
		vh_free(t->captured);
		t->captured = grown;
		t->capture_capacity = capacity;
	}
	memcpy(t->captured + t->capture_length, data, size);
	t->capture_length += size;
}

/* RFC 1123's date, with "+0000" for its zone as Sony's writes it */
static void date_now(char out[40])
{
	static const char days[] = "ThuFriSatSunMonTueWed", months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
	int64_t now = vh_platform_now(), day = now / 86400, second = now % 86400;
	int weekday = (int)(day % 7);
	/* Howard Hinnant's civil_from_days */
	int64_t z = day + 719468, era = (z >= 0 ? z : z - 146096) / 146097, doe = z - era * 146097;
	int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365, year = yoe + era * 400;
	int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100), mp = (5 * doy + 2) / 153;
	int dom = (int)(doy - (153 * mp + 2) / 5 + 1), month = (int)(mp < 10 ? mp + 3 : mp - 9);
	year += month <= 2;
	/* The names copied by hand: Sony's _sys_vsnprintf has no precision for %s */
	char day_name[4], month_name[4];
	memcpy(day_name, days + weekday * 3, 3);
	memcpy(month_name, months + (month - 1) * 3, 3);
	day_name[3] = month_name[3] = '\0';
	snprintf(out, 40, "%s, %02d %s %04d %02d:%02d:%02d +0000", day_name, dom, month_name, (int)year,
	         (int)(second / 3600), (int)(second / 60 % 60), (int)(second % 60));
}

/* The whole body read: the response kept, in place of what was kept for its URL */
void vh_cache_store(VhTransaction *t)
{
	if (!t->cache_capture)
		return;
	t->cache_capture = 0;
	char key[1400];
	key_of(t, key, sizeof(key));
	size_t cost = t->capture_length + strlen(key) + 64;
	for (unsigned i = 0; i < t->response.count; ++i)
		cost += strlen(t->response.items[i].name) + strlen(t->response.items[i].value) + 2;
	vh_lock();
	if (!g_cache || cost > g_size) {
		vh_unlock();
		return;
	}
	VhCached *old = find(key);
	if (old != NULL) {
		unlink_entry(old);
		cached_free(old);
	}
	/* The oldest out until it fits */
	while (g_first != NULL && g_used + cost > g_size) {
		VhCached **last = &g_first;
		while ((*last)->next != NULL)
			last = &(*last)->next;
		VhCached *oldest = *last;
		unlink_entry(oldest);
		cached_free(oldest);
	}
	VhCached *entry = vh_calloc(sizeof(*entry));
	int ok = entry != NULL && (entry->key = vh_strdup(key)) != NULL;
	for (unsigned i = 0; ok && i < t->response.count; ++i)
		ok = vh_headers_add(&entry->headers, t->response.items[i].name, t->response.items[i].value) == 0;
	if (ok && t->capture_length > 0) {
		entry->body = vh_alloc(t->capture_length);
		ok = entry->body != NULL;
		if (ok)
			memcpy(entry->body, t->captured, t->capture_length);
	}
	if (!ok) {
		if (entry != NULL)
			cached_free(entry);
		vh_unlock();
		return;
	}
	entry->length = t->capture_length;
	entry->cost = cost;
	date_now(entry->date);
	entry->next = g_first;
	g_first = entry;
	g_used += (uint32_t)cost;
	vh_unlock();
	VH_LOG("transaction %p: response kept in the cache (%u bytes)", (void *)t, (unsigned)cost);
}

/* At cellHttpEnd: the cache's memory is libhttp's heap's */
void vh_cache_end(void)
{
	drop_all();
	g_cache = 0;
}

/* ---- the API ---- */

int cellHttpInitCache(uint32_t size)
{
	VH_LOG("cellHttpInitCache %u", (unsigned)size);
	if (g_cache)
		return ERROR_CACHE_ALREADY;
	g_size = size;
	g_used = 0;
	g_first = NULL;
	g_cache = 1;
	return 0;
}

int cellHttpEndCache(void)
{
	VH_LOG("cellHttpEndCache");
	if (!g_cache)
		return ERROR_CACHE_NOT_INITIALIZED;
	vh_lock();
	drop_all();
	g_cache = 0;
	vh_unlock();
	return 0;
}

int cellHttpFlushCache(void)
{
	VH_LOG("cellHttpFlushCache");
	if (!g_cache)
		return ERROR_CACHE_NOT_INITIALIZED;
	vh_lock();
	drop_all();
	vh_unlock();
	return 0;
}

/* Its size and what's used, two words */
int cellHttpGetCacheInfo(uint32_t *info)
{
	if (!g_cache)
		return ERROR_CACHE_NOT_INITIALIZED;
	if (info != NULL) {
		info[0] = g_size;
		info[1] = g_used;
	}
	return 0;
}

int cellHttpEndExternalCache(void)
{
	if (!g_external)
		return ERROR_CACHE_NOT_INITIALIZED;
	g_external = 0;
	return 0;
}

int cellHttpClientSetCacheStatus(CellHttpClientId id, bool enable)
{
	VH_LOG("cellHttpClientSetCacheStatus %p %d", (void *)id, enable ? 1 : 0);
	if (!vh_initialized())
		return VH_ERROR_NOT_INITIALIZED;
	VhClient *client = vh_client((void *)id);
	if (client == NULL)
		return VH_ERROR_BAD_CLIENT;
	/* On only with the cache there, as Sony's */
	if (enable && !g_cache)
		return ERROR_CACHE_NOT_INITIALIZED;
	client->cache = enable ? 1 : 0;
	return 0;
}

int cellHttpClientGetCacheStatus(CellHttpClientId id, bool *enable)
{
	if (!vh_initialized())
		return VH_ERROR_NOT_INITIALIZED;
	VhClient *client = vh_client((void *)id);
	if (client == NULL)
		return VH_ERROR_BAD_CLIENT;
	if (enable == NULL)
		return VH_ERROR_NO_BUFFER;
	*enable = client->cache != 0;
	return 0;
}

/* Kept: what Sony's calls it with isn't worked out */
int cellHttpClientSetCacheCallback(CellHttpClientId id, void *callback, void *argument)
{
	VH_LOG("cellHttpClientSetCacheCallback %p %p", (void *)id, callback);
	if (!vh_initialized())
		return VH_ERROR_NOT_INITIALIZED;
	VhClient *client = vh_client((void *)id);
	if (client == NULL)
		return VH_ERROR_BAD_CLIENT;
	client->callbacks[VH_CALLBACK_CACHE] = callback;
	client->callback_arguments[VH_CALLBACK_CACHE] = argument;
	return 0;
}

int vh_cache_initialized(void)
{
	return g_cache;
}

/* ---- the external cache: on the game's block (cellHttpInitExternalCache's), its codes as Sony's;
 * nothing is kept in it yet ---- */

void vh_external_cache_size(uint32_t size);

int vh_external_cache_initialized(void)
{
	return g_external;
}

int cellHttpInitExternalCache(void *block, uint32_t size)
{
	VH_LOG("cellHttpInitExternalCache %p %u", block, (unsigned)size);
	(void)block;
	if (g_external)
		return ERROR_CACHE_ALREADY;
	g_external = 1;
	vh_external_cache_size(size);
	return 0;
}

int cellHttpFlushExternalCache(void)
{
	return g_external ? 0 : ERROR_CACHE_NOT_INITIALIZED;
}

/* ---- the walks ---- */

typedef int (*CacheWalk)(void *record, void *argument);

/* Each kept response to callback(record, argument): what Sony's record holds isn't worked out, so
 * vitals' is zeros */
int cellHttp_003F88AE(CacheWalk callback, void *argument)
{
	if (!g_cache)
		return ERROR_CACHE_NOT_INITIALIZED;
	vh_lock();
	unsigned count = 0;
	for (VhCached *entry = g_first; entry != NULL; entry = entry->next)
		++count;
	vh_unlock();
	for (unsigned i = 0; i < count && callback != NULL; ++i) {
		uint32_t record[8] = {0};
		(void)callback(record, argument);
	}
	return 0;
}

/* The external cache holds nothing, so its walk calls nothing */
int cellHttp_9BF4365D(CacheWalk callback, void *argument)
{
	(void)callback, (void)argument;
	return g_external ? 0 : ERROR_CACHE_NOT_INITIALIZED;
}

/* Its size and what it holds (in Sony's, a count of 512-byte blocks) */
static uint32_t g_external_size;

int cellHttpGetExternalCacheInfo(uint32_t *info)
{
	if (!g_external)
		return ERROR_CACHE_NOT_INITIALIZED;
	if (info != NULL) {
		info[0] = g_external_size;
		info[1] = 0;
	}
	return 0;
}

void vh_external_cache_size(uint32_t size)
{
	g_external_size = size;
}
