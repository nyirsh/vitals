/* vitals' additions, as the Vita's vitals-http has them (its redirect.c and useragent.c):
 *
 * - The host redirect list, /dev_hdd0/vitals/redirects.txt: "old-host new-host" pairs, one a
 *   line, '#' comments, 32 at most (shared/src/host_map.c and redirect_list.c, the Vita's too).
 *   A transaction's host goes through it wherever it's set (cellHttpCreateTransaction,
 *   cellHttpTransactionSetUri, a redirect followed), so the connection, the Host header, the
 *   certificate check and the URI the game reads back are all the new host's, as on the Vita.
 *   cellHttpClientCloseConnections takes an old host too. A redirected host's receive timeout is
 *   30 seconds at least, as on the Vita: community servers can be slow.
 * - The User-Agent: the first line of /dev_hdd0/vitals/useragent.txt that isn't empty or a '#'
 *   comment, trimmed, at most 127 printable ASCII characters, takes the place of the library's part
 *   of the default agent ("libhttp/4.9.3-000 (CellOS)" after "PS3Application", or the build's
 *   USER_AGENT). A game that sets its own agent keeps it, as on the Vita.
 *
 * Both are read once per cellHttpInit, on first use, into the pool. A missing file changes nothing.
 * While /dev_hdd0/vitals/flags/redirects.off is there, the list isn't read: no host is redirected */

#include "vh.h"

#include "vitals/host_map.h"
#include "vitals/redirect_list.h"
#include "vitals_paths.h"

#include <string.h>

#define REDIRECTS_PATH VITALS_REDIRECTS
#define USER_AGENT_PATH VITALS_USER_AGENT
#define AGENT_PREFIX "PS3Application "
/* The build sets it (make http USER_AGENT=...); Sony's by default, and for the host run */
#ifndef VH_DEFAULT_SUFFIX
#define VH_DEFAULT_SUFFIX "libhttp/4.9.3-000 (CellOS)"
#endif
#define SUFFIX_MAX 128u

/* ---- the host redirect list ---- */

static VitalsHostMap g_map;
static char *g_names;
static int g_loaded;

typedef struct ListReader {
	char *names;
	size_t used, capacity;
	size_t from[VITALS_HOST_MAP_MAX_RULES], to[VITALS_HOST_MAP_MAX_RULES];
	size_t from_length[VITALS_HOST_MAP_MAX_RULES], to_length[VITALS_HOST_MAP_MAX_RULES];
	size_t count;
	int failed;
} ListReader;

/* Keeps one pair; stops the reading once the list is full or memory runs out */
static int keep_rule(void *context, const VitalsHostRule *rule)
{
	ListReader *reader = context;
	size_t needed = reader->used + rule->from_length + rule->to_length + 2u;
	if (needed > reader->capacity) {
		size_t capacity = needed * 2;
		char *grown = vh_alloc(capacity);
		if (grown == NULL) {
			reader->failed = 1;
			return 1;
		}
		if (reader->names != NULL)
			memcpy(grown, reader->names, reader->used);
		vh_free(reader->names);
		reader->names = grown;
		reader->capacity = capacity;
	}
	reader->from[reader->count] = reader->used;
	reader->from_length[reader->count] = rule->from_length;
	memcpy(reader->names + reader->used, rule->from, rule->from_length);
	reader->used += rule->from_length;
	reader->names[reader->used++] = '\0';
	reader->to[reader->count] = reader->used;
	reader->to_length[reader->count] = rule->to_length;
	memcpy(reader->names + reader->used, rule->to, rule->to_length);
	reader->used += rule->to_length;
	reader->names[reader->used++] = '\0';
	return ++reader->count == VITALS_HOST_MAP_MAX_RULES;
}

static int read_redirects(unsigned int offset, void *buffer, unsigned int size)
{
	return vh_platform_file_read(REDIRECTS_PATH, offset, buffer, size);
}

/* The list, read on first use with the lock held; a missing or unreadable one has no rules */
static void load(void)
{
	/* Before cellHttpInit there's no pool to read it into */
	if (g_loaded || !vh_initialized())
		return;
	g_loaded = 1;
	if (vh_platform_stat(VITALS_REDIRECTS_OFF) == 0) {
		VITALS_LOG("redirects.off is there: no host redirects");
		return;
	}
	ListReader *reader = vh_alloc(sizeof(*reader));
	char *work = vh_alloc(VITALS_REDIRECT_LIST_WORK_SIZE);
	if (reader == NULL || work == NULL) {
		vh_free(reader);
		vh_free(work);
		return;
	}
	memset(reader, 0, sizeof(*reader));
	int result = vitals_redirect_list_read(read_redirects, work, keep_rule, reader);
	vh_free(work);
	if (result < 0)
		VITALS_LOG("redirect list not read: 0x%08x", (unsigned)result);
	if (result >= 0 && !reader->failed && reader->count > 0) {
		for (size_t i = 0; i < reader->count; ++i)
			g_map.rules[i] = (VitalsHostRule){reader->names + reader->from[i], reader->names + reader->to[i],
			                                  reader->from_length[i], reader->to_length[i]};
		g_map.count = reader->count;
		g_names = reader->names;
		VITALS_LOG("redirects: %u", (unsigned)g_map.count);
	} else
		vh_free(reader->names);
	vh_free(reader);
}

const char *vh_redirect_host(const char *host)
{
	if (host == NULL)
		return NULL;
	vh_lock();
	load();
	size_t length = 0;
	while (length <= VITALS_HOST_MAP_MAX_HOST && host[length] != '\0')
		++length;
	const VitalsHostRule *rule = vitals_host_map_find(&g_map, host, length);
	vh_unlock();
	if (rule == NULL)
		return host;
	VITALS_LOG("redirect host %s -> %s", rule->from, rule->to);
	return rule->to;
}

int vh_redirect_is_target(const char *host)
{
	int found = 0;
	vh_lock();
	load();
	for (size_t i = 0; i < g_map.count && !found; ++i)
		found = strlen(host) == g_map.rules[i].to_length && vh_equal_nocase(host, g_map.rules[i].to);
	vh_unlock();
	return found;
}

/* ---- the User-Agent ---- */

static char g_agent[sizeof(AGENT_PREFIX) + SUFFIX_MAX];
static int g_agent_loaded;

/* The first line that holds something, trimmed, after the prefix in g_agent; 0 when there's none */
static int pick_line(const char *text, size_t length)
{
	size_t prefix = sizeof(AGENT_PREFIX) - 1;
	for (size_t at = 0; at < length;) {
		size_t end = at;
		while (end < length && text[end] != '\n')
			++end;
		size_t start = at, stop = end;
		at = end + 1;
		while (start < stop && (text[start] == ' ' || text[start] == '\t'))
			++start;
		while (stop > start && (text[stop - 1] == ' ' || text[stop - 1] == '\t' || text[stop - 1] == '\r'))
			--stop;
		if (start == stop || text[start] == '#')
			continue;
		if (stop - start >= SUFFIX_MAX)
			return 0;
		for (size_t i = start; i < stop; ++i)
			if ((unsigned char)text[i] < 0x20 || (unsigned char)text[i] > 0x7e)
				return 0;
		memcpy(g_agent + prefix, text + start, stop - start);
		g_agent[prefix + stop - start] = '\0';
		return 1;
	}
	return 0;
}

const char *vh_default_user_agent(void)
{
	vh_lock();
	if (!g_agent_loaded) {
		char text[256];
		g_agent_loaded = 1;
		memcpy(g_agent, AGENT_PREFIX, sizeof(AGENT_PREFIX) - 1);
		int read = vh_platform_file_read(USER_AGENT_PATH, 0, text, sizeof(text));
		if (read > 0 && pick_line(text, (size_t)read))
			VITALS_LOG("user agent from useragent.txt: %s", g_agent);
		else {
			if (read > 0)
				VITALS_LOG("useragent.txt ignored: no usable line");
			memcpy(g_agent + sizeof(AGENT_PREFIX) - 1, VH_DEFAULT_SUFFIX, sizeof(VH_DEFAULT_SUFFIX));
		}
	}
	vh_unlock();
	return g_agent;
}

/* At cellHttpEnd: both read again at the next cellHttpInit */
void vh_redirect_end(void)
{
	vh_free(g_names);
	g_names = NULL;
	memset(&g_map, 0, sizeof(g_map));
	g_loaded = 0;
	g_agent_loaded = 0;
}
