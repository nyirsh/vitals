#include "vh.h"

#include "diagnostics.h"
#include "vitals/host_map.h"
#include "vitals/redirect_list.h"

#include <string.h>

/* The host redirect list (ux0:data/vitals/redirects.txt), as the HTTP provider applied it: read
 * through the kernel plugin, since games can't open ux0:data, and applied to the host names
 * connections and URL requests are made with. Read once per sceHttpInit, into the pool's memory
 * but outside its accounting: apps wait for an empty pool, as Sony's is once all is deleted */

static VitalsHostMap g_map;
static char *g_names;
static int g_loaded;

typedef struct ListReader
{
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
        char *grown = vh_platform_alloc(capacity);
        if (grown == NULL) {
            reader->failed = 1;
            return 1;
        }
        if (reader->names != NULL)
            memcpy(grown, reader->names, reader->used);
        vh_platform_free(reader->names);
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

/* The list, read on first use, with the lock held; a missing or unreadable one has no rules */
static void load(void)
{
    /* Before sceHttpInit there is no pool to read it into */
    if (g_loaded || vh_initialized() != 0)
        return;
    g_loaded = 1;
    ListReader *reader = vh_platform_alloc(sizeof(*reader));
    char *work = vh_platform_alloc(VITALS_REDIRECT_LIST_WORK_SIZE);
    if (reader == NULL || work == NULL) {
        vh_platform_free(reader);
        vh_platform_free(work);
        return;
    }
    memset(reader, 0, sizeof(*reader));
    int result = vitals_redirect_list_read(vh_platform_redirects_read, work, keep_rule, reader);
    vh_platform_free(work);
    if (result < 0)
        VITALS_LOG("redirect list not read: rc=%08X", (unsigned int)result);
    if (result >= 0 && !reader->failed && reader->count > 0) {
        for (size_t i = 0; i < reader->count; ++i)
            g_map.rules[i] = (VitalsHostRule){reader->names + reader->from[i], reader->names + reader->to[i],
                                              reader->from_length[i], reader->to_length[i]};
        g_map.count = reader->count;
        g_names = reader->names;
        VITALS_LOG("redirects loaded=%u", (unsigned int)g_map.count);
    } else
        vh_platform_free(reader->names);
    vh_platform_free(reader);
}

void vh_redirect_clear(void)
{
    vh_platform_free(g_names);
    g_names = NULL;
    memset(&g_map, 0, sizeof(g_map));
    g_loaded = 0;
}

/* Whether host is one the list sends others to, with the lock held */
int vh_redirect_is_target(const char *host)
{
    load();
    for (size_t i = 0; i < g_map.count; ++i)
        if (strlen(host) == g_map.rules[i].to_length && vh_equal_nocase(host, g_map.rules[i].to, g_map.rules[i].to_length))
            return 1;
    return 0;
}

const char *vh_redirect_host(const char *host)
{
    if (host == NULL)
        return NULL;
    load();
    size_t length = 0;
    while (length <= VITALS_HOST_MAP_MAX_HOST && host[length] != '\0')
        ++length;
    const VitalsHostRule *rule = vitals_host_map_find(&g_map, host, length);
    if (rule == NULL)
        return host;
    VITALS_LOG("redirect host %s -> %s", rule->from, rule->to);
    return rule->to;
}

char *vh_redirect_url(const char *url)
{
    size_t needed = 0;
    if (url == NULL)
        return NULL;
    load();
    if (vitals_host_map_rewrite_url(&g_map, url, NULL, 0, &needed) != -1)
        return NULL;
    /* The caller's, freed with vh_free */
    char *copy = vh_alloc(needed);
    if (copy == NULL || vitals_host_map_rewrite_url(&g_map, url, copy, needed, &needed) != 1) {
        vh_free(copy);
        return NULL;
    }
    VITALS_LOG("redirect %s -> %s", url, copy);
    return copy;
}
