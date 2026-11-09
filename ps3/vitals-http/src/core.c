/* cellHttpInit and cellHttpEnd, the library's memory and lock, and checking the IDs games pass,
 * as Sony's libhttp (0x19b40): its heap on the block the game gives, named as Sony's
 * ("cellHttp_Library"), and a recursive lock */

#include "vh.h"

#include <cell/http.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#if VITALS_DEBUG >= 1
#include "vitals_log.h"
#endif

static int g_initialized;
static VhClient *g_clients;

int vh_initialized(void)
{
	return g_initialized;
}

void *vh_alloc(size_t size)
{
	return vh_platform_alloc(size == 0 ? 1 : size);
}

void *vh_calloc(size_t size)
{
	void *memory = vh_alloc(size);
	if (memory != NULL)
		memset(memory, 0, size);
	return memory;
}

void vh_free(void *memory)
{
	if (memory != NULL)
		vh_platform_free(memory);
}

char *vh_strdup(const char *text)
{
	size_t length = strlen(text) + 1;
	char *copy = vh_alloc(length);
	if (copy != NULL)
		memcpy(copy, text, length);
	return copy;
}

void vh_lock(void)
{
	vh_platform_lock();
}

void vh_unlock(void)
{
	vh_platform_unlock();
}

int vh_equal_nocase_prefix(const char *text, const char *word)
{
	for (; *word != '\0'; ++text, ++word)
		if (*text == '\0' || (*text | 32) != (*word | 32))
			return 0;
	return 1;
}

int vh_equal_nocase(const char *a, const char *b)
{
	for (;; ++a, ++b) {
		char x = *a >= 'A' && *a <= 'Z' ? (char)(*a + 32) : *a, y = *b >= 'A' && *b <= 'Z' ? (char)(*b + 32) : *b;
		if (x != y)
			return 0;
		if (x == '\0')
			return 1;
	}
}

/* An ID is a pointer: readable, with its own address and the kind's magic in it, as Sony's checks
 * (a self-pointer at +128 for a client) */
VhClient *vh_client(void *id)
{
	VhClient *client = id;
	if (client == NULL || !vh_platform_readable(client) || client->self != client || client->magic != VH_CLIENT_MAGIC)
		return NULL;
	return client;
}

VhTransaction *vh_transaction(void *id)
{
	VhTransaction *transaction = id;
	if (transaction == NULL || !vh_platform_readable(transaction) || transaction->self != transaction ||
	    transaction->magic != VH_TRANS_MAGIC)
		return NULL;
	return transaction;
}

void vh_clients_add(VhClient *client)
{
	client->next = g_clients;
	g_clients = client;
}

void vh_clients_remove(VhClient *client)
{
	for (VhClient **at = &g_clients; *at != NULL; at = &(*at)->next)
		if (*at == client) {
			*at = client->next;
			return;
		}
}

/* 0x80710001 a second time, 0x80710004 without a pool or a size, 0x80710003 when the heap can't
 * be made there */
int cellHttpInit(void *pool, size_t size)
{
	VITALS_LOG("cellHttpInit pool %p of %u bytes%s", pool, (unsigned)size, g_initialized ? ": already" : "");
	if (g_initialized)
		return VH_ERROR_ALREADY_INITIALIZED;
	if (pool == NULL || size == 0)
		return VH_ERROR_NO_BUFFER;
	if (vh_platform_lock_create() != 0)
		return VH_ERROR_NO_MEMORY;
	if (vh_platform_pool_create(pool, size) != 0) {
		vh_platform_lock_destroy();
		VITALS_LOG("cellHttpInit: no heap on the pool");
		return VH_ERROR_NO_MEMORY;
	}
	g_clients = NULL;
	g_initialized = 1;
	return 0;
}

/* Every client the game didn't destroy, with its connections, then the heap; 0x80710002 before
 * cellHttpInit */
int cellHttpEnd(void)
{
	VITALS_LOG("cellHttpEnd%s", g_initialized ? "" : ": not initialized");
	if (!g_initialized)
		return VH_ERROR_NOT_INITIALIZED;
	vh_lock();
	while (g_clients != NULL) {
		VhClient *client = g_clients;
		g_clients = client->next;
		vh_client_free(client);
	}
	vh_proxy_end();
	vh_cache_end();
	vh_redirect_end();
	g_initialized = 0;
	vh_unlock();
	vh_platform_pool_delete();
	vh_platform_lock_destroy();
	return 0;
}

/* The heap's free size; *first the first word *info had, as Sony's reads it before filling it;
 * the heap's mallinfo, 10 words. Any may be NULL */
int cellHttpGetMemoryInfo(uint32_t *free_size, uint32_t *first, uint32_t *info)
{
	VITALS_VERBOSE("cellHttpGetMemoryInfo");
	uint32_t numbers[10];
	vh_platform_pool_mallinfo(numbers);
	if (free_size != NULL)
		*free_size = vh_platform_pool_free_size();
	if (first != NULL && info != NULL)
		*first = info[0];
	if (info != NULL)
		memcpy(info, numbers, sizeof(numbers));
	return 0;
}

/* ---- the debug log ---- */

static int lower_ascii(int c)
{
	return c >= 'A' && c <= 'Z' ? c + 32 : c;
}

static int has_word(const char *text, const char *word)
{
	for (; *text != '\0'; ++text) {
		size_t i = 0;
		while (word[i] != '\0' && lower_ascii((unsigned char)text[i]) == word[i])
			++i;
		if (word[i] == '\0')
			return 1;
	}
	return 0;
}

const char *vh_log_header(const char *name, const char *value, char *buffer, size_t size)
{
	static const char *const secrets[] = {"cookie", "auth", "token", "session", "ticket", "key", "secret",
	                                      "password", "passphrase", "signature"};
	if (value == NULL)
		return "-";
	for (unsigned i = 0; name != NULL && i < sizeof(secrets) / sizeof(secrets[0]); ++i)
		if (has_word(name, secrets[i])) {
			snprintf(buffer, size, "(%u bytes)", (unsigned)strlen(value));
			return buffer;
		}
	return value;
}

const char *vh_log_path(const char *path, char *buffer, size_t size)
{
	if (path == NULL)
		return "-";
	const char *query = strchr(path, '?');
	if (query == NULL)
		return path;
	size_t keep = (size_t)(query - path);
	if (keep > size / 2)
		keep = size / 2;
	memcpy(buffer, path, keep);
	snprintf(buffer + keep, size - keep, "?(%u bytes)", (unsigned)strlen(query + 1));
	return buffer;
}

#if VITALS_DEBUG >= 1
void vh_log(const char *format, ...)
{
	char line[256];
	va_list arguments;
	va_start(arguments, format);
	vsnprintf(line, sizeof(line), format, arguments);
	va_end(arguments);
	vitals_log("vitals-http", line);
}
#endif
