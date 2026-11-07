/* Header lists (a client's, a request's, a response's) and how Sony's getters hand them out: copied
 * into the game's pool, *required what that takes. The probe's numbers: one header is its name and
 * value with a NUL each ("X-Probe" and "one", 12); all of them are an array of CellHttpHeader, then
 * the strings (three headers, 24 + 12 + 22 + 18 = 76) */

#include "vh.h"

#include <cell/http.h>
#include <string.h>

static void free_item(VhHeader *item)
{
	vh_free(item->name);
	vh_free(item->value);
}

int vh_headers_insert(VhHeaders *headers, unsigned at, const char *name, const char *value)
{
	if (name == NULL || value == NULL)
		return VH_ERROR_NO_BUFFER;
	if (headers->count == headers->capacity) {
		unsigned capacity = headers->capacity ? headers->capacity * 2 : 8;
		VhHeader *items = vh_alloc(capacity * sizeof(*items));
		if (items == NULL)
			return VH_ERROR_NO_MEMORY;
		if (headers->count != 0)
			memcpy(items, headers->items, headers->count * sizeof(*items));
		vh_free(headers->items);
		headers->items = items;
		headers->capacity = capacity;
	}
	VhHeader item = {vh_strdup(name), vh_strdup(value)};
	if (item.name == NULL || item.value == NULL) {
		free_item(&item);
		return VH_ERROR_NO_MEMORY;
	}
	if (at > headers->count)
		at = headers->count;
	memmove(headers->items + at + 1, headers->items + at, (headers->count - at) * sizeof(*headers->items));
	headers->items[at] = item;
	++headers->count;
	return 0;
}

int vh_headers_add(VhHeaders *headers, const char *name, const char *value)
{
	return vh_headers_insert(headers, headers->count, name, value);
}

int vh_headers_find(const VhHeaders *headers, const char *name)
{
	for (unsigned i = 0; i < headers->count; ++i)
		if (vh_equal_nocase(headers->items[i].name, name))
			return (int)i;
	return -1;
}

/* The first one with the name gets the value; without one, it's added */
int vh_headers_set(VhHeaders *headers, const char *name, const char *value)
{
	if (name == NULL || value == NULL)
		return VH_ERROR_NO_BUFFER;
	int at = vh_headers_find(headers, name);
	if (at < 0)
		return vh_headers_add(headers, name, value);
	char *copy = vh_strdup(value);
	if (copy == NULL)
		return VH_ERROR_NO_MEMORY;
	vh_free(headers->items[at].value);
	headers->items[at].value = copy;
	return 0;
}

/* Every one with the name; 0x80710016 without one */
int vh_headers_delete(VhHeaders *headers, const char *name)
{
	if (name == NULL)
		return VH_ERROR_NO_BUFFER;
	int found = 0;
	for (unsigned i = 0; i < headers->count;) {
		if (vh_equal_nocase(headers->items[i].name, name)) {
			free_item(&headers->items[i]);
			memmove(headers->items + i, headers->items + i + 1, (headers->count - i - 1) * sizeof(*headers->items));
			--headers->count;
			found = 1;
		} else
			++i;
	}
	return found ? 0 : VH_ERROR_NO_HEADER;
}

void vh_headers_clear(VhHeaders *headers)
{
	for (unsigned i = 0; i < headers->count; ++i)
		free_item(&headers->items[i]);
	vh_free(headers->items);
	headers->items = NULL;
	headers->count = headers->capacity = 0;
}

int vh_headers_get(const VhHeaders *headers, void *out, const char *name, void *pool, size_t size, size_t *required)
{
	CellHttpHeader *header = out;
	/* As get_all: without a pool only the size is asked for, and the header may be NULL */
	if (name == NULL || (header == NULL && pool != NULL))
		return VH_ERROR_NO_BUFFER;
	int at = vh_headers_find(headers, name);
	if (at < 0)
		return VH_ERROR_NO_HEADER;
	const VhHeader *item = &headers->items[at];
	size_t name_size = strlen(item->name) + 1, value_size = strlen(item->value) + 1;
	if (required != NULL)
		*required = name_size + value_size;
	if (pool == NULL)
		return 0;
	if (size < name_size + value_size)
		return VH_ERROR_INSUFFICIENT;
	char *text = pool;
	memcpy(text, item->name, name_size);
	memcpy(text + name_size, item->value, value_size);
	header->name = text;
	header->value = text + name_size;
	return 0;
}

/* Without a pool, only the count and the size are asked for, as the XMB's profile request does
 * (GetAllHeaders(t, NULL, &items, NULL, 0, &required), then again with a pool of that size): the
 * list may be NULL then, and Sony's answers 0. With a pool, the list and the count are needed */
int vh_headers_get_all(const VhHeaders *headers, void *out, size_t *items, void *pool, size_t size, size_t *required)
{
	CellHttpHeaderPtr *list = out;
	if (pool != NULL && (list == NULL || items == NULL))
		return VH_ERROR_NO_BUFFER;
	size_t need = headers->count * sizeof(CellHttpHeader);
	for (unsigned i = 0; i < headers->count; ++i)
		need += strlen(headers->items[i].name) + 1 + strlen(headers->items[i].value) + 1;
	if (required != NULL)
		*required = need;
	if (items != NULL)
		*items = headers->count;
	if (pool == NULL)
		return 0;
	if (size < need)
		return VH_ERROR_INSUFFICIENT;
	CellHttpHeader *array = pool;
	char *text = (char *)(array + headers->count);
	for (unsigned i = 0; i < headers->count; ++i) {
		size_t name_size = strlen(headers->items[i].name) + 1, value_size = strlen(headers->items[i].value) + 1;
		memcpy(text, headers->items[i].name, name_size);
		array[i].name = text;
		text += name_size;
		memcpy(text, headers->items[i].value, value_size);
		array[i].value = text;
		text += value_size;
	}
	*list = headers->count ? array : NULL;
	return 0;
}
