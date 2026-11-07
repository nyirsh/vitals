/* The pool on a host, for the tests (in place of vitals-ssl/src/platform/pool.c): the system's allocator,
 * with what the pool holds counted, so the tests see a connection's memory given back, and nothing
 * allocated before cellSslInit, as the console's has no heap then */

#include "pool.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct Block {
	size_t size;
	max_align_t align;
} Block;

static int g_created;
static uint32_t g_capacity, g_refused;
/* What's allocated now, and the most it has been */
size_t vs_test_pool_used, vs_test_pool_peak;
/* A size the tests want refused, as liblv2 would refuse it */
uint32_t vs_test_refused_pool;

int vitals_pool_create(void *block, uint32_t size)
{
	(void)block;
	if (size == vs_test_refused_pool)
		return -1;
	g_created = 1;
	g_capacity = size;
	vs_test_pool_used = vs_test_pool_peak = 0;
	g_refused = 0;
	return 0;
}

void vitals_pool_delete(void)
{
	g_created = 0;
}

void *vitals_pool_calloc(size_t count, size_t size)
{
	if (!g_created || (count != 0 && size > (SIZE_MAX - sizeof(Block)) / count))
		return NULL;
	size_t total = count * size;
	if (vs_test_pool_used + total > g_capacity) {
		++g_refused;
		return NULL;
	}
	Block *block = calloc(1, sizeof(Block) + total);
	if (block == NULL)
		return NULL;
	block->size = total;
	vs_test_pool_used += total;
	if (vs_test_pool_used > vs_test_pool_peak)
		vs_test_pool_peak = vs_test_pool_used;
	return block + 1;
}

/* The host's: the pool's size less what's allocated, and mallinfo with its arena, the pool's size */
int vitals_pool_stats(uint32_t *free_size, uint32_t mallinfo[10])
{
	if (!g_created)
		return -1;
	*free_size = g_capacity - (uint32_t)vs_test_pool_used;
	memset(mallinfo, 0, 10 * sizeof(uint32_t));
	mallinfo[0] = g_capacity;
	return 0;
}

int vitals_pool_use(VitalsPoolUse *use)
{
	if (!g_created)
		return -1;
	use->size = g_capacity;
	use->free_now = g_capacity - (uint32_t)vs_test_pool_used;
	use->lowest_free = g_capacity - (uint32_t)vs_test_pool_peak;
	use->refused = g_refused;
	return 0;
}

void vitals_pool_free(void *memory)
{
	if (memory == NULL)
		return;
	Block *block = (Block *)memory - 1;
	vs_test_pool_used -= block->size;
	free(block);
}
