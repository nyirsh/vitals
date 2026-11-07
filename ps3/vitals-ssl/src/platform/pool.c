#include "pool.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <sys/synchronization.h>

/* libssl's memory: liblv2's heap on the block the app gives cellSslInit, as Sony's libssl, which
 * creates it the same way (in cellSslInit, ps3-dumps/libssl.prx 0x1660: the name, the size, flags
 * 0x80000000 and {8, the block}); Mbed TLS's allocations come from it too */

typedef struct VitalsHeapMemory {
	uint32_t kind; /* 8: the heap is the memory given */
	uint32_t start;
} VitalsHeapMemory;

uint32_t _sys_heap_create_heap(const char *name, uint32_t size, uint32_t flags, const VitalsHeapMemory *memory);
int _sys_heap_delete_heap(uint32_t heap);
void *_sys_heap_malloc(uint32_t heap, uint32_t size);
int _sys_heap_free(uint32_t heap, void *address);
uint32_t _sys_heap_get_total_free_size(uint32_t heap);
int _sys_heap_get_mallinfo(uint32_t heap, uint32_t *mallinfo);

#define VITALS_HEAP_FLAGS 0x80000000u
#define VITALS_HEAP_GIVEN_MEMORY 8u

static uint32_t g_heap;
/* Mbed TLS allocates for every record it protects, on every thread that has a connection (the XMB
 * has many at once): the heap's calls go one at a time, whatever liblv2's own heap does about it */
static sys_lwmutex_t g_heap_lock;
static int g_heap_locked;

static void heap_lock(void)
{
	if (g_heap_locked)
		(void)sys_lwmutex_lock(&g_heap_lock, 0);
}

static void heap_unlock(void)
{
	if (g_heap_locked)
		(void)sys_lwmutex_unlock(&g_heap_lock);
}

/* vitals_pool_use's: the size given, and (debug builds) the least free after an allocation and the
 * allocations refused */
static uint32_t g_size, g_lowest_free, g_refused;

#if VITALS_DEBUG >= 1
void vs_log(const char *format, ...) __attribute__((format(printf, 1, 2)));
#endif

/* NULL before cellSslInit, as there's no heap */
void *vitals_pool_calloc(size_t count, size_t size)
{
	if (g_heap == 0)
		return NULL;
	if (count != 0 && size > UINT32_MAX / count)
		return NULL;
	uint32_t total = (uint32_t)(count * size);
	heap_lock();
	void *memory = _sys_heap_malloc(g_heap, total == 0 ? 1 : total);
#if VITALS_DEBUG >= 1
	uint32_t free_now = _sys_heap_get_total_free_size(g_heap);
#endif
	heap_unlock();
	if (memory != NULL)
		memset(memory, 0, total);
#if VITALS_DEBUG >= 1
	if (memory == NULL) {
		++g_refused;
		vs_log("pool: %u bytes refused, %u of %u free", (unsigned)total, (unsigned)free_now, (unsigned)g_size);
	} else if (free_now < g_lowest_free) {
		g_lowest_free = free_now;
	}
#endif
	return memory;
}

void vitals_pool_free(void *memory)
{
	if (memory != NULL && g_heap != 0) {
		heap_lock();
		(void)_sys_heap_free(g_heap, memory);
		heap_unlock();
	}
}

int vitals_pool_create(void *block, uint32_t size)
{
	const VitalsHeapMemory memory = {VITALS_HEAP_GIVEN_MEMORY, (uint32_t)(uintptr_t)block};
	g_heap = _sys_heap_create_heap("cellSsl_Library", size, VITALS_HEAP_FLAGS, &memory);
	if (g_heap == 0)
		return -1;
	if (!g_heap_locked) {
		sys_lwmutex_attribute_t attr;
		sys_lwmutex_attribute_initialize(attr);
		sys_lwmutex_attribute_name_set(attr.name, "vpool");
		g_heap_locked = sys_lwmutex_create(&g_heap_lock, &attr) == 0;
	}
	g_size = g_lowest_free = size;
	g_refused = 0;
	return 0;
}

int vitals_pool_use(VitalsPoolUse *use)
{
	if (g_heap == 0)
		return -1;
	use->size = g_size;
	heap_lock();
	use->free_now = _sys_heap_get_total_free_size(g_heap);
	heap_unlock();
	use->lowest_free = g_lowest_free;
	use->refused = g_refused;
	return 0;
}

int vitals_pool_stats(uint32_t *free_size, uint32_t mallinfo[10])
{
	if (g_heap == 0)
		return -1;
	heap_lock();
	*free_size = _sys_heap_get_total_free_size(g_heap);
	memset(mallinfo, 0, 10 * sizeof(uint32_t));
	(void)_sys_heap_get_mallinfo(g_heap, mallinfo);
	heap_unlock();
	return 0;
}

void vitals_pool_delete(void)
{
	if (g_heap != 0)
		(void)_sys_heap_delete_heap(g_heap);
	g_heap = 0;
}
