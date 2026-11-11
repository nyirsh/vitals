#ifndef VITALS_POOL_H
#define VITALS_POOL_H

#include <stddef.h>
#include <stdint.h>

/* The heap on the block cellSslInit is given, which Mbed TLS then allocates from; 0, or -1 when
 * liblv2 refuses it */
int vitals_pool_create(void *block, uint32_t size);
void vitals_pool_delete(void);
/* Mbed TLS's calloc and free (MBEDTLS_PLATFORM_STD_CALLOC and _FREE in psa_user_config.h) */
void *vitals_pool_calloc(size_t count, size_t size);
void vitals_pool_free(void *memory);
/* liblv2's heap statistics, as cellSslGetMemoryInfo gives them: its free size, and its mallinfo
 * (10 words); 0, or -1 without a heap */
int vitals_pool_stats(uint32_t *free_size, uint32_t mallinfo[10]);

/* For the debug log: the pool's size, what's free now, the least that has been free since
 * cellSslInit (in debug builds; the size otherwise), and how many allocations it refused; 0, or -1
 * without a heap */
typedef struct VitalsPoolUse {
	uint32_t size, free_now, lowest_free, refused;
} VitalsPoolUse;
int vitals_pool_use(VitalsPoolUse *use);

#endif
