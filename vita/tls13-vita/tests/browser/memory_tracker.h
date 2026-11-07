#ifndef VITALS_TEST_MEMORY_TRACKER_H
#define VITALS_TEST_MEMORY_TRACKER_H

#include <stddef.h>

typedef struct VitalsMemoryStats {
    size_t current_bytes;
    size_t peak_bytes;
    size_t live_allocations;
    size_t peak_allocations;
    size_t total_allocations;
    int overflow;
} VitalsMemoryStats;

void vitals_memory_tracker_reset(void);
VitalsMemoryStats vitals_memory_tracker_snapshot(void);

#endif
