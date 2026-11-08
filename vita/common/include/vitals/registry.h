#ifndef VITALS_REGISTRY_H
#define VITALS_REGISTRY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef VITALS_REGISTRY_CAPACITY
#define VITALS_REGISTRY_CAPACITY 32
#endif

typedef enum VitalsSlotState {
    VITALS_SLOT_FREE = 0,
    VITALS_SLOT_ACTIVE,
    VITALS_SLOT_REMOVING
} VitalsSlotState;

typedef enum VitalsRegistryResult {
    VITALS_REGISTRY_OK = 0,
    VITALS_REGISTRY_INVALID_ARGUMENT = -1,
    VITALS_REGISTRY_NOT_INITIALIZED = -2,
    VITALS_REGISTRY_DUPLICATE = -3,
    VITALS_REGISTRY_FULL = -4,
    VITALS_REGISTRY_NOT_FOUND = -5,
    VITALS_REGISTRY_STALE_HANDLE = -6,
    VITALS_REGISTRY_BUSY = -7
} VitalsRegistryResult;

typedef void (*VitalsRegistryLockFn)(void *context);
typedef void (*VitalsRegistryCleanupFn)(void *context, void *payload);

typedef struct VitalsRegistryOps {
    VitalsRegistryLockFn lock;
    VitalsRegistryLockFn unlock;
    VitalsRegistryCleanupFn cleanup;
    void *context;
} VitalsRegistryOps;

typedef struct VitalsRegistrySlot {
    uintptr_t key;
    void *payload;
    uint32_t generation;
    uint32_t references;
    VitalsSlotState state;
} VitalsRegistrySlot;

typedef struct VitalsRegistryHandle {
    size_t index;
    uint32_t generation;
    void *payload;
} VitalsRegistryHandle;

typedef struct VitalsRegistry {
    VitalsRegistrySlot slots[VITALS_REGISTRY_CAPACITY];
    VitalsRegistryOps ops;
    size_t cleanup_inflight;
    uint8_t initialized;
    uint8_t stopping;
} VitalsRegistry;

int vitals_registry_init(VitalsRegistry *registry, const VitalsRegistryOps *ops);
int vitals_registry_insert(VitalsRegistry *registry, uintptr_t key, void *payload);
int vitals_registry_replace(VitalsRegistry *registry, uintptr_t key, void *payload);
int vitals_registry_acquire(
    VitalsRegistry *registry,
    uintptr_t key,
    VitalsRegistryHandle *handle);
int vitals_registry_release(VitalsRegistry *registry, VitalsRegistryHandle *handle);
int vitals_registry_remove(VitalsRegistry *registry, uintptr_t key);
int vitals_registry_begin_stop_if_empty(VitalsRegistry *registry);
int vitals_registry_destroy(VitalsRegistry *registry);
size_t vitals_registry_count(VitalsRegistry *registry);

#ifdef __cplusplus
}
#endif

#endif
