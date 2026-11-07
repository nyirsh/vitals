#include "vitals/registry.h"

#include <stddef.h>
#include <string.h>

static void registry_lock(VitalsRegistry *registry) {
    if (registry->ops.lock != NULL) {
        registry->ops.lock(registry->ops.context);
    }
}

static void registry_unlock(VitalsRegistry *registry) {
    if (registry->ops.unlock != NULL) {
        registry->ops.unlock(registry->ops.context);
    }
}

static void cleanup_payload(VitalsRegistry *registry, void *payload) {
    if (payload == NULL) {
        return;
    }
    if (registry->ops.cleanup != NULL) {
        registry->ops.cleanup(registry->ops.context, payload);
    }
    registry_lock(registry);
    --registry->cleanup_inflight;
    registry_unlock(registry);
}

static void reset_slot(VitalsRegistrySlot *slot) {
    slot->key = 0;
    slot->payload = NULL;
    slot->references = 0;
    slot->state = VITALS_SLOT_FREE;
}

static uint32_t next_generation(uint32_t generation) {
    ++generation;
    if (generation == 0) {
        generation = 1;
    }
    return generation;
}

int vitals_registry_init(VitalsRegistry *registry, const VitalsRegistryOps *ops) {
    if (registry == NULL || ops == NULL ||
        (ops->lock == NULL) != (ops->unlock == NULL)) {
        return VITALS_REGISTRY_INVALID_ARGUMENT;
    }

    memset(registry, 0, sizeof(*registry));
    registry->ops = *ops;
    registry->initialized = 1;
    return VITALS_REGISTRY_OK;
}

int vitals_registry_insert(VitalsRegistry *registry, uintptr_t key, void *payload) {
    size_t index;
    size_t free_index = VITALS_REGISTRY_CAPACITY;

    if (registry == NULL || key == 0 || payload == NULL) {
        return VITALS_REGISTRY_INVALID_ARGUMENT;
    }
    if (!registry->initialized) {
        return VITALS_REGISTRY_NOT_INITIALIZED;
    }

    registry_lock(registry);
    if (registry->stopping) {
        registry_unlock(registry);
        return VITALS_REGISTRY_BUSY;
    }

    for (index = 0; index < VITALS_REGISTRY_CAPACITY; ++index) {
        VitalsRegistrySlot *slot = &registry->slots[index];

        if (slot->state != VITALS_SLOT_FREE && slot->key == key) {
            registry_unlock(registry);
            return VITALS_REGISTRY_DUPLICATE;
        }
        if (slot->state == VITALS_SLOT_FREE && free_index == VITALS_REGISTRY_CAPACITY) {
            free_index = index;
        }
    }

    if (free_index == VITALS_REGISTRY_CAPACITY) {
        registry_unlock(registry);
        return VITALS_REGISTRY_FULL;
    }

    registry->slots[free_index].key = key;
    registry->slots[free_index].payload = payload;
    registry->slots[free_index].generation =
        next_generation(registry->slots[free_index].generation);
    registry->slots[free_index].references = 0;
    registry->slots[free_index].state = VITALS_SLOT_ACTIVE;
    registry_unlock(registry);
    return VITALS_REGISTRY_OK;
}

int vitals_registry_replace(VitalsRegistry *registry, uintptr_t key, void *payload) {
    size_t index;
    void *old_payload = NULL;

    if (registry == NULL || key == 0 || payload == NULL) {
        return VITALS_REGISTRY_INVALID_ARGUMENT;
    }
    if (!registry->initialized) {
        return VITALS_REGISTRY_NOT_INITIALIZED;
    }

    registry_lock(registry);
    if (registry->stopping) {
        registry_unlock(registry);
        return VITALS_REGISTRY_BUSY;
    }

    for (index = 0; index < VITALS_REGISTRY_CAPACITY; ++index) {
        VitalsRegistrySlot *slot = &registry->slots[index];

        if (slot->key != key || slot->state == VITALS_SLOT_FREE) {
            continue;
        }
        if (slot->state != VITALS_SLOT_ACTIVE || slot->references != 0) {
            registry_unlock(registry);
            return VITALS_REGISTRY_BUSY;
        }

        old_payload = slot->payload;
        ++registry->cleanup_inflight;
        slot->payload = payload;
        slot->generation = next_generation(slot->generation);
        registry_unlock(registry);
        cleanup_payload(registry, old_payload);
        return VITALS_REGISTRY_OK;
    }

    registry_unlock(registry);
    return VITALS_REGISTRY_NOT_FOUND;
}

int vitals_registry_acquire(
    VitalsRegistry *registry,
    uintptr_t key,
    VitalsRegistryHandle *handle) {
    size_t index;

    if (registry == NULL || handle == NULL || key == 0) {
        return VITALS_REGISTRY_INVALID_ARGUMENT;
    }
    if (!registry->initialized) {
        return VITALS_REGISTRY_NOT_INITIALIZED;
    }

    handle->index = VITALS_REGISTRY_CAPACITY;
    handle->generation = 0;
    handle->payload = NULL;

    registry_lock(registry);
    for (index = 0; index < VITALS_REGISTRY_CAPACITY; ++index) {
        VitalsRegistrySlot *slot = &registry->slots[index];

        if (slot->state != VITALS_SLOT_FREE && slot->key == key) {
            if (slot->state != VITALS_SLOT_ACTIVE || slot->references == UINT32_MAX) {
                registry_unlock(registry);
                return VITALS_REGISTRY_BUSY;
            }
            ++slot->references;
            handle->index = index;
            handle->generation = slot->generation;
            handle->payload = slot->payload;
            registry_unlock(registry);
            return VITALS_REGISTRY_OK;
        }
    }
    registry_unlock(registry);
    return VITALS_REGISTRY_NOT_FOUND;
}

int vitals_registry_release(VitalsRegistry *registry, VitalsRegistryHandle *handle) {
    VitalsRegistrySlot *slot;
    void *payload = NULL;

    if (registry == NULL || handle == NULL ||
        handle->index >= VITALS_REGISTRY_CAPACITY || handle->generation == 0) {
        return VITALS_REGISTRY_INVALID_ARGUMENT;
    }
    if (!registry->initialized) {
        return VITALS_REGISTRY_NOT_INITIALIZED;
    }

    registry_lock(registry);
    slot = &registry->slots[handle->index];
    if (slot->generation != handle->generation || slot->references == 0 ||
        (slot->state != VITALS_SLOT_ACTIVE && slot->state != VITALS_SLOT_REMOVING)) {
        registry_unlock(registry);
        return VITALS_REGISTRY_STALE_HANDLE;
    }

    --slot->references;
    if (slot->state == VITALS_SLOT_REMOVING && slot->references == 0) {
        payload = slot->payload;
        ++registry->cleanup_inflight;
        reset_slot(slot);
    }
    registry_unlock(registry);

    handle->index = VITALS_REGISTRY_CAPACITY;
    handle->generation = 0;
    handle->payload = NULL;
    cleanup_payload(registry, payload);
    return VITALS_REGISTRY_OK;
}

int vitals_registry_remove(VitalsRegistry *registry, uintptr_t key) {
    size_t index;
    void *payload = NULL;

    if (registry == NULL || key == 0) {
        return VITALS_REGISTRY_INVALID_ARGUMENT;
    }
    if (!registry->initialized) {
        return VITALS_REGISTRY_NOT_INITIALIZED;
    }

    registry_lock(registry);
    for (index = 0; index < VITALS_REGISTRY_CAPACITY; ++index) {
        VitalsRegistrySlot *slot = &registry->slots[index];

        if (slot->state != VITALS_SLOT_FREE && slot->key == key) {
            if (slot->state == VITALS_SLOT_REMOVING) {
                registry_unlock(registry);
                return VITALS_REGISTRY_OK;
            }
            slot->state = VITALS_SLOT_REMOVING;
            if (slot->references == 0) {
                payload = slot->payload;
                ++registry->cleanup_inflight;
                reset_slot(slot);
            }
            registry_unlock(registry);
            cleanup_payload(registry, payload);
            return VITALS_REGISTRY_OK;
        }
    }
    registry_unlock(registry);
    return VITALS_REGISTRY_NOT_FOUND;
}

int vitals_registry_begin_stop_if_empty(VitalsRegistry *registry) {
    size_t index;

    if (registry == NULL) {
        return VITALS_REGISTRY_INVALID_ARGUMENT;
    }
    if (!registry->initialized) {
        return VITALS_REGISTRY_NOT_INITIALIZED;
    }

    registry_lock(registry);
    if (registry->stopping || registry->cleanup_inflight != 0) {
        registry_unlock(registry);
        return VITALS_REGISTRY_BUSY;
    }
    for (index = 0; index < VITALS_REGISTRY_CAPACITY; ++index) {
        if (registry->slots[index].state != VITALS_SLOT_FREE) {
            registry_unlock(registry);
            return VITALS_REGISTRY_BUSY;
        }
    }
    registry->stopping = 1;
    registry_unlock(registry);
    return VITALS_REGISTRY_OK;
}

int vitals_registry_destroy(VitalsRegistry *registry) {
    void *payloads[VITALS_REGISTRY_CAPACITY];
    size_t payload_count = 0;
    size_t index;
    int result = VITALS_REGISTRY_OK;

    if (registry == NULL) {
        return VITALS_REGISTRY_INVALID_ARGUMENT;
    }
    if (!registry->initialized) {
        return VITALS_REGISTRY_NOT_INITIALIZED;
    }

    registry_lock(registry);
    registry->stopping = 1;
    for (index = 0; index < VITALS_REGISTRY_CAPACITY; ++index) {
        VitalsRegistrySlot *slot = &registry->slots[index];

        if (slot->state == VITALS_SLOT_FREE) {
            continue;
        }
        slot->state = VITALS_SLOT_REMOVING;
        if (slot->references == 0) {
            payloads[payload_count++] = slot->payload;
            ++registry->cleanup_inflight;
            reset_slot(slot);
        } else {
            result = VITALS_REGISTRY_BUSY;
        }
    }
    registry_unlock(registry);

    for (index = 0; index < payload_count; ++index) {
        cleanup_payload(registry, payloads[index]);
    }
    registry_lock(registry);
    result = registry->cleanup_inflight == 0 ? VITALS_REGISTRY_OK : VITALS_REGISTRY_BUSY;
    for (index = 0; index < VITALS_REGISTRY_CAPACITY; ++index) {
        if (registry->slots[index].state != VITALS_SLOT_FREE) {
            result = VITALS_REGISTRY_BUSY;
        }
    }
    if (result == VITALS_REGISTRY_OK) {
        registry->initialized = 0;
    }
    registry_unlock(registry);
    return result;
}

size_t vitals_registry_count(VitalsRegistry *registry) {
    size_t index;
    size_t count = 0;

    if (registry == NULL || !registry->initialized) {
        return 0;
    }

    registry_lock(registry);
    count = registry->cleanup_inflight;
    for (index = 0; index < VITALS_REGISTRY_CAPACITY; ++index) {
        if (registry->slots[index].state != VITALS_SLOT_FREE) {
            ++count;
        }
    }
    registry_unlock(registry);
    return count;
}
