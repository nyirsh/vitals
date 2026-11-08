#include "vitals/registry.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

static unsigned int cleaned;

static void cleanup(void *context, void *payload) {
    VitalsRegistry *registry = context;
    assert(payload != NULL);
    assert(vitals_registry_count(registry) != 0);
    assert(vitals_registry_begin_stop_if_empty(registry) == VITALS_REGISTRY_BUSY);
    ++cleaned;
}

int main(void) {
    VitalsRegistry registry;
    VitalsRegistryHandle handle, second;
    VitalsRegistryOps ops = {.cleanup = cleanup, .context = &registry};
    assert(vitals_registry_init(&registry, &ops) == 0);
    assert(vitals_registry_insert(&registry, 1, (void *)(uintptr_t)1) == 0);
    assert(vitals_registry_acquire(&registry, 1, &handle) == 0);
    assert(vitals_registry_remove(&registry, 1) == 0);
    assert(vitals_registry_acquire(&registry, 1, &second) == VITALS_REGISTRY_BUSY);
    assert(vitals_registry_release(&registry, &handle) == 0);
    assert(cleaned == 1 && vitals_registry_count(&registry) == 0);

    assert(vitals_registry_insert(&registry, 2, (void *)(uintptr_t)2) == 0);
    assert(vitals_registry_acquire(&registry, 2, &handle) == 0);
    registry.slots[handle.index].references = UINT32_MAX;
    assert(vitals_registry_acquire(&registry, 2, &second) == VITALS_REGISTRY_BUSY);
    registry.slots[handle.index].references = 1;
    assert(vitals_registry_release(&registry, &handle) == 0);
    assert(vitals_registry_destroy(&registry) == 0);
    assert(cleaned == 2);
    puts("registry lifetime: retiring ownership, cleanup quiescence, reference overflow PASS");
    return 0;
}
