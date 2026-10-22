#ifndef VITALS_PROVIDER_H
#define VITALS_PROVIDER_H

#include <stddef.h>
#include <stdint.h>

#include <taihen.h>
#include <psp2/types.h>

#include <mbedtls/x509_crt.h>
#include "ca_index.h"

#include "vitals/module_gate.h"
#include "vitals/cert_policy.h"
#include "vitals/registry.h"
#include "vitals/sony_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VITALS_HOOK_COUNT 6

typedef enum VitalsProviderState {
    VITALS_PROVIDER_STOPPED = 0,
    VITALS_PROVIDER_STARTING,
    VITALS_PROVIDER_ACTIVE,
    VITALS_PROVIDER_STOPPING
} VitalsProviderState;

typedef struct VitalsProviderGlobal {
    VitalsProviderState state;
    int32_t libhttp_modid;
    uintptr_t text_address;
    size_t text_size;
    uintptr_t data_address;
    size_t data_size;
    uintptr_t global_https_options_address;
    int hook_ids[VITALS_HOOK_COUNT];
    tai_hook_ref_t hook_refs[VITALS_HOOK_COUNT];
    VitalsRegistry registry;
    VitalsCertPolicy cert_policy;
    SceUID registry_mutex;
    VitalsCaIndex ca_index;
    uint8_t registry_mutex_initialized;
    uint8_t ca_index_initialized;
    uint8_t crypto_initialized;
} VitalsProviderGlobal;

extern VitalsProviderGlobal g_vitals_http;

int vitals_http_validate_start_args(SceSize argc, const void *args, VitalsStartArgs *out);
int vitals_http_validate_module(
    int32_t modid,
    uintptr_t *text_address,
    size_t *text_size,
    uintptr_t *data_address,
    size_t *data_size);
int vitals_http_install_hooks(void);
void vitals_http_release_hooks(void);
int vitals_trust_store_init(void);
void vitals_trust_store_free(void);

#ifdef __cplusplus
}
#endif

#endif
