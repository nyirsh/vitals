#ifndef VITALS_MODULE_GATE_H
#define VITALS_MODULE_GATE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct VitalsMaskedSignature {
    const char *name;
    size_t offset;
    const uint8_t *bytes;
    const char *mask;
    size_t length;
} VitalsMaskedSignature;

typedef struct VitalsModuleDescriptor {
    size_t text_size;
    const VitalsMaskedSignature *signatures;
    size_t signature_count;
} VitalsModuleDescriptor;

typedef enum VitalsModuleGateResult {
    VITALS_MODULE_GATE_OK = 0,
    VITALS_MODULE_GATE_INVALID_ARGUMENT = -1,
    VITALS_MODULE_GATE_TEXT_SIZE_MISMATCH = -2,
    VITALS_MODULE_GATE_SIGNATURE_BOUNDS = -3,
    VITALS_MODULE_GATE_SIGNATURE_MASK = -4,
    VITALS_MODULE_GATE_SIGNATURE_MISMATCH = -5
} VitalsModuleGateResult;

int vitals_validate_module_text(
    const uint8_t *text,
    size_t text_size,
    const VitalsModuleDescriptor *descriptor,
    size_t *failed_signature_index,
    size_t *failed_byte_index);

#ifdef __cplusplus
}
#endif

#endif
