#ifndef VITALS_CERT_POLICY_H
#define VITALS_CERT_POLICY_H

#include <stddef.h>
#include <stdint.h>

typedef struct VitalsCertPolicy {
    int (*is_game_program)(void);
    int (*is_system_callback)(void *address);
    uint32_t (*compatibility_version)(void);
    int (*system_parameter)(int selector, int *value);
} VitalsCertPolicy;

int vitals_cert_callback_accepted(int result, uint32_t verification_detail,
                                uintptr_t callback, const VitalsCertPolicy *policy);
int vitals_cert_policy_bind(VitalsCertPolicy *policy, const void *text, size_t text_size);

#endif
