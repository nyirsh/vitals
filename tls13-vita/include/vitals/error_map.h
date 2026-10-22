#ifndef VITALS_ERROR_MAP_H
#define VITALS_ERROR_MAP_H

#include <stdint.h>

#include "vitals/sony_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum VitalsOutcome {
    VITALS_OUTCOME_OK = 0,
    VITALS_OUTCOME_WANT_READ,
    VITALS_OUTCOME_WANT_WRITE,
    VITALS_OUTCOME_CLOSE_NOTIFY,
    VITALS_OUTCOME_EOF,
    VITALS_OUTCOME_TIMEOUT,
    VITALS_OUTCOME_CERTIFICATE,
    VITALS_OUTCOME_HANDSHAKE,
    VITALS_OUTCOME_IO,
    VITALS_OUTCOME_NO_MEMORY,
    VITALS_OUTCOME_INTERNAL
} VitalsOutcome;

#define VITALS_CERT_INVALID UINT32_C(0x01)
#define VITALS_CERT_HOSTNAME UINT32_C(0x02)
#define VITALS_CERT_EXPIRED UINT32_C(0x04)
#define VITALS_CERT_FUTURE UINT32_C(0x08)
#define VITALS_CERT_UNKNOWN_CA UINT32_C(0x10)
#define VITALS_CERT_INTERNAL UINT32_C(0x20)

typedef struct VitalsMappedError {
    int32_t hook_result;
    int32_t ssl_error;
    uint32_t detail;
    uint8_t fatal;
} VitalsMappedError;

uint32_t vitals_map_certificate_detail(uint32_t provider_flags);
uint32_t vitals_filter_certificate_flags(uint32_t provider_flags, uint32_t https_options);
VitalsMappedError vitals_map_outcome(VitalsOutcome outcome, uint32_t detail);

#ifdef __cplusplus
}
#endif

#endif
