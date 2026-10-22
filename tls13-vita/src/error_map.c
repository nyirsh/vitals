#include "vitals/error_map.h"

uint32_t vitals_map_certificate_detail(uint32_t provider_flags) {
    uint32_t detail = 0;

    if ((provider_flags & VITALS_CERT_INTERNAL) != 0) {
        detail |= VITALS_SCE_HTTPS_DETAIL_INTERNAL;
    }
    if ((provider_flags & VITALS_CERT_INVALID) != 0) {
        detail |= VITALS_SCE_HTTPS_DETAIL_INVALID_CERT;
    }
    if ((provider_flags & VITALS_CERT_HOSTNAME) != 0) {
        detail |= VITALS_SCE_HTTPS_DETAIL_CN_CHECK;
    }
    if ((provider_flags & VITALS_CERT_EXPIRED) != 0) {
        detail |= VITALS_SCE_HTTPS_DETAIL_NOT_AFTER;
    }
    if ((provider_flags & VITALS_CERT_FUTURE) != 0) {
        detail |= VITALS_SCE_HTTPS_DETAIL_NOT_BEFORE;
    }
    if ((provider_flags & VITALS_CERT_UNKNOWN_CA) != 0) {
        detail |= VITALS_SCE_HTTPS_DETAIL_UNKNOWN_CA;
    }

    return detail;
}

uint32_t vitals_filter_certificate_flags(uint32_t provider_flags, uint32_t https_options) {
    uint32_t filtered;

    if ((https_options & VITALS_SCE_HTTPS_OPTION_SERVER_VERIFY) == 0) {
        return 0;
    }

    filtered = provider_flags & (VITALS_CERT_INVALID | VITALS_CERT_INTERNAL);
    if ((https_options & VITALS_SCE_HTTPS_OPTION_CN_CHECK) != 0) {
        filtered |= provider_flags & VITALS_CERT_HOSTNAME;
    }
    if ((https_options & VITALS_SCE_HTTPS_OPTION_NOT_AFTER) != 0) {
        filtered |= provider_flags & VITALS_CERT_EXPIRED;
    }
    if ((https_options & VITALS_SCE_HTTPS_OPTION_NOT_BEFORE) != 0) {
        filtered |= provider_flags & VITALS_CERT_FUTURE;
    }
    if ((https_options & VITALS_SCE_HTTPS_OPTION_KNOWN_CA) != 0) {
        filtered |= provider_flags & VITALS_CERT_UNKNOWN_CA;
    }
    return filtered;
}

VitalsMappedError vitals_map_outcome(VitalsOutcome outcome, uint32_t detail) {
    VitalsMappedError mapped = {
        .hook_result = 0,
        .ssl_error = 0,
        .detail = detail,
        .fatal = 0,
    };

    switch (outcome) {
        case VITALS_OUTCOME_OK:
        case VITALS_OUTCOME_CLOSE_NOTIFY:
            break;
        case VITALS_OUTCOME_WANT_READ:
        case VITALS_OUTCOME_WANT_WRITE:
            mapped.hook_result = VITALS_SCE_HTTP_ERROR_EAGAIN;
            break;
        case VITALS_OUTCOME_TIMEOUT:
            mapped.hook_result = VITALS_SCE_HTTP_ERROR_TIMEOUT;
            break;
        case VITALS_OUTCOME_CERTIFICATE:
            mapped.hook_result = VITALS_SCE_HTTP_ERROR_SSL;
            mapped.ssl_error = VITALS_SCE_HTTPS_ERROR_CERT;
            mapped.detail = vitals_map_certificate_detail(detail);
            mapped.fatal = 1;
            break;
        case VITALS_OUTCOME_HANDSHAKE:
            mapped.hook_result = VITALS_SCE_HTTP_ERROR_SSL;
            mapped.ssl_error = VITALS_SCE_HTTPS_ERROR_HANDSHAKE;
            mapped.fatal = 1;
            break;
        case VITALS_OUTCOME_IO:
        case VITALS_OUTCOME_EOF:
            mapped.hook_result = VITALS_SCE_HTTP_ERROR_SSL;
            mapped.ssl_error = VITALS_SCE_HTTPS_ERROR_IO;
            mapped.fatal = 1;
            break;
        case VITALS_OUTCOME_NO_MEMORY:
            mapped.hook_result = VITALS_SCE_HTTP_ERROR_OUT_OF_MEMORY;
            mapped.ssl_error = VITALS_SCE_HTTPS_ERROR_INTERNAL;
            mapped.fatal = 1;
            break;
        case VITALS_OUTCOME_INTERNAL:
        default:
            mapped.hook_result = VITALS_SCE_HTTP_ERROR_SSL;
            mapped.ssl_error = VITALS_SCE_HTTPS_ERROR_INTERNAL;
            mapped.fatal = 1;
            break;
    }

    return mapped;
}
