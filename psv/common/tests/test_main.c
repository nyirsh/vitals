#include "vitals/error_map.h"
#include "vitals/module_gate.h"
#include "vitals/path.h"
#include "vitals/registry.h"
#include "vitals/sony_abi.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned int g_assertions;
static unsigned int g_failures;

#define CHECK(expression)                                                                 \
    do {                                                                                  \
        ++g_assertions;                                                                   \
        if (!(expression)) {                                                              \
            ++g_failures;                                                                 \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #expression); \
        }                                                                                 \
    } while (0)

#define CHECK_EQ_INT(expected, actual)                                                     \
    do {                                                                                  \
        const int64_t check_expected = (int64_t)(expected);                              \
        const int64_t check_actual = (int64_t)(actual);                                  \
        ++g_assertions;                                                                   \
        if (check_expected != check_actual) {                                             \
            ++g_failures;                                                                 \
            fprintf(                                                                      \
                stderr,                                                                   \
                "%s:%d: expected %" PRId64 ", got %" PRId64 "\n",                    \
                __FILE__,                                                                 \
                __LINE__,                                                                 \
                check_expected,                                                           \
                check_actual);                                                            \
        }                                                                                 \
    } while (0)

static void test_path_helpers(void) {
    CHECK(vitals_path_equals("vs0:sys/external/libhttp.suprx", "vs0:sys/external/libhttp.suprx", 64));
    CHECK(!vitals_path_equals("vs0:sys/external/libhttp.suprx.old", "vs0:sys/external/libhttp.suprx", 64));
    CHECK(vitals_path_has_suffix("vs0:/data/external/webcore/ScePsp2Compat.suprx", "webcore/ScePsp2Compat.suprx", 64));
    CHECK(!vitals_path_has_suffix("x", "webcore/ScePsp2Compat.suprx", 64));
    CHECK(!vitals_path_has_suffix(NULL, "x", 64));
    CHECK(!vitals_path_has_suffix("unterminated", "ated", 4));
}

static void test_sony_abi(void) {
    uint8_t request[0x140] = {0};
    uint8_t connection[0x168] = {0};
    uint32_t value;

    value = UINT32_C(0x12345678);
    memcpy(request + VITALS_REQUEST_FALLBACK_CONNECTION_OFFSET, &value, sizeof(value));
    CHECK_EQ_INT(UINT32_C(0x12345678), vitals_resolve_connection_address(request));

    value = UINT32_C(0x87654321);
    memcpy(request + VITALS_REQUEST_PRIMARY_CONNECTION_OFFSET, &value, sizeof(value));
    CHECK_EQ_INT(UINT32_C(0x87654321), vitals_resolve_connection_address(request));

    CHECK_EQ_INT(0, vitals_request_is_nonblocking(request));
    value = UINT32_C(1);
    memcpy(request + VITALS_REQUEST_NONBLOCK_OFFSET, &value, sizeof(value));
    CHECK_EQ_INT(1, vitals_request_is_nonblocking(request));

    value = UINT32_C(42);
    memcpy(connection + VITALS_CONNECTION_SOCKET_OFFSET, &value, sizeof(value));
    CHECK_EQ_INT(42, vitals_connection_socket(connection));

    value = UINT32_C(0x10203040);
    memcpy(connection + VITALS_CONNECTION_HOSTNAME_OFFSET, &value, sizeof(value));
    CHECK_EQ_INT(UINT32_C(0x10203040), vitals_connection_hostname_address(connection));

    value = UINT32_C(0x11223344);
    memcpy(connection + VITALS_CONNECTION_CALLBACK_OFFSET, &value, sizeof(value));
    CHECK_EQ_INT(UINT32_C(0x11223344), vitals_connection_callback_address(connection));

    value = UINT32_C(0x55667788);
    memcpy(connection + VITALS_CONNECTION_CALLBACK_ARG_OFFSET, &value, sizeof(value));
    CHECK_EQ_INT(UINT32_C(0x55667788), vitals_connection_callback_arg_address(connection));

    value = UINT32_C(3);
    memcpy(connection + VITALS_CONNECTION_HTTPS_OPTIONS_OFFSET, &value, sizeof(value));
    CHECK_EQ_INT(
        UINT32_C(0x65),
        vitals_connection_effective_https_options(connection, UINT32_C(0x65)));

    value = UINT32_C(0x80000025);
    memcpy(connection + VITALS_CONNECTION_HTTPS_OPTIONS_OFFSET, &value, sizeof(value));
    CHECK_EQ_INT(
        UINT32_C(0x25),
        vitals_connection_effective_https_options(connection, UINT32_C(0x65)));

    vitals_store_ssl_error(
        connection,
        VITALS_SCE_HTTPS_ERROR_HANDSHAKE,
        VITALS_SCE_HTTPS_DETAIL_INTERNAL);
    CHECK_EQ_INT(
        (uint32_t)VITALS_SCE_HTTPS_ERROR_HANDSHAKE,
        vitals_read_u32(connection, VITALS_CONNECTION_SSL_ERROR_OFFSET));
    CHECK_EQ_INT(
        VITALS_SCE_HTTPS_DETAIL_INTERNAL,
        vitals_read_u32(connection, VITALS_CONNECTION_SSL_DETAIL_OFFSET));
}

static void test_error_map(void) {
    VitalsMappedError mapped;
    uint32_t provider_flags =
        VITALS_CERT_INVALID |
        VITALS_CERT_HOSTNAME |
        VITALS_CERT_EXPIRED |
        VITALS_CERT_FUTURE |
        VITALS_CERT_UNKNOWN_CA |
        VITALS_CERT_INTERNAL;

    CHECK_EQ_INT(
        VITALS_SCE_HTTPS_DETAIL_INTERNAL |
            VITALS_SCE_HTTPS_DETAIL_INVALID_CERT |
            VITALS_SCE_HTTPS_DETAIL_CN_CHECK |
            VITALS_SCE_HTTPS_DETAIL_NOT_AFTER |
            VITALS_SCE_HTTPS_DETAIL_NOT_BEFORE |
            VITALS_SCE_HTTPS_DETAIL_UNKNOWN_CA,
        vitals_map_certificate_detail(provider_flags));

    CHECK_EQ_INT(
        0,
        vitals_filter_certificate_flags(provider_flags, 0));
    CHECK_EQ_INT(
        VITALS_CERT_INVALID | VITALS_CERT_INTERNAL,
        vitals_filter_certificate_flags(
            provider_flags,
            VITALS_SCE_HTTPS_OPTION_SERVER_VERIFY));
    CHECK_EQ_INT(
        VITALS_CERT_INVALID |
            VITALS_CERT_INTERNAL |
            VITALS_CERT_HOSTNAME |
            VITALS_CERT_EXPIRED |
            VITALS_CERT_FUTURE |
            VITALS_CERT_UNKNOWN_CA,
        vitals_filter_certificate_flags(
            provider_flags,
            VITALS_SCE_HTTPS_OPTION_SERVER_VERIFY |
                VITALS_SCE_HTTPS_OPTION_CN_CHECK |
                VITALS_SCE_HTTPS_OPTION_NOT_AFTER |
                VITALS_SCE_HTTPS_OPTION_NOT_BEFORE |
                VITALS_SCE_HTTPS_OPTION_KNOWN_CA));

    mapped = vitals_map_outcome(VITALS_OUTCOME_WANT_READ, UINT32_C(0xAA));
    CHECK_EQ_INT(VITALS_SCE_HTTP_ERROR_EAGAIN, mapped.hook_result);
    CHECK_EQ_INT(0, mapped.ssl_error);
    CHECK_EQ_INT(0, mapped.fatal);

    mapped = vitals_map_outcome(VITALS_OUTCOME_WANT_WRITE, 0);
    CHECK_EQ_INT(VITALS_SCE_HTTP_ERROR_EAGAIN, mapped.hook_result);
    CHECK_EQ_INT(0, mapped.fatal);

    mapped = vitals_map_outcome(VITALS_OUTCOME_CLOSE_NOTIFY, 0);
    CHECK_EQ_INT(0, mapped.hook_result);
    CHECK_EQ_INT(0, mapped.fatal);

    mapped = vitals_map_outcome(VITALS_OUTCOME_CERTIFICATE, provider_flags);
    CHECK_EQ_INT(VITALS_SCE_HTTP_ERROR_SSL, mapped.hook_result);
    CHECK_EQ_INT(VITALS_SCE_HTTPS_ERROR_CERT, mapped.ssl_error);
    CHECK_EQ_INT(UINT32_C(0x3F), mapped.detail);
    CHECK_EQ_INT(1, mapped.fatal);

    mapped = vitals_map_outcome(VITALS_OUTCOME_HANDSHAKE, UINT32_C(0x1234));
    CHECK_EQ_INT(VITALS_SCE_HTTP_ERROR_SSL, mapped.hook_result);
    CHECK_EQ_INT(VITALS_SCE_HTTPS_ERROR_HANDSHAKE, mapped.ssl_error);
    CHECK_EQ_INT(UINT32_C(0x1234), mapped.detail);

    mapped = vitals_map_outcome(VITALS_OUTCOME_IO, UINT32_C(0x55));
    CHECK_EQ_INT(VITALS_SCE_HTTP_ERROR_SSL, mapped.hook_result);
    CHECK_EQ_INT(VITALS_SCE_HTTPS_ERROR_IO, mapped.ssl_error);

    mapped = vitals_map_outcome(VITALS_OUTCOME_EOF, 0);
    CHECK_EQ_INT(VITALS_SCE_HTTP_ERROR_SSL, mapped.hook_result);
    CHECK_EQ_INT(VITALS_SCE_HTTPS_ERROR_IO, mapped.ssl_error);

    mapped = vitals_map_outcome(VITALS_OUTCOME_TIMEOUT, 0);
    CHECK_EQ_INT(VITALS_SCE_HTTP_ERROR_TIMEOUT, mapped.hook_result);
    CHECK_EQ_INT(0, mapped.ssl_error);
    CHECK_EQ_INT(0, mapped.fatal);

    mapped = vitals_map_outcome(VITALS_OUTCOME_NO_MEMORY, 0);
    CHECK_EQ_INT(VITALS_SCE_HTTP_ERROR_OUT_OF_MEMORY, mapped.hook_result);
    CHECK_EQ_INT(VITALS_SCE_HTTPS_ERROR_INTERNAL, mapped.ssl_error);

    mapped = vitals_map_outcome(VITALS_OUTCOME_INTERNAL, UINT32_C(0xDEAD));
    CHECK_EQ_INT(VITALS_SCE_HTTP_ERROR_SSL, mapped.hook_result);
    CHECK_EQ_INT(VITALS_SCE_HTTPS_ERROR_INTERNAL, mapped.ssl_error);
    CHECK_EQ_INT(UINT32_C(0xDEAD), mapped.detail);
}

static void test_module_gate(void) {
    uint8_t text[32];
    const uint8_t bytes[] = {0x10, 0x20, 0x30, 0x40};
    const VitalsMaskedSignature signature = {
        .name = "test",
        .offset = 8,
        .bytes = bytes,
        .mask = "x?xx",
        .length = sizeof(bytes),
    };
    const VitalsModuleDescriptor descriptor = {
        .text_size = sizeof(text),
        .signatures = &signature,
        .signature_count = 1,
    };
    size_t failed_signature = 0;
    size_t failed_byte = 0;
    VitalsMaskedSignature invalid_signature = signature;
    VitalsModuleDescriptor invalid_descriptor = descriptor;

    memset(text, 0, sizeof(text));
    memcpy(text + signature.offset, bytes, sizeof(bytes));
    CHECK_EQ_INT(
        VITALS_MODULE_GATE_OK,
        vitals_validate_module_text(
            text,
            sizeof(text),
            &descriptor,
            &failed_signature,
            &failed_byte));
    CHECK_EQ_INT(SIZE_MAX, failed_signature);
    CHECK_EQ_INT(SIZE_MAX, failed_byte);

    text[signature.offset + 1] ^= UINT8_C(0xFF);
    CHECK_EQ_INT(
        VITALS_MODULE_GATE_OK,
        vitals_validate_module_text(text, sizeof(text), &descriptor, NULL, NULL));

    text[signature.offset + 2] ^= UINT8_C(0xFF);
    CHECK_EQ_INT(
        VITALS_MODULE_GATE_SIGNATURE_MISMATCH,
        vitals_validate_module_text(
            text,
            sizeof(text),
            &descriptor,
            &failed_signature,
            &failed_byte));
    CHECK_EQ_INT(0, failed_signature);
    CHECK_EQ_INT(2, failed_byte);

    CHECK_EQ_INT(
        VITALS_MODULE_GATE_TEXT_SIZE_MISMATCH,
        vitals_validate_module_text(text, sizeof(text) - 1, &descriptor, NULL, NULL));

    invalid_signature.offset = sizeof(text) - 1;
    invalid_descriptor.signatures = &invalid_signature;
    CHECK_EQ_INT(
        VITALS_MODULE_GATE_SIGNATURE_BOUNDS,
        vitals_validate_module_text(text, sizeof(text), &invalid_descriptor, NULL, NULL));

    invalid_signature = signature;
    invalid_signature.mask = "x!xx";
    invalid_descriptor.signatures = &invalid_signature;
    CHECK_EQ_INT(
        VITALS_MODULE_GATE_SIGNATURE_MASK,
        vitals_validate_module_text(text, sizeof(text), &invalid_descriptor, NULL, NULL));
}

typedef struct RegistryTestContext {
    unsigned int lock_depth;
    unsigned int cleanup_count;
    uintptr_t last_cleaned_payload;
} RegistryTestContext;

static void registry_test_lock(void *context) {
    RegistryTestContext *test = context;
    CHECK_EQ_INT(0, test->lock_depth);
    ++test->lock_depth;
}

static void registry_test_unlock(void *context) {
    RegistryTestContext *test = context;
    CHECK_EQ_INT(1, test->lock_depth);
    --test->lock_depth;
}

static void registry_test_cleanup(void *context, void *payload) {
    RegistryTestContext *test = context;
    CHECK_EQ_INT(0, test->lock_depth);
    ++test->cleanup_count;
    test->last_cleaned_payload = (uintptr_t)payload;
}

static VitalsRegistryOps registry_test_ops(RegistryTestContext *context) {
    VitalsRegistryOps ops = {
        .lock = registry_test_lock,
        .unlock = registry_test_unlock,
        .cleanup = registry_test_cleanup,
        .context = context,
    };
    return ops;
}

static void test_registry_basic(void) {
    VitalsRegistry registry;
    RegistryTestContext context = {0};
    VitalsRegistryOps ops = registry_test_ops(&context);
    VitalsRegistryHandle handle = {0};

    CHECK_EQ_INT(VITALS_REGISTRY_OK, vitals_registry_init(&registry, &ops));
    CHECK_EQ_INT(
        VITALS_REGISTRY_INVALID_ARGUMENT,
        vitals_registry_insert(&registry, 0, (void *)(uintptr_t)1));
    CHECK_EQ_INT(
        VITALS_REGISTRY_OK,
        vitals_registry_insert(&registry, UINT32_C(0x1000), (void *)(uintptr_t)UINT32_C(0x2000)));
    CHECK_EQ_INT(1, vitals_registry_count(&registry));
    CHECK_EQ_INT(
        VITALS_REGISTRY_DUPLICATE,
        vitals_registry_insert(&registry, UINT32_C(0x1000), (void *)(uintptr_t)UINT32_C(0x3000)));
    CHECK_EQ_INT(
        VITALS_REGISTRY_OK,
        vitals_registry_acquire(&registry, UINT32_C(0x1000), &handle));
    CHECK_EQ_INT(UINT32_C(0x2000), (uintptr_t)handle.payload);
    CHECK_EQ_INT(
        VITALS_REGISTRY_OK,
        vitals_registry_remove(&registry, UINT32_C(0x1000)));
    CHECK_EQ_INT(1, vitals_registry_count(&registry));
    CHECK_EQ_INT(0, context.cleanup_count);
    CHECK_EQ_INT(
        VITALS_REGISTRY_BUSY,
        vitals_registry_acquire(&registry, UINT32_C(0x1000), &(VitalsRegistryHandle){0}));
    CHECK_EQ_INT(VITALS_REGISTRY_OK, vitals_registry_release(&registry, &handle));
    CHECK_EQ_INT(1, context.cleanup_count);
    CHECK_EQ_INT(UINT32_C(0x2000), context.last_cleaned_payload);
    CHECK_EQ_INT(0, vitals_registry_count(&registry));
    CHECK_EQ_INT(VITALS_REGISTRY_OK, vitals_registry_destroy(&registry));
}

static void test_registry_generation_and_stale_handle(void) {
    VitalsRegistry registry;
    RegistryTestContext context = {0};
    VitalsRegistryOps ops = registry_test_ops(&context);
    VitalsRegistryHandle first = {0};
    VitalsRegistryHandle stale;
    VitalsRegistryHandle second = {0};

    CHECK_EQ_INT(VITALS_REGISTRY_OK, vitals_registry_init(&registry, &ops));
    CHECK_EQ_INT(
        VITALS_REGISTRY_OK,
        vitals_registry_insert(&registry, 1, (void *)(uintptr_t)11));
    CHECK_EQ_INT(VITALS_REGISTRY_OK, vitals_registry_acquire(&registry, 1, &first));
    stale = first;
    CHECK_EQ_INT(VITALS_REGISTRY_OK, vitals_registry_release(&registry, &first));
    CHECK_EQ_INT(VITALS_REGISTRY_OK, vitals_registry_remove(&registry, 1));
    CHECK_EQ_INT(
        VITALS_REGISTRY_OK,
        vitals_registry_insert(&registry, 2, (void *)(uintptr_t)22));
    CHECK_EQ_INT(VITALS_REGISTRY_OK, vitals_registry_acquire(&registry, 2, &second));
    CHECK(second.generation != stale.generation);
    CHECK_EQ_INT(
        VITALS_REGISTRY_STALE_HANDLE,
        vitals_registry_release(&registry, &stale));
    CHECK_EQ_INT(VITALS_REGISTRY_OK, vitals_registry_release(&registry, &second));
    CHECK_EQ_INT(VITALS_REGISTRY_OK, vitals_registry_remove(&registry, 2));
    CHECK_EQ_INT(2, context.cleanup_count);
    CHECK_EQ_INT(VITALS_REGISTRY_OK, vitals_registry_destroy(&registry));
}

static void test_registry_replace(void) {
    VitalsRegistry registry;
    RegistryTestContext context = {0};
    VitalsRegistryOps ops = registry_test_ops(&context);
    VitalsRegistryHandle handle = {0};
    uint32_t first_generation;

    CHECK_EQ_INT(VITALS_REGISTRY_OK, vitals_registry_init(&registry, &ops));
    CHECK_EQ_INT(
        VITALS_REGISTRY_NOT_FOUND,
        vitals_registry_replace(&registry, 1, (void *)(uintptr_t)11));
    CHECK_EQ_INT(
        VITALS_REGISTRY_OK,
        vitals_registry_insert(&registry, 1, (void *)(uintptr_t)11));
    CHECK_EQ_INT(VITALS_REGISTRY_OK, vitals_registry_acquire(&registry, 1, &handle));
    first_generation = handle.generation;
    CHECK_EQ_INT(
        VITALS_REGISTRY_BUSY,
        vitals_registry_replace(&registry, 1, (void *)(uintptr_t)22));
    CHECK_EQ_INT(VITALS_REGISTRY_OK, vitals_registry_release(&registry, &handle));
    CHECK_EQ_INT(
        VITALS_REGISTRY_OK,
        vitals_registry_replace(&registry, 1, (void *)(uintptr_t)22));
    CHECK_EQ_INT(1, context.cleanup_count);
    CHECK_EQ_INT(11, context.last_cleaned_payload);
    CHECK_EQ_INT(VITALS_REGISTRY_OK, vitals_registry_acquire(&registry, 1, &handle));
    CHECK_EQ_INT(22, (uintptr_t)handle.payload);
    CHECK(handle.generation != first_generation);
    CHECK_EQ_INT(VITALS_REGISTRY_OK, vitals_registry_release(&registry, &handle));
    CHECK_EQ_INT(VITALS_REGISTRY_OK, vitals_registry_remove(&registry, 1));
    CHECK_EQ_INT(2, context.cleanup_count);
    CHECK_EQ_INT(VITALS_REGISTRY_OK, vitals_registry_destroy(&registry));
}

static void test_registry_capacity(void) {
    VitalsRegistry registry;
    RegistryTestContext context = {0};
    VitalsRegistryOps ops = registry_test_ops(&context);
    size_t index;

    CHECK_EQ_INT(VITALS_REGISTRY_OK, vitals_registry_init(&registry, &ops));
    for (index = 0; index < VITALS_REGISTRY_CAPACITY; ++index) {
        CHECK_EQ_INT(
            VITALS_REGISTRY_OK,
            vitals_registry_insert(
                &registry,
                (uintptr_t)(index + 1),
                (void *)(uintptr_t)(index + 101)));
    }
    CHECK_EQ_INT(
        VITALS_REGISTRY_FULL,
        vitals_registry_insert(&registry, UINT32_C(0xFFFF), (void *)(uintptr_t)1));
    CHECK_EQ_INT(VITALS_REGISTRY_CAPACITY, vitals_registry_count(&registry));
    CHECK_EQ_INT(VITALS_REGISTRY_OK, vitals_registry_destroy(&registry));
    CHECK_EQ_INT(VITALS_REGISTRY_CAPACITY, context.cleanup_count);
}

static void test_registry_stop_gate(void) {
    VitalsRegistry registry;
    RegistryTestContext context = {0};
    VitalsRegistryOps ops = registry_test_ops(&context);

    CHECK_EQ_INT(VITALS_REGISTRY_OK, vitals_registry_init(&registry, &ops));
    CHECK_EQ_INT(
        VITALS_REGISTRY_OK,
        vitals_registry_insert(&registry, 1, (void *)(uintptr_t)11));
    CHECK_EQ_INT(
        VITALS_REGISTRY_BUSY,
        vitals_registry_begin_stop_if_empty(&registry));
    CHECK_EQ_INT(
        VITALS_REGISTRY_OK,
        vitals_registry_insert(&registry, 2, (void *)(uintptr_t)22));
    CHECK_EQ_INT(VITALS_REGISTRY_OK, vitals_registry_remove(&registry, 1));
    CHECK_EQ_INT(VITALS_REGISTRY_OK, vitals_registry_remove(&registry, 2));
    CHECK_EQ_INT(
        VITALS_REGISTRY_OK,
        vitals_registry_begin_stop_if_empty(&registry));
    CHECK_EQ_INT(
        VITALS_REGISTRY_BUSY,
        vitals_registry_insert(&registry, 3, (void *)(uintptr_t)33));
    CHECK_EQ_INT(VITALS_REGISTRY_OK, vitals_registry_destroy(&registry));
    CHECK_EQ_INT(2, context.cleanup_count);
}

static void test_registry_busy_destroy(void) {
    VitalsRegistry registry;
    RegistryTestContext context = {0};
    VitalsRegistryOps ops = registry_test_ops(&context);
    VitalsRegistryHandle handle = {0};

    CHECK_EQ_INT(VITALS_REGISTRY_OK, vitals_registry_init(&registry, &ops));
    CHECK_EQ_INT(
        VITALS_REGISTRY_OK,
        vitals_registry_insert(&registry, 7, (void *)(uintptr_t)77));
    CHECK_EQ_INT(VITALS_REGISTRY_OK, vitals_registry_acquire(&registry, 7, &handle));
    CHECK_EQ_INT(VITALS_REGISTRY_BUSY, vitals_registry_destroy(&registry));
    CHECK_EQ_INT(
        VITALS_REGISTRY_BUSY,
        vitals_registry_insert(&registry, 8, (void *)(uintptr_t)88));
    CHECK_EQ_INT(VITALS_REGISTRY_OK, vitals_registry_release(&registry, &handle));
    CHECK_EQ_INT(1, context.cleanup_count);
    CHECK_EQ_INT(VITALS_REGISTRY_OK, vitals_registry_destroy(&registry));
}

int main(void) {
    test_path_helpers();
    test_sony_abi();
    test_error_map();
    test_module_gate();
    test_registry_basic();
    test_registry_generation_and_stale_handle();
    test_registry_replace();
    test_registry_capacity();
    test_registry_stop_gate();
    test_registry_busy_destroy();

    if (g_failures != 0) {
        fprintf(stderr, "%u of %u checks failed\n", g_failures, g_assertions);
        return EXIT_FAILURE;
    }

    printf("all %u checks passed\n", g_assertions);
    return EXIT_SUCCESS;
}
