#ifndef VITALS_SONY_ABI_H
#define VITALS_SONY_ABI_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VITALS_START_MAGIC UINT32_C(0x49544C53)
#define VITALS_START_VERSION UINT32_C(1)

#define VITALS_LIBHTTP_TEXT_SIZE ((size_t)UINT32_C(0x1D150))
#define VITALS_LIBHTTP_DATA_FILE_SIZE ((size_t)UINT32_C(0x5A4))
#define VITALS_LIBHTTP_DATA_MEMORY_SIZE ((size_t)UINT32_C(0x640))
#define VITALS_LIBHTTP_GLOBAL_HTTPS_OPTIONS_OFFSET ((size_t)UINT32_C(0xF4))
#define VITALS_LIBSSL_TEXT_SIZE ((size_t)UINT32_C(0x4CCA0))

#define VITALS_HOOK_CREATE_OFFSET ((size_t)UINT32_C(0x8130))
#define VITALS_HOOK_CONNECT_OFFSET ((size_t)UINT32_C(0x8362))
#define VITALS_HOOK_MAP_IO_OFFSET ((size_t)UINT32_C(0x85FE))
#define VITALS_HOOK_READ_OFFSET ((size_t)UINT32_C(0x869C))
#define VITALS_HOOK_WRITE_OFFSET ((size_t)UINT32_C(0x86F4))
#define VITALS_HOOK_SHUTDOWN_OFFSET ((size_t)UINT32_C(0x874C))

#define VITALS_SSL_GET_SERIAL_OFFSET ((size_t)UINT32_C(0x494F0))
#define VITALS_SSL_GET_SUBJECT_OFFSET ((size_t)UINT32_C(0x49570))
#define VITALS_SSL_GET_ISSUER_OFFSET ((size_t)UINT32_C(0x495B8))
#define VITALS_SSL_FREE_NAME_OFFSET ((size_t)UINT32_C(0x49600))
#define VITALS_SSL_GET_NOT_BEFORE_OFFSET ((size_t)UINT32_C(0x4963C))
#define VITALS_SSL_GET_NOT_AFTER_OFFSET ((size_t)UINT32_C(0x49768))
#define VITALS_SSL_GET_NAME_COUNT_OFFSET ((size_t)UINT32_C(0x49894))
#define VITALS_SSL_GET_NAME_INFO_OFFSET ((size_t)UINT32_C(0x498F0))

#define VITALS_REQUEST_PRIMARY_CONNECTION_OFFSET ((size_t)UINT32_C(0x134))
#define VITALS_REQUEST_FALLBACK_CONNECTION_OFFSET ((size_t)UINT32_C(0x130))
#define VITALS_REQUEST_NONBLOCK_OFFSET ((size_t)UINT32_C(0x8C))

#define VITALS_CONNECTION_SOCKET_OFFSET ((size_t)UINT32_C(0x24))
#define VITALS_CONNECTION_HOSTNAME_OFFSET ((size_t)UINT32_C(0x48))
#define VITALS_CONNECTION_CALLBACK_OFFSET ((size_t)UINT32_C(0x104))
#define VITALS_CONNECTION_CALLBACK_ARG_OFFSET ((size_t)UINT32_C(0x108))
#define VITALS_CONNECTION_HTTPS_OPTIONS_OFFSET ((size_t)UINT32_C(0xD4))
#define VITALS_CONNECTION_SSL_ERROR_OFFSET ((size_t)UINT32_C(0x160))
#define VITALS_CONNECTION_SSL_DETAIL_OFFSET ((size_t)UINT32_C(0x164))

#define VITALS_SCE_NET_ERROR_EAGAIN ((int32_t)UINT32_C(0x80410123))
#define VITALS_SCE_HTTP_ERROR_OUT_OF_MEMORY ((int32_t)UINT32_C(0x80431022))
#define VITALS_SCE_HTTP_ERROR_TIMEOUT ((int32_t)UINT32_C(0x80431068))
#define VITALS_SCE_HTTP_ERROR_SSL ((int32_t)UINT32_C(0x80431075))
#define VITALS_SCE_HTTP_ERROR_EAGAIN ((int32_t)UINT32_C(0x80431082))
#define VITALS_SCE_HTTP_ERROR_INVALID_VALUE ((int32_t)UINT32_C(0x804311FE))

#define VITALS_SCE_SSL_ERROR_BEFORE_INIT ((int32_t)UINT32_C(0x80435001))
#define VITALS_SCE_SSL_ERROR_OUT_OF_MEMORY ((int32_t)UINT32_C(0x80435022))
#define VITALS_SCE_SSL_ERROR_NOT_FOUND ((int32_t)UINT32_C(0x80435025))
#define VITALS_SCE_SSL_ERROR_INTERNAL ((int32_t)UINT32_C(0x80435026))
#define VITALS_SCE_SSL_ERROR_INVALID_FORMAT ((int32_t)UINT32_C(0x80435108))
#define VITALS_SCE_SSL_ERROR_INVALID_VALUE ((int32_t)UINT32_C(0x804351FE))

#define VITALS_SCE_HTTPS_ERROR_CERT ((int32_t)UINT32_C(0x80435060))
#define VITALS_SCE_HTTPS_ERROR_HANDSHAKE ((int32_t)UINT32_C(0x80435061))
#define VITALS_SCE_HTTPS_ERROR_IO ((int32_t)UINT32_C(0x80435062))
#define VITALS_SCE_HTTPS_ERROR_INTERNAL ((int32_t)UINT32_C(0x80435063))
#define VITALS_SCE_HTTPS_ERROR_PROXY ((int32_t)UINT32_C(0x80435064))
#define VITALS_SCE_HTTPS_INTERNAL_RETRY ((int32_t)UINT32_C(0x80435065))

#define VITALS_SCE_HTTPS_DETAIL_INTERNAL UINT32_C(0x01)
#define VITALS_SCE_HTTPS_DETAIL_INVALID_CERT UINT32_C(0x02)
#define VITALS_SCE_HTTPS_DETAIL_CN_CHECK UINT32_C(0x04)
#define VITALS_SCE_HTTPS_DETAIL_NOT_AFTER UINT32_C(0x08)
#define VITALS_SCE_HTTPS_DETAIL_NOT_BEFORE UINT32_C(0x10)
#define VITALS_SCE_HTTPS_DETAIL_UNKNOWN_CA UINT32_C(0x20)

#define VITALS_SCE_HTTPS_OPTION_SERVER_VERIFY UINT32_C(0x01)
#define VITALS_SCE_HTTPS_OPTION_CLIENT_VERIFY UINT32_C(0x02)
#define VITALS_SCE_HTTPS_OPTION_CN_CHECK UINT32_C(0x04)
#define VITALS_SCE_HTTPS_OPTION_NOT_AFTER UINT32_C(0x08)
#define VITALS_SCE_HTTPS_OPTION_NOT_BEFORE UINT32_C(0x10)
#define VITALS_SCE_HTTPS_OPTION_KNOWN_CA UINT32_C(0x20)
#define VITALS_SCE_HTTPS_OPTION_PUBLIC_MASK UINT32_C(0x3F)
#define VITALS_SCE_HTTPS_OPTION_PRIVATE_CHAIN UINT32_C(0x40)
#define VITALS_SCE_HTTPS_OPTION_SUPPORTED_MASK UINT32_C(0x1FF)

#define VITALS_MAX_IO_CHUNK ((size_t)1500)

typedef struct VitalsStartArgs {
    uint32_t magic;
    uint32_t version;
    int32_t libhttp_modid;
    uint32_t reserved;
} VitalsStartArgs;

static inline uint32_t vitals_read_u32(const void *base, size_t offset) {
    uint32_t value = 0;
    memcpy(&value, (const uint8_t *)base + offset, sizeof(value));
    return value;
}

static inline int32_t vitals_read_i32(const void *base, size_t offset) {
    int32_t value = 0;
    memcpy(&value, (const uint8_t *)base + offset, sizeof(value));
    return value;
}

static inline void vitals_write_u32(void *base, size_t offset, uint32_t value) {
    memcpy((uint8_t *)base + offset, &value, sizeof(value));
}

static inline uintptr_t vitals_resolve_connection_address(const void *request) {
    uint32_t value = vitals_read_u32(request, VITALS_REQUEST_PRIMARY_CONNECTION_OFFSET);
    if (value == 0) {
        value = vitals_read_u32(request, VITALS_REQUEST_FALLBACK_CONNECTION_OFFSET);
    }
    return (uintptr_t)value;
}

static inline void *vitals_resolve_connection(void *request) {
    return (void *)vitals_resolve_connection_address(request);
}

static inline int vitals_request_is_nonblocking(const void *request) {
    return request != NULL &&
        vitals_read_i32(request, VITALS_REQUEST_NONBLOCK_OFFSET) != 0;
}

static inline int vitals_connection_socket(const void *connection) {
    return (int)vitals_read_i32(connection, VITALS_CONNECTION_SOCKET_OFFSET);
}

static inline uintptr_t vitals_connection_hostname_address(const void *connection) {
    return (uintptr_t)vitals_read_u32(connection, VITALS_CONNECTION_HOSTNAME_OFFSET);
}

static inline const char *vitals_connection_hostname(const void *connection) {
    return (const char *)vitals_connection_hostname_address(connection);
}

static inline uintptr_t vitals_connection_callback_address(const void *connection) {
    return (uintptr_t)vitals_read_u32(connection, VITALS_CONNECTION_CALLBACK_OFFSET);
}

static inline uintptr_t vitals_connection_callback_arg_address(const void *connection) {
    return (uintptr_t)vitals_read_u32(connection, VITALS_CONNECTION_CALLBACK_ARG_OFFSET);
}

static inline uint32_t vitals_connection_effective_https_options(
    const void *connection,
    uint32_t global_options) {
    const int32_t connection_options =
        vitals_read_i32(connection, VITALS_CONNECTION_HTTPS_OPTIONS_OFFSET);
    const uint32_t effective = connection_options < 0
        ? (uint32_t)connection_options
        : global_options;

    return effective & VITALS_SCE_HTTPS_OPTION_SUPPORTED_MASK;
}

static inline void vitals_store_ssl_error(void *connection, int32_t error, uint32_t detail) {
    vitals_write_u32(connection, VITALS_CONNECTION_SSL_ERROR_OFFSET, (uint32_t)error);
    vitals_write_u32(connection, VITALS_CONNECTION_SSL_DETAIL_OFFSET, detail);
}

#ifdef __cplusplus
}
#endif

#endif
