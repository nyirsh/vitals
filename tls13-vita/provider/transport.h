#ifndef VITALS_TRANSPORT_H
#define VITALS_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

#include <psp2/types.h>

#include <mbedtls/build_info.h>
#include <mbedtls/ssl.h>

#include "vitals/error_map.h"
#include "vitals/registry.h"
#include "vitals/sony_abi.h"

#if MBEDTLS_VERSION_MAJOR != 4
#error "The HTTP provider's configuration targets Mbed TLS 4.x"
#endif

#ifndef MBEDTLS_SSL_PROTO_TLS1_3
#error "vitals requires Mbed TLS TLS 1.3 support"
#endif

#if !defined(MBEDTLS_THREADING_C) || !defined(MBEDTLS_THREADING_ALT)
#error "vitals requires the explicit Vita threading port"
#endif

typedef enum VitalsConnectionState {
    VITALS_CONNECTION_INITIALIZING = 0,
    VITALS_CONNECTION_HANDSHAKING,
    VITALS_CONNECTION_ACTIVE,
    VITALS_CONNECTION_FAILED,
    VITALS_CONNECTION_CLOSING
} VitalsConnectionState;

typedef struct VitalsConnection {
    void *sony_connection;
    int socket;
    char *hostname;
    VitalsConnectionState state;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config config;
    mbedtls_x509_crt_profile certificate_profile;
    SceUID mutex;
    int32_t last_tls_error;
    int32_t last_net_error;
    uint32_t last_verify_flags;
    uint32_t https_options;
    size_t pending_write_length;
    unsigned char pending_write[VITALS_MAX_IO_CHUNK];
    uint8_t mutex_initialized;
    uint8_t ssl_initialized;
    uint8_t config_initialized;
} VitalsConnection;

int vitals_transport_global_init(void);
int vitals_transport_global_destroy(void);
void vitals_transport_cleanup(void *context, void *payload);

int vitals_transport_create(void *request, int socket, int *handled);
int vitals_transport_connect(void *request, int *handled);
int vitals_transport_map_io(void *connection, int result, int *handled);
int vitals_transport_read(
    void *connection,
    void *buffer,
    unsigned int length,
    int *handled);
int vitals_transport_write(
    void *connection,
    const void *buffer,
    unsigned int length,
    int *handled);
int vitals_transport_shutdown(void *connection, int *handled);

int vitals_vita_send(void *context, const unsigned char *buffer, size_t length);
int vitals_vita_recv(void *context, unsigned char *buffer, size_t length);

#endif
