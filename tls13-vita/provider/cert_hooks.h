#ifndef VITALS_CERT_HOOKS_H
#define VITALS_CERT_HOOKS_H

#include <stdint.h>

#include <mbedtls/x509_crt.h>

int vitals_cert_hooks_install(void);
void vitals_cert_hooks_release(void);
int vitals_legacy_certificates_loaded(void);
/* Appends game-loaded CA certificates that issued child to *candidates (allocating the
 * chain when it is NULL); same ownership contract as mbedtls_x509_crt_ca_cb_t */
int vitals_game_ca_find(const mbedtls_x509_crt *child, mbedtls_x509_crt **candidates);
int vitals_cert_callback_decide(
    void *sony_connection,
    uint32_t verification_detail,
    int *accepted);

#endif
