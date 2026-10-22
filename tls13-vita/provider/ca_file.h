#ifndef VITALS_CA_FILE_H
#define VITALS_CA_FILE_H

#include <mbedtls/x509_crt.h>

#ifndef VITALS_DEFAULT_CA_PATH
#define VITALS_DEFAULT_CA_PATH "vs0:/data/external/cert/CA_LIST.cer"
#endif

int vitals_load_ca_file(mbedtls_x509_crt *chain, const char *path);

#endif
