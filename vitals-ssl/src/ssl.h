#ifndef VITALS_SSL_H
#define VITALS_SSL_H

#include <psp2/libssl.h>

/* What every export that isn't written yet does: logs its name (DEBUG=1 or 2) and fails with
 * SCE_SSL_ERROR_INTERNAL */
int ssl_not_implemented(const char *function);

#endif
