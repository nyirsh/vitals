#ifndef VITALS_SSL_CORE_H
#define VITALS_SSL_CORE_H

#include <stdint.h>

/* cellSsl's error codes, as Sony's libssl returns them (core.c says where) */
#define VITALS_SSL_ERROR_NOT_INITIALIZED ((int)0x80740001)
#define VITALS_SSL_ERROR_ALREADY_INITIALIZED ((int)0x80740002)
#define VITALS_SSL_ERROR_INITIALIZATION_FAILED ((int)0x80740003)
#define VITALS_SSL_ERROR_NO_BUFFER ((int)0x80740004)
#define VITALS_SSL_ERROR_NO_MEMORY ((int)0x80740035)

int cellSslInit(void *pool, uint32_t size);
int cellSslEnd(void);
int _cellSslIsInitd(void);

/* SSL-C's error queue: one for the library, where OpenSSL keeps one a thread (which connection.c's
 * SSL_get_error doesn't depend on: it reports what the connection itself saw) */
unsigned long ERR_get_error(void);
unsigned long ERR_peek_error(void);
void ERR_clear_error(void);
char *ERR_error_string(unsigned long error, char *buffer);
const char *ERR_func_error_string(unsigned long error);
int cellSsl_4EE83087(uint32_t first, uint32_t second);
void cellSsl_E95B6A4C(void);

#endif
