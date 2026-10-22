#ifndef VITALS_THREADING_ALT_H
#define VITALS_THREADING_ALT_H

typedef struct {
    int uid;
} mbedtls_platform_mutex_t;

typedef struct {
    int uid;
    int mutex_uid;
} mbedtls_platform_condition_variable_t;

#endif
