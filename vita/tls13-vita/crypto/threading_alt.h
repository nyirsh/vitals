#ifndef VITALS_THREADING_ALT_H
#define VITALS_THREADING_ALT_H

/* TF-PSA-Crypto's mutexes and condition variables are the kernel's (../provider/platform_shims.c);
 * a condition is created on its first wait, as the kernel ties it to its mutex */
typedef struct
{
    int uid;
} mbedtls_platform_mutex_t;

typedef struct
{
    int uid;
    int mutex_uid;
} mbedtls_platform_condition_variable_t;

#endif
