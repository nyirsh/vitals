#ifndef VITALS_USER_RUNTIME_H
#define VITALS_USER_RUNTIME_H

#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>

/* Provider heap size, set by the build (VITALS_HTTP_HEAP_KIB)
 * A heap that is too small fails closed: allocation errors fail the TLS operation */
#ifndef VITALS_HTTP_HEAP_BYTES
#define VITALS_HTTP_HEAP_BYTES (128u * 1024u)
#endif

/* This runtime belongs to one HTTP provider process, never to the host app */
typedef struct VitalsRuntimeStats {
    uint32_t capacity;
    uint32_t peak;
    uint32_t used;
    uint32_t outstanding;
} VitalsRuntimeStats;

int vitals_user_runtime_init(void);
int vitals_user_runtime_destroy(void);
int vitals_user_runtime_stats(VitalsRuntimeStats *stats);
/* Debug level 1 and up: prints heap use through sceClibPrintf when the peak has
 * grown since the last report
 * Compiles to nothing otherwise */
#if defined(VITALS_DEBUG) && VITALS_DEBUG >= 1
void vitals_user_runtime_report(const char *tag, int force);
#else
#define vitals_user_runtime_report(tag, force) ((void)(tag), (void)(force))
#endif

/* Linker wrappers satisfy unmodified provider/dependency C calls */
void *__wrap_malloc(size_t size);
void *__wrap_calloc(size_t count, size_t size);
void *__wrap_realloc(void *pointer, size_t size);
void __wrap_free(void *pointer);
void *__wrap_memchr(const void *source, int value, size_t size);
int __wrap_memcmp(const void *left, const void *right, size_t size);
void *__wrap_memcpy(void *destination, const void *source, size_t size);
void *__wrap_memmove(void *destination, const void *source, size_t size);
void *__wrap_memset(void *destination, int value, size_t size);
char *__wrap_strchr(const char *source, int value);
int __wrap_strcmp(const char *left, const char *right);
size_t __wrap_strlen(const char *source);
char *__wrap_strstr(const char *source, const char *needle);
int __wrap_printf(const char *format, ...) __attribute__((format(printf, 1, 2)));
int __wrap_puts(const char *source);
int __wrap_snprintf(char *output, size_t capacity, const char *format, ...)
    __attribute__((format(printf, 3, 4)));
int __wrap_vsnprintf(char *output, size_t capacity, const char *format, va_list args)
    __attribute__((format(printf, 3, 0)));

#endif
