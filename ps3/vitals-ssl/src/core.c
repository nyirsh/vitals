/* cellSslInit and cellSslEnd: the library's pool, its lock and Mbed TLS, in the order Sony's checks
 * and builds them (ps3-dumps/libssl.prx: cellSslInit at 0x15f0, cellSslEnd at 0x155c); and what the
 * rest of the library shares: whether it's set up, its lock, and SSL-C's error queue */

#include "core.h"

#include "ca_store.h"

#include "crypto_platform.h"
#include "pool.h"
#include "vs.h"
#include "vitals_log.h"

#include <psa/crypto.h>

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

/* The errors kept, oldest first; OpenSSL's queue keeps 16 too */
#define VS_ERROR_QUEUE 16

static int g_initialized;
static unsigned long g_errors[VS_ERROR_QUEUE];
static int g_error_count;

int cellSslInit(void *pool, uint32_t size)
{
	VS_LOG("cellSslInit: pool of %u bytes", (unsigned)size);

	if (g_initialized)
		return VITALS_SSL_ERROR_ALREADY_INITIALIZED;
	if (pool == NULL || size == 0)
		return VITALS_SSL_ERROR_NO_BUFFER;
	if (vitals_pool_create(pool, size) != 0)
		return VITALS_SSL_ERROR_NO_MEMORY;
	/* Recursive, as Sony's ("_sslsys") */
	if (vs_platform_lock_create() != 0) {
		vitals_pool_delete();
		return VITALS_SSL_ERROR_INITIALIZATION_FAILED;
	}

	int rc = vitals_crypto_platform_init();
	psa_status_t status = rc == 0 ? psa_crypto_init() : PSA_ERROR_GENERIC_ERROR;
	VS_LOG("cellSslInit: platform %d, psa_crypto_init %d", rc, (int)status);
	if (status != PSA_SUCCESS) {
		if (rc == 0)
			vitals_crypto_platform_free();
		vs_platform_lock_destroy();
		vitals_pool_delete();
		return VITALS_SSL_ERROR_INITIALIZATION_FAILED;
	}
	g_error_count = 0;
	g_initialized = 1;
	return 0;
}

int cellSslEnd(void)
{
	VS_LOG("cellSslEnd");
	if (!g_initialized)
		return VITALS_SSL_ERROR_NOT_INITIALIZED;
#if VITALS_DEBUG >= 1
	VitalsPoolUse use;
	if (vitals_pool_use(&use) == 0)
		VS_LOG("cellSslEnd: pool of %u bytes, at most %u used, %u allocations refused", (unsigned)use.size,
		       (unsigned)(use.size - use.lowest_free), (unsigned)use.refused);
#endif
	g_initialized = 0;
	vs_ca_store_end();
	mbedtls_psa_crypto_free();
	vitals_crypto_platform_free();
	vs_platform_lock_destroy();
	vitals_pool_delete();
	return 0;
}

/* 1 between cellSslInit and cellSslEnd, else 0: the flag Sony's reads (0x1114), which libhttp's
 * cellHttpsInit checks */
int _cellSslIsInitd(void)
{
	return g_initialized;
}

int vs_initialized(void)
{
	return g_initialized;
}

void vs_lock(void)
{
	if (g_initialized)
		vs_platform_lock();
}

void vs_unlock(void)
{
	if (g_initialized)
		vs_platform_unlock();
}

/* ---- SSL-C's error queue (OpenSSL's ERR) ---- */

void vs_error_push(unsigned long error)
{
	vs_lock();
	if (g_error_count == VS_ERROR_QUEUE) {
		/* Full: the oldest goes, as OpenSSL's ring overwrites it */
		for (int i = 1; i < VS_ERROR_QUEUE; ++i)
			g_errors[i - 1] = g_errors[i];
		--g_error_count;
	}
	g_errors[g_error_count++] = error;
	vs_unlock();
}

/* ERR_get_error: the oldest error, taken off the queue; 0 when there's none */
unsigned long ERR_get_error(void)
{
	vs_lock();
	unsigned long error = g_error_count > 0 ? g_errors[0] : 0;
	if (g_error_count > 0) {
		for (int i = 1; i < g_error_count; ++i)
			g_errors[i - 1] = g_errors[i];
		--g_error_count;
	}
	vs_unlock();
	return error;
}

/* ERR_peek_error: the oldest error, left there; 0 when there's none */
unsigned long ERR_peek_error(void)
{
	vs_lock();
	unsigned long error = g_error_count > 0 ? g_errors[0] : 0;
	vs_unlock();
	return error;
}

/* ERR_clear_error: the queue emptied */
void ERR_clear_error(void)
{
	vs_lock();
	g_error_count = 0;
	vs_unlock();
}

/* ERR_error_string (0x13290): an error as OpenSSL 0.9.8 writes it, "error:%08lX:" and its library,
 * function and reason. Sony's has names for some libraries and reasons and none for functions, so
 * these name the four libraries it does (and give lib(N) for the rest), and func(N) and reason(N);
 * the reasons' texts aren't Sony's. Into buffer (256 bytes), or a buffer of the library's without
 * one, as OpenSSL's */
char *ERR_error_string(unsigned long error, char *buffer)
{
	static char kept[256];
	char *out = buffer != NULL ? buffer : kept;
	unsigned long library = error >> 24 & 0xFF, function = error >> 12 & 0xFFF, reason = error & 0xFFF;
	const char *name = library == VS_ERR_LIB_SYS   ? "system library"
	                   : library == 9              ? "PEM routines"
	                   : library == VS_ERR_LIB_SSL ? "SSL routines"
	                   : library == VS_ERR_LIB_BIO ? "BIO routines"
	                                               : NULL;
	char library_text[24];
	if (name == NULL) {
		snprintf(library_text, sizeof(library_text), "lib(%lu)", library);
		name = library_text;
	}
	snprintf(out, 256, "error:%08lX:%s:func(%lu):reason(%lu)", error, name, function, reason);
	return out;
}

/* ERR_func_error_string (0x130f8): an error's function's name, which Sony's has none of: NULL */
const char *ERR_func_error_string(unsigned long error)
{
	(void)error;
	return NULL;
}

/* NID 0x4EE83087, Sony 0x1120: keeps two values in the library's state (Sony's words 4 and 8),
 * which nothing seen reads back; 0, or 0x80740001 before cellSslInit */
static uint32_t g_values[2];

int cellSsl_4EE83087(uint32_t first, uint32_t second)
{
	if (!g_initialized)
		return VITALS_SSL_ERROR_NOT_INITIALIZED;
	g_values[0] = first;
	g_values[1] = second;
	return 0;
}

/* NID 0xE95B6A4C, Sony 0x114c: does nothing (Sony's is a lone blr) */
void cellSsl_E95B6A4C(void)
{
}

#if VITALS_DEBUG >= 1
void vs_log(const char *format, ...)
{
	char line[256];
	va_list arguments;
	va_start(arguments, format);
	vsnprintf(line, sizeof(line), format, arguments);
	va_end(arguments);
	vs_platform_log(line);
}
#endif
