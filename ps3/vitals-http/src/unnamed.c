/* The exports Sony's libhttp has no published name for, as their code and the probe show them
 * (tests/http-probe/source/unnamed.c): further slots of the client's tables
 * (the named setters and getters share one function per table, with the slot as an index), the
 * transaction's credentials, a libhttp-wide value, and the disk cache's API (0x80710061, 0x80710062),
 * answered without a disk cache. What a flag or value does isn't known
 * either; each is kept and answered as Sony's, defaults and highest values included */

#include "vh.h"

#include <cell/http.h>
#include <string.h>

#define ERROR_SUBSYSTEM_ALREADY ((int)0x80710061)
#define ERROR_SUBSYSTEM_NOT_INITIALIZED ((int)0x80710062)
#define ERROR_CACHE_NOT_INITIALIZED ((int)0x80710044)
#define ERROR_CANNOT_AUTHENTICATE ((int)0x80710028)

#define WITH_CLIENT(id, client)                         \
	if (!vh_initialized())                          \
		return VH_ERROR_NOT_INITIALIZED;        \
	VhClient *client = vh_client((void *)(id));     \
	if (client == NULL)                             \
		return VH_ERROR_BAD_CLIENT

/* A flag's setter and getter; check, when it isn't 0, is the error turning it on gives */
#define FLAG(setter, getter, field, check)                                \
	int setter(CellHttpClientId id, bool enable)                      \
	{                                                                 \
		VH_LOG(#setter " %p %d", (void *)id, enable ? 1 : 0);     \
		WITH_CLIENT(id, client);                                  \
		int refused = (check);                                    \
		if (enable && refused != 0)                               \
			return refused;                                   \
		client->field = enable ? 1 : 0;                           \
		return 0;                                                 \
	}                                                                 \
	int getter(CellHttpClientId id, bool *enable)                     \
	{                                                                 \
		WITH_CLIENT(id, client);                                  \
		if (enable == NULL)                                       \
			return VH_ERROR_NO_BUFFER;                        \
		*enable = client->field != 0;                             \
		return 0;                                                 \
	}

/* A value's setter and getter; max, when it isn't 0, the highest it takes (0x80710027 above) */
#define VALUE(setter, getter, field, max)                                 \
	int setter(CellHttpClientId id, size_t value)                     \
	{                                                                 \
		VH_LOG(#setter " %p %u", (void *)id, (unsigned)value);    \
		WITH_CLIENT(id, client);                                  \
		if ((max) != 0 && value > (size_t)(max))                  \
			return VH_ERROR_INVALID_VALUE;                    \
		client->field = (uint32_t)value;                          \
		return 0;                                                 \
	}                                                                 \
	int getter(CellHttpClientId id, size_t *value)                    \
	{                                                                 \
		WITH_CLIENT(id, client);                                  \
		if (value == NULL)                                        \
			return VH_ERROR_NO_BUFFER;                        \
		*value = client->field;                                   \
		return 0;                                                 \
	}

FLAG(cellHttp_6869A969, cellHttp_0DE7B221, flag5, 0)
FLAG(cellHttp_C0C891E3, cellHttp_F764FD69, flag6, 0)
FLAG(cellHttpClientSetExternalCacheStatus, cellHttpClientGetExternalCacheStatus, flag8, vh_external_cache_initialized() ? 0 : ERROR_CACHE_NOT_INITIALIZED)
FLAG(cellHttpClientSetDiskCacheStatus, cellHttpClientGetDiskCacheStatus, flag9, vh_subsystem_initialized() ? 0 : ERROR_SUBSYSTEM_NOT_INITIALIZED)
/* gzip: Accept-Encoding gzip in new requests, and gzip bodies given decoded (transaction.c) */
FLAG(cellHttpClientSetGzipEncoding, cellHttpClientGetGzipEncoding, gzip, 0)
FLAG(cellHttp_E1DDBD73, cellHttp_15CD67D8, wait0, 0)
VALUE(cellHttp_9C902AB4, cellHttp_9823EB7D, size4, 16)
VALUE(cellHttp_104E9662, cellHttp_9FE6021B, size5, 8)
VALUE(cellHttp_561BE85B, cellHttp_923D3BD9, size6, 4)
VALUE(cellHttp_E9A53480, cellHttp_CCFB621A, size7, 8)
VALUE(cellHttp_9ED1C0B5, cellHttp_2A9BD960, size10, 0)
VALUE(cellHttp_42D600B1, cellHttp_D5C9C1DF, buffer1, 0)
VALUE(cellHttp_D5198360, cellHttp_415087D1, buffer2, 0)
VALUE(cellHttp_9619B961, cellHttp_44A86F38, buffer3, 0)

#define WITH_TRANSACTION(id, t)                         \
	if (!vh_initialized())                          \
		return VH_ERROR_NOT_INITIALIZED;        \
	VhTransaction *t = vh_transaction((void *)(id)); \
	if (t == NULL)                                  \
		return VH_ERROR_BAD_TRANS

/* The method, as the other string getters give theirs: *required with its NUL, given even when
 * the buffer is too small (0x80710006) */
int cellHttpTransactionGetMethod(CellHttpTransId id, char *method, size_t size, size_t *required)
{
	WITH_TRANSACTION(id, t);
	size_t need = strlen(t->method) + 1;
	if (method == NULL) {
		if (required == NULL)
			return VH_ERROR_NO_BUFFER;
		*required = need;
		return 0;
	}
	if (required != NULL)
		*required = need;
	if (size < need)
		return VH_ERROR_INSUFFICIENT;
	memcpy(method, t->method, need);
	return 0;
}

/* The credentials the transaction answers with: those it tried last, else its URI's; 0x80710028
 * without any. The NP sign-in plugin imports it. The buffers are 256 bytes, as the authentication
 * callback's */
int cellHttp_15C1FD80(CellHttpTransId id, char *username, char *password)
{
	WITH_TRANSACTION(id, t);
	if (username == NULL || password == NULL)
		return VH_ERROR_NO_BUFFER;
	const char *user = t->auth_username, *secret = t->auth_password;
	if (user[0] == '\0') {
		user = t->username != NULL ? t->username : "";
		secret = t->password != NULL ? t->password : "";
	}
	if (user[0] == '\0')
		return ERROR_CANNOT_AUTHENTICATE;
	size_t length = strlen(user), secret_length = strlen(secret);
	if (length > 255)
		length = 255;
	if (secret_length > 255)
		secret_length = 255;
	memcpy(username, user, length);
	username[length] = '\0';
	memcpy(password, secret, secret_length);
	password[secret_length] = '\0';
	return 0;
}

/* ---- a libhttp-wide value (1024 by default) ---- */

static uint32_t g_global = 1024;

int cellHttp_DE6475BF(uint32_t value)
{
	if (!vh_initialized())
		return VH_ERROR_NOT_INITIALIZED;
	g_global = value;
	return 0;
}

int cellHttp_F1374828(uint32_t *value)
{
	if (!vh_initialized())
		return VH_ERROR_NOT_INITIALIZED;
	if (value == NULL)
		return VH_ERROR_NO_BUFFER;
	*value = g_global;
	return 0;
}

/* ---- the disk cache ----
 * Sony's keeps responses in files under a directory (its _CACHE_), on a heap on the block
 * cellHttpInitDiskCache gets. vitals' answers its API as Sony's (the probe): 0x80710062 before
 * init, 0x80710061 a second time, 0x80710081 to close one not opened, its info with the block's
 * size and the values set; but keeps nothing, on disk or off it. cellHttpOpenDiskCache's arguments
 * past the first (a path) aren't worked out */

#define DISK_STATE_SIZE 18112u /* what Sony's state takes of the block */

static int g_disk, g_disk_open;
static uint32_t g_disk_size, g_disk_value;
static uint16_t g_disk_a, g_disk_b;
static uint8_t g_disk_flag;

int vh_subsystem_initialized(void)
{
	return g_disk;
}

int cellHttpInitDiskCache(void *block, uint32_t size)
{
	VH_LOG("cellHttpInitDiskCache %p %u (nothing is kept on disk)", block, (unsigned)size);
	(void)block;
	if (g_disk)
		return ERROR_SUBSYSTEM_ALREADY;
	g_disk = 1;
	g_disk_open = 0;
	g_disk_size = size;
	g_disk_value = 0;
	g_disk_a = g_disk_b = 0;
	g_disk_flag = 0;
	return 0;
}

int cellHttpEndDiskCache(void)
{
	if (!g_disk)
		return ERROR_SUBSYSTEM_NOT_INITIALIZED;
	g_disk = g_disk_open = 0;
	return 0;
}

int cellHttpOpenDiskCache(const char *path, uint32_t a, uint32_t b)
{
	VH_LOG("cellHttpOpenDiskCache %s", path != NULL ? path : "-");
	(void)a, (void)b;
	if (!g_disk)
		return ERROR_SUBSYSTEM_NOT_INITIALIZED;
	if (path == NULL)
		return VH_ERROR_NO_BUFFER;
	g_disk_open = 1;
	return 0;
}

int cellHttpCloseDiskCache(void)
{
	if (!g_disk)
		return ERROR_SUBSYSTEM_NOT_INITIALIZED;
	if (!g_disk_open)
		return (int)0x80710081;
	g_disk_open = 0;
	return 0;
}

int cellHttpFlushDiskCache(void)
{
	return g_disk ? 0 : ERROR_SUBSYSTEM_NOT_INITIALIZED;
}

/* Sony's layout: the block's size at 16, its heap's free size at 20, the value 4558639F set at
 * 24, the 16-bit ones at 48 (419C41D2) and 52 (ABC0EB57); vitals' fills 64 bytes */
int cellHttpGetDiskCacheInfo(uint32_t *info)
{
	if (!g_disk)
		return ERROR_SUBSYSTEM_NOT_INITIALIZED;
	if (info == NULL)
		return VH_ERROR_NO_BUFFER;
	memset(info, 0, 64);
	info[4] = g_disk_size;
	info[5] = g_disk_size > DISK_STATE_SIZE ? g_disk_size - DISK_STATE_SIZE : 0;
	info[6] = g_disk_value;
	info[12] = (uint32_t)g_disk_b << 16;
	info[13] = (uint32_t)g_disk_a << 16;
	return 0;
}

/* Each entry to callback: none */
int cellHttp_EBF753AB(int (*callback)(void *, void *), void *argument)
{
	(void)callback, (void)argument;
	return g_disk ? 0 : ERROR_SUBSYSTEM_NOT_INITIALIZED;
}

/* Before init only (0x80710061 after): what a directory's cache holds, removed in Sony's;
 * vitals' only checks the directory is there (cellFs's ENOENT, 0x80010006, when it isn't) */
int cellHttp_E9BE8A88(const char *path)
{
	if (g_disk)
		return ERROR_SUBSYSTEM_ALREADY;
	if (path == NULL)
		return VH_ERROR_NO_BUFFER;
	return vh_platform_stat(path);
}

int cellHttp_ABC0EB57(uint32_t value)
{
	if (!g_disk)
		return ERROR_SUBSYSTEM_NOT_INITIALIZED;
	g_disk_a = (uint16_t)value;
	return 0;
}

int cellHttp_419C41D2(uint32_t value)
{
	if (!g_disk)
		return ERROR_SUBSYSTEM_NOT_INITIALIZED;
	g_disk_b = (uint16_t)value;
	return 0;
}

int cellHttp_4558639F(uint32_t value)
{
	if (!g_disk)
		return ERROR_SUBSYSTEM_NOT_INITIALIZED;
	g_disk_value = value;
	return 0;
}

int cellHttp_E55FE254(void)
{
	if (!g_disk)
		return ERROR_SUBSYSTEM_NOT_INITIALIZED;
	g_disk_flag = 1;
	return 0;
}
