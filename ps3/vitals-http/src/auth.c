/* HTTP authentication, as the Vita's vitals-http answers it (its request.c's try_auth): a 401 is
 * answered again with credentials, Basic or Digest as the server asks, and nothing is kept between
 * requests. Sony's PS3 libhttp also keeps an authentication cache and sends what it holds before a
 * 401; vitals' keeps none, so the game's callback is asked at every 401. What
 * the probe showed of Sony's is kept (tests/http-probe/source/auth.c):
 * - only with automatic authentication on (the default); else the 401 is the game's;
 * - the URI's credentials first, never before a 401; then the game's callback, with the
 *   credentials tried last in its buffers (256 bytes each);
 * - a negative answer from the callback, or nothing to answer with, fails the request with
 *   0x80710021; after 6 answers from the callback, 0x80710019;
 * - the transaction-state callback gets state 8 before each answer is made.
 * Digest is MD5 or MD5-sess, with qop auth or none: the body isn't kept for auth-int */

#include "vh.h"

#include <cell/http.h>
#include <stdio.h>
#include <string.h>

#define ERROR_TOO_MANY_AUTHS ((int)0x80710019)
#define ERROR_CANNOT_AUTHENTICATE ((int)0x80710021)
#define MAX_CALLBACK_ANSWERS 6
#define CREDENTIAL_SIZE 256

/* The cache's entry count, which the API keeps though nothing is cached */
static uint32_t g_entry_max = 4;

/* ---- challenges ---- */

static int has_token(const char *list, const char *token)
{
	size_t length = strlen(token);
	for (const char *at = list; *at != '\0';) {
		while (*at == ' ' || *at == ',' || *at == '\t')
			++at;
		const char *end = at;
		while (*end != '\0' && *end != ',' && *end != ' ')
			++end;
		if ((size_t)(end - at) == length) {
			size_t i = 0;
			while (i < length && ((at[i] | 32) == (token[i] | 32)))
				++i;
			if (i == length)
				return 1;
		}
		at = end;
	}
	return 0;
}

/* A parameter of a challenge (name=value or name="value", comma-separated), into out */
static int challenge_parameter(const char *value, const char *name, char *out, size_t capacity)
{
	size_t name_length = strlen(name), length = strlen(value);
	for (size_t at = 0; at < length;) {
		while (at < length && (value[at] == ' ' || value[at] == ',' || value[at] == '\t'))
			++at;
		size_t key = at;
		while (at < length && value[at] != '=' && value[at] != ',' && value[at] != ' ')
			++at;
		size_t key_end = at;
		while (at < length && value[at] == ' ')
			++at;
		if (at >= length || value[at] != '=')
			continue;
		++at;
		while (at < length && value[at] == ' ')
			++at;
		size_t start = at, end;
		if (at < length && value[at] == '"') {
			start = ++at;
			while (at < length && value[at] != '"')
				at += value[at] == '\\' && at + 1 < length ? 2u : 1u;
			end = at < length ? at++ : at;
		} else {
			while (at < length && value[at] != ',')
				++at;
			end = at;
			while (end > start && value[end - 1] == ' ')
				--end;
		}
		if (key_end - key == name_length) {
			size_t i = 0;
			while (i < name_length && ((value[key + i] | 32) == (name[i] | 32)))
				++i;
			if (i == name_length) {
				size_t size = end - start < capacity - 1 ? end - start : capacity - 1;
				memcpy(out, value + start, size);
				out[size] = '\0';
				return 1;
			}
		}
	}
	out[0] = '\0';
	return 0;
}

/* MD5 of the parts joined, as lowercase hex */
static void md5_hex(const char *const parts[], size_t count, char out[33])
{
	char joined[1100];
	size_t used = 0;
	for (size_t i = 0; i < count; ++i) {
		size_t length = strlen(parts[i]);
		if (used + length > sizeof(joined))
			length = sizeof(joined) - used;
		memcpy(joined + used, parts[i], length);
		used += length;
	}
	unsigned char digest[16];
	vh_md5(joined, used, digest);
	static const char hex[] = "0123456789abcdef";
	for (int i = 0; i < 16; ++i) {
		out[i * 2] = hex[digest[i] >> 4];
		out[i * 2 + 1] = hex[digest[i] & 15];
	}
	out[32] = '\0';
}

/* The Digest answer (RFC 2617) into out: 0, or -1 for a challenge it can't answer */
static int digest_header(const VhTransaction *t, const char *challenge, const char *username, const char *password,
                         char *out, size_t capacity)
{
	char realm[256], nonce[256], opaque[256], algorithm[32], qops[64];
	char ha1[33], ha2[33], response[33], cnonce[33];
	static unsigned counter;
	challenge_parameter(challenge, "realm", realm, sizeof(realm));
	if (!challenge_parameter(challenge, "nonce", nonce, sizeof(nonce)))
		return -1;
	int has_opaque = challenge_parameter(challenge, "opaque", opaque, sizeof(opaque));
	int has_algorithm = challenge_parameter(challenge, "algorithm", algorithm, sizeof(algorithm));
	int session = has_algorithm && vh_equal_nocase(algorithm, "MD5-sess");
	if (has_algorithm && !session && !vh_equal_nocase(algorithm, "MD5"))
		return -1;
	const char *qop = NULL;
	if (challenge_parameter(challenge, "qop", qops, sizeof(qops))) {
		if (!has_token(qops, "auth"))
			return -1;
		qop = "auth";
	}
	/* The client nonce: not a secret, only different each time */
	char seed[64];
	snprintf(seed, sizeof(seed), "%ld:%p:%u", (long)vh_platform_now(), (const void *)t, ++counter);
	const char *seed_parts[] = {seed};
	md5_hex(seed_parts, 1, cnonce);
	cnonce[16] = '\0';
	const char *ha1_parts[] = {username, ":", realm, ":", password};
	md5_hex(ha1_parts, 5, ha1);
	if (session) {
		const char *session_parts[] = {ha1, ":", nonce, ":", cnonce};
		md5_hex(session_parts, 5, ha1);
	}
	const char *uri = t->path[0] != '\0' ? t->path : "/";
	const char *ha2_parts[] = {t->method, ":", uri};
	md5_hex(ha2_parts, 3, ha2);
	if (qop != NULL) {
		const char *parts[] = {ha1, ":", nonce, ":", "00000001", ":", cnonce, ":", qop, ":", ha2};
		md5_hex(parts, 11, response);
	} else {
		const char *parts[] = {ha1, ":", nonce, ":", ha2};
		md5_hex(parts, 5, response);
	}
	int written = snprintf(out, capacity, "Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\"",
	                       username, realm, nonce, uri, response);
	/* Only MD5-sess is named, as Sony's leaves MD5 out */
	if (written > 0 && (size_t)written < capacity && session)
		written += snprintf(out + written, capacity - (size_t)written, ", algorithm=%s", algorithm);
	if (written > 0 && (size_t)written < capacity && qop != NULL)
		written += snprintf(out + written, capacity - (size_t)written, ", qop=%s, nc=00000001, cnonce=\"%s\"", qop, cnonce);
	/* No opaque: Sony's doesn't send it back */
	(void)has_opaque;
	return written > 0 && (size_t)written < capacity ? 0 : -1;
}

/* ---- answering a 401 ---- */

int vh_auth_answer(VhTransaction *t, const char *challenge)
{
	VhClient *client = t->client;
	int digest = vh_equal_nocase_prefix(challenge, "Digest") && (challenge[6] == '\0' || challenge[6] == ' ');
	int basic = vh_equal_nocase_prefix(challenge, "Basic") && (challenge[5] == '\0' || challenge[5] == ' ');
	if (!digest && !basic)
		return ERROR_CANNOT_AUTHENTICATE;
	const char *parameters = challenge + (digest ? 6 : 5);
	char realm[256];
	challenge_parameter(parameters, "realm", realm, sizeof(realm));
	char username[CREDENTIAL_SIZE], password[CREDENTIAL_SIZE];
	if (!t->auth_tried_uri && t->username != NULL && t->username[0] != '\0') {
		/* The URI's credentials, once */
		t->auth_tried_uri = 1;
		snprintf(username, sizeof(username), "%s", t->username);
		snprintf(password, sizeof(password), "%s", t->password != NULL ? t->password : "");
		VITALS_VERBOSE("transaction %p: %s for \"%s\" with the URI's credentials", (void *)t, digest ? "Digest" : "Basic", realm);
		vh_notify_state(t, CELL_HTTP_TRANSACTION_STATE_SETTING_AUTHENTICATION);
	} else {
		if (client->callbacks[VH_CALLBACK_AUTHENTICATION] == NULL) {
			VITALS_LOG("transaction %p: %s for \"%s\", nothing to answer with", (void *)t, digest ? "Digest" : "Basic", realm);
			return ERROR_CANNOT_AUTHENTICATE;
		}
		if (t->auth_answers == MAX_CALLBACK_ANSWERS)
			return ERROR_TOO_MANY_AUTHS;
		++t->auth_answers;
		vh_notify_state(t, CELL_HTTP_TRANSACTION_STATE_SETTING_AUTHENTICATION);
		snprintf(username, sizeof(username), "%s", t->auth_username);
		snprintf(password, sizeof(password), "%s", t->auth_password);
		bool save = false;
		CellHttpUri uri;
		memset(&uri, 0, sizeof(uri));
		uri.scheme = t->scheme, uri.hostname = t->host, uri.username = t->username;
		uri.password = t->password, uri.path = t->path, uri.port = t->port;
		CellHttpAuthenticationCallback callback = (CellHttpAuthenticationCallback)client->callbacks[VH_CALLBACK_AUTHENTICATION];
		int answer = callback((CellHttpTransId)t, realm, &uri, username, password, &save,
		                      client->callback_arguments[VH_CALLBACK_AUTHENTICATION]);
		username[sizeof(username) - 1] = password[sizeof(password) - 1] = '\0';
		VITALS_VERBOSE("transaction %p: %s for \"%s\", the game's callback said %d", (void *)t, digest ? "Digest" : "Basic", realm,
		       answer);
		if (answer < 0)
			return ERROR_CANNOT_AUTHENTICATE;
	}
	snprintf(t->auth_username, sizeof(t->auth_username), "%s", username);
	snprintf(t->auth_password, sizeof(t->auth_password), "%s", password);
	char header[1024];
	if (digest) {
		if (digest_header(t, parameters, username, password, header, sizeof(header)) < 0) {
			VITALS_LOG("transaction %p: a Digest challenge vitals can't answer", (void *)t);
			return ERROR_CANNOT_AUTHENTICATE;
		}
	} else {
		char credentials[CREDENTIAL_SIZE * 2 + 1];
		int length = snprintf(credentials, sizeof(credentials), "%s:%s", username, password);
		memcpy(header, "Basic ", 6);
		int encoded = cellHttpUtilBase64Encoder(header + 6, credentials, (size_t)length);
		header[6 + (encoded > 0 ? encoded : 0)] = '\0';
	}
	return vh_headers_set(&t->request, "Authorization", header);
}

/* ---- the cache's API: nothing is cached (see above) ---- */

int cellHttpAuthCacheFlush(void)
{
	VITALS_LOG("cellHttpAuthCacheFlush");
	return vh_initialized() ? 0 : VH_ERROR_NOT_INITIALIZED;
}

int cellHttpAuthCacheGetEntryMax(uint32_t *max)
{
	if (!vh_initialized())
		return VH_ERROR_NOT_INITIALIZED;
	if (max == NULL)
		return VH_ERROR_NO_BUFFER;
	*max = g_entry_max;
	return 0;
}

int cellHttpAuthCacheSetEntryMax(uint32_t max)
{
	VITALS_LOG("cellHttpAuthCacheSetEntryMax %u", (unsigned)max);
	if (!vh_initialized())
		return VH_ERROR_NOT_INITIALIZED;
	g_entry_max = max;
	return 0;
}

/* An empty cache's export: nothing */
int cellHttpAuthCacheExport(void *buffer, size_t size, size_t *exported)
{
	(void)buffer, (void)size;
	if (!vh_initialized())
		return VH_ERROR_NOT_INITIALIZED;
	if (exported != NULL)
		*exported = 0;
	return 0;
}

int cellHttpAuthCacheImport(const void *buffer, size_t size)
{
	(void)size;
	if (!vh_initialized())
		return VH_ERROR_NOT_INITIALIZED;
	if (buffer == NULL)
		return VH_ERROR_NO_BUFFER;
	return 0;
}
