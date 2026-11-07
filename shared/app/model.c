/* The connection test's model, the same on every console: its endpoints, the badssl.com battery, how
 * far a run has got (for the test screen to follow it) and the TLS report's parser. Judging a request
 * is each console's (its check_model.c), as its HTTP library's errors are its own */

#include "model.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

const char *check_endpoint(unsigned test)
{
	static const char *urls[] = {"https://tls10.browserleaks.com/", "https://tls11.browserleaks.com/",
	                             "https://tls12.browserleaks.com/", "https://tls13.browserleaks.com/",
	                             "https://tls.browserleaks.com/tls?minify=1"};
	return test < CHECK_TEST_COUNT ? urls[test] : NULL;
}

const CheckBadssl *check_badssl(unsigned index)
{
	static const CheckBadssl tests[CHECK_BADSSL_COUNT] = {
	    {"badssl.com", "Valid certificate", 0},
	    {"sha256.badssl.com", "SHA-256 signature", 0},
	    {"ecc256.badssl.com", "ECDSA P-256 key", 0},
	    {"rsa2048.badssl.com", "RSA 2048 key", 0},
	    {"tls-v1-2.badssl.com:1012", "TLS 1.2 only", 0},
	    {"expired.badssl.com", "Expired", 1},
	    {"wrong.host.badssl.com", "Wrong host name", 1},
	    {"self-signed.badssl.com", "Self-signed", 1},
	    {"untrusted-root.badssl.com", "Untrusted root", 1},
	    {"rc4.badssl.com", "RC4 cipher", 1},
	    {"3des.badssl.com", "3DES cipher", 1},
	    {"dh512.badssl.com", "DH 512 key exchange", 1}};
	return index < CHECK_BADSSL_COUNT ? &tests[index] : NULL;
}

/* ---- the TLS report ---- */

/* Bounded JSON reader: no allocation, no dependence on any TLS implementation */
typedef struct {
	int start, end, next;
	char kind;
} Token;
typedef struct {
	const char *s;
	size_t n, pos;
	Token *t;
	int count;
} Json;
#define TOKEN_MAX 2048
static void ws(Json *j)
{
	while (j->pos < j->n && strchr(" \r\n\t", j->s[j->pos]))
		++j->pos;
}
static int value(Json *j, unsigned depth);
static int string(Json *j)
{
	if (j->pos == j->n || j->s[j->pos++] != '"')
		return -1;
	while (j->pos < j->n) {
		unsigned char c = (unsigned char)j->s[j->pos++];
		if (c == '"')
			return 0;
		if (c < 32)
			return -1;
		if (c == '\\') {
			if (j->pos == j->n)
				return -1;
			c = (unsigned char)j->s[j->pos++];
			if (c == 'u') {
				for (int x = 0; x < 4; ++x)
					if (j->pos == j->n || !isxdigit((unsigned char)j->s[j->pos++]))
						return -1;
			} else if (!strchr("\"\\/bfnrt", c))
				return -1;
		}
	}
	return -1;
}
static int value(Json *j, unsigned depth)
{
	ws(j);
	if (depth > 32 || j->count == TOKEN_MAX || j->pos == j->n)
		return -1;
	int id = j->count++;
	Token *t = &j->t[id];
	t->start = (int)j->pos;
	t->kind = j->s[j->pos];
	if (t->kind == '"') {
		if (string(j))
			return -1;
	} else if (t->kind == '{' || t->kind == '[') {
		char end = t->kind == '{' ? '}' : ']';
		++j->pos;
		ws(j);
		if (j->pos < j->n && j->s[j->pos] == end)
			++j->pos;
		else
			for (;;) {
				if (t->kind == '{') {
					ws(j);
					if (j->pos == j->n || j->s[j->pos] != '"' || value(j, depth + 1) < 0)
						return -1;
					ws(j);
					if (j->pos == j->n || j->s[j->pos++] != ':')
						return -1;
				}
				if (value(j, depth + 1) < 0)
					return -1;
				ws(j);
				if (j->pos == j->n)
					return -1;
				char c = j->s[j->pos++];
				if (c == end)
					break;
				if (c != ',')
					return -1;
			}
	} else if (strchr("tfn", t->kind)) {
		const char *word = t->kind == 't' ? "true" : t->kind == 'f' ? "false" : "null";
		size_t z = strlen(word);
		if (j->n - j->pos < z || memcmp(j->s + j->pos, word, z))
			return -1;
		j->pos += z;
	} else {
		if (j->s[j->pos] == '-')
			++j->pos;
		if (j->pos == j->n || !isdigit((unsigned char)j->s[j->pos]))
			return -1;
		if (j->s[j->pos] == '0')
			++j->pos;
		else
			while (j->pos < j->n && isdigit((unsigned char)j->s[j->pos]))
				++j->pos;
		if (j->pos < j->n && j->s[j->pos] == '.') {
			++j->pos;
			size_t begin = j->pos;
			while (j->pos < j->n && isdigit((unsigned char)j->s[j->pos]))
				++j->pos;
			if (j->pos == begin)
				return -1;
		}
		if (j->pos < j->n && strchr("eE", j->s[j->pos])) {
			++j->pos;
			if (j->pos < j->n && strchr("+-", j->s[j->pos]))
				++j->pos;
			size_t begin = j->pos;
			while (j->pos < j->n && isdigit((unsigned char)j->s[j->pos]))
				++j->pos;
			if (j->pos == begin)
				return -1;
		}
	}
	t->end = (int)j->pos;
	t->next = j->count;
	return id;
}
static int text(const Json *j, int i, char *out, size_t cap)
{
	if (i < 0 || j->t[i].kind != '"' || cap == 0)
		return -1;
	size_t n = 0;
	for (int p = j->t[i].start + 1; p < j->t[i].end - 1; ++p) {
		unsigned char c = (unsigned char)j->s[p];
		if (c == '\\') {
			c = (unsigned char)j->s[++p];
			if (c == 'u') {
				p += 4;
				c = '?';
			} else if (strchr("bfnrt", c))
				c = ' ';
		}
		if (n + 1 >= cap)
			return -1;
		out[n++] = (char)(c >= 32 && c <= 126 ? c : '?');
	}
	out[n] = '\0';
	return 0;
}
static int field(const Json *j, int obj, const char *key)
{
	if (obj < 0 || j->t[obj].kind != '{')
		return -1;
	int found = -1;
	for (int i = obj + 1; i < j->t[obj].next;) {
		char name[96];
		int v = i + 1;
		if (!text(j, i, name, sizeof(name)) && !strcmp(name, key)) {
			if (found >= 0)
				return -1; /* Reject ambiguous duplicate fields */
			found = v;
		}
		i = j->t[v].next;
	}
	return found;
}
static int number(const Json *j, int i, unsigned *out)
{
	if (i < 0 || j->t[i].kind < '0' || j->t[i].kind > '9')
		return -1;
	unsigned n = 0;
	for (int p = j->t[i].start; p < j->t[i].end; ++p) {
		char c = j->s[p];
		if (c < '0' || c > '9' || n > 6553)
			return -1;
		n = n * 10 + (unsigned)(c - '0');
		if (n > 65535)
			return -1;
	}
	*out = n;
	return 0;
}
static int named(const Json *j, int i, CheckNamed *out)
{
	return number(j, field(j, i, "id"), &out->id) || text(j, field(j, i, "name"), out->name, sizeof(out->name));
}
static void list(const Json *j, int i, CheckNamed *out, unsigned *count)
{
	if (i < 0 || j->t[i].kind != '[')
		return;
	for (int x = i + 1; x < j->t[i].next && *count < CHECK_LIST_MAX; x = j->t[x].next)
		if (!named(j, x, &out[*count]))
			++*count;
}
int check_parse_browserleaks(const char *b, size_t n, CheckHandshake *out)
{
	if (!b || !out || !n || n > CHECK_BODY_MAX || memchr(b, 0, n))
		return -1;
	/* Static, as only one test runs at a time and the tokens are too many for some workers' stacks;
	 * this parser is also tested natively */
	static Token tokens[TOKEN_MAX];
	Json j = {b, n, 0, tokens, 0};
	memset(out, 0, sizeof(*out));
	if (value(&j, 0) != 0)
		return -1;
	ws(&j);
	if (j.pos != n || tokens[0].kind != '{')
		return -1;
	int tls = field(&j, 0, "tls");
	if (named(&j, field(&j, tls, "selected_version"), &out->version) || out->version.id < 0x301 ||
	    out->version.id > 0x304 || named(&j, field(&j, tls, "cipher_suite"), &out->cipher))
		return -1;
	(void)named(&j, field(&j, tls, "key_exchange"), &out->group);
	(void)named(&j, field(&j, tls, "signature_scheme"), &out->signature);
	list(&j, field(&j, tls, "cipher_suites"), out->ciphers, &out->cipher_count);
	list(&j, field(&j, tls, "extensions"), out->extensions, &out->extension_count);
	(void)text(&j, field(&j, 0, "ja3_hash"), out->ja3, sizeof(out->ja3));
	(void)text(&j, field(&j, 0, "ja4"), out->ja4, sizeof(out->ja4));
	int ext = field(&j, tls, "extensions");
	if (ext >= 0 && j.t[ext].kind == '[')
		for (int x = ext + 1; x < j.t[ext].next; x = j.t[x].next) {
			unsigned id;
			if (number(&j, field(&j, x, "id"), &id))
				continue;
			int data = field(&j, x, "data");
			if (id == 10)
				list(&j, field(&j, data, "named_group_list"), out->groups, &out->group_count);
			if (id == 16) {
				int a = field(&j, data, "protocol_name_list");
				if (a >= 0 && j.t[a].kind == '[' && j.t[a].next > a + 1)
					(void)text(&j, a + 1, out->alpn, sizeof(out->alpn));
			}
		}
	out->valid = 1;
	return 0;
}

int check_follow(const CheckService *s, unsigned *item)
{
	/* The run goes tiles, report, badssl.com, redirects, DNS rules, each list in order: the last
	 * check that isn't waiting any more is how far it got. A check can start and end between two
	 * looks (a lookup the resolver has cached takes no time), so the running one alone isn't enough */
	for (unsigned i = s->dns_count < CHECK_DNS_MAX ? s->dns_count : CHECK_DNS_MAX; i-- > 0;)
		if (s->dns[i].result.state != CHECK_WAIT) {
			*item = i;
			return CHECK_FOLLOW_DNS;
		}
	for (unsigned i = s->redirect_count < CHECK_REDIRECT_MAX ? s->redirect_count : CHECK_REDIRECT_MAX; i-- > 0;)
		if (s->redirects[i].result.state != CHECK_WAIT) {
			*item = i;
			return CHECK_FOLLOW_REDIRECTS;
		}
	for (unsigned i = CHECK_BADSSL_COUNT; i-- > 0;)
		if (s->badssl[i].state != CHECK_WAIT) {
			*item = i;
			return CHECK_FOLLOW_CERTIFICATES;
		}
	*item = 0;
	if (s->connection.state != CHECK_WAIT)
		return CHECK_FOLLOW_CIPHERS;
	for (unsigned v = 0; v < 4; ++v)
		if (s->protocols[v].state != CHECK_WAIT)
			return CHECK_FOLLOW_REQUESTS;
	return -1;
}
