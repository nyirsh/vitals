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

void check_reached_host(const char *reached, char *host, size_t size)
{
	if (size == 0)
		return;
	const char *start = reached != NULL ? strstr(reached, "://") : NULL;
	start = start != NULL ? start + 3 : reached != NULL ? reached : "";
	size_t length = strcspn(start, ":/?#");
	if (length >= size)
		length = 0;
	memcpy(host, start, length);
	host[length] = '\0';
}

static int same_host(const char *a, const char *b)
{
	for (; *a != '\0' && *b != '\0'; ++a, ++b)
		if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
			return 0;
	return *a == *b;
}

void check_redirect_judge(CheckResult *r, int rc, const char *host, const char *expected)
{
	if (rc != 0 || r->error != 0 || r->http_code < 200 || r->http_code > 599) {
		r->state = CHECK_FAIL;
		if (r->message[0] == '\0') {
			if (r->http_code != 0)
				snprintf(r->message, sizeof(r->message), "Unexpected HTTP status %d", r->http_code);
			else
				snprintf(r->message, sizeof(r->message), "Request failed (0x%08X)", (unsigned)r->error);
		}
		return;
	}
	r->state = CHECK_PASS;
	if (host == NULL || host[0] == '\0' || expected == NULL)
		snprintf(r->message, sizeof(r->message), "Connected (HTTP %d); the host reached isn't known", r->http_code);
	else if (same_host(host, expected))
		snprintf(r->message, sizeof(r->message), "Reached %.96s (HTTP %d)", expected, r->http_code);
	else {
		r->state = CHECK_FAIL;
		snprintf(r->message, sizeof(r->message), "Answered by %.50s, not %.50s", host, expected);
	}
}

enum CheckDnsTarget check_dns_target(const char *target, unsigned char address[4])
{
	static const char block[] = "block";
	size_t length = strlen(target);
	if (length == sizeof(block) - 1) {
		size_t i = 0;
		while (i < length && tolower((unsigned char)target[i]) == block[i])
			++i;
		if (i == length)
			return CHECK_DNS_BLOCK;
	}
	/* Four decimal parts of at most 255, as the kernel plugin reads them */
	unsigned part = 0, parts = 0, digits = 0;
	for (size_t i = 0;; ++i) {
		char c = target[i];
		if (c >= '0' && c <= '9') {
			part = part * 10 + (unsigned)(c - '0');
			if (++digits > 3 || part > 255)
				return CHECK_DNS_NAME;
		} else if ((c == '.' || c == '\0') && digits) {
			if (parts == 4)
				return CHECK_DNS_NAME;
			address[parts++] = (unsigned char)part;
			part = digits = 0;
			if (c == '\0')
				return parts == 4 ? CHECK_DNS_ADDRESS : CHECK_DNS_NAME;
		} else
			return CHECK_DNS_NAME;
	}
}

static void print_addresses(const CheckLookup *lookup, char *text, size_t capacity)
{
	size_t used = 0;
	text[0] = '\0';
	for (unsigned i = 0; i < lookup->count && i < CHECK_DNS_ADDRESSES && used < capacity; ++i) {
		const unsigned char *a = lookup->addresses[i];
		int n = snprintf(text + used, capacity - used, "%s%u.%u.%u.%u", i ? ", " : "", a[0], a[1], a[2], a[3]);
		if (n < 0)
			break;
		used += (size_t)n;
	}
}

static int has_address(const CheckLookup *lookup, const unsigned char address[4])
{
	for (unsigned i = 0; i < lookup->count && i < CHECK_DNS_ADDRESSES; ++i)
		if (memcmp(lookup->addresses[i], address, 4) == 0)
			return 1;
	return 0;
}

static const char *lookup_error(int error)
{
	switch (error) {
	case CHECK_LOOKUP_NO_HOST: return "no such host";
	case CHECK_LOOKUP_TRY_AGAIN: return "no answer, try again";
	case CHECK_LOOKUP_FAILED: return "the resolver failed";
	case CHECK_LOOKUP_NO_ADDRESS: return "no address";
	default: return "the lookup failed";
	}
}

void check_dns_judge(const char *rule_target, const CheckLookup *answer, const CheckLookup *target, CheckResult *r)
{
	unsigned char address[4];
	char got[96];
	print_addresses(answer, got, sizeof(got));
	switch (check_dns_target(rule_target, address)) {
	case CHECK_DNS_BLOCK:
		/* The plugin answers "no such name"; a resolver may call that no address */
		if (!answer->found && (answer->error == CHECK_LOOKUP_NO_HOST || answer->error == CHECK_LOOKUP_NO_ADDRESS)) {
			r->state = CHECK_PASS;
			snprintf(r->message, sizeof(r->message), "Blocked (no such host)");
		} else if (answer->found) {
			r->state = CHECK_FAIL;
			snprintf(r->message, sizeof(r->message), "Not blocked: %s", got);
		} else {
			r->state = CHECK_FAIL;
			snprintf(r->message, sizeof(r->message), "Not blocked: %s", lookup_error(answer->error));
		}
		return;
	case CHECK_DNS_ADDRESS:
		if (answer->found && has_address(answer, address)) {
			r->state = CHECK_PASS;
			snprintf(r->message, sizeof(r->message), "Resolved to %s", got);
		} else {
			r->state = CHECK_FAIL;
			if (answer->found)
				snprintf(r->message, sizeof(r->message), "Resolved to %s instead", got);
			else
				snprintf(r->message, sizeof(r->message), "Not resolved: %s", lookup_error(answer->error));
		}
		return;
	case CHECK_DNS_NAME:
		break;
	}
	if (!target->found) {
		/* Renamed, the name gets the target's answer: none to compare with */
		r->state = CHECK_INFO;
		snprintf(r->message, sizeof(r->message), "Can't tell: the target doesn't resolve (%s)", lookup_error(target->error));
		return;
	}
	if (!answer->found) {
		r->state = CHECK_FAIL;
		snprintf(r->message, sizeof(r->message), "Not resolved: %s", lookup_error(answer->error));
		return;
	}
	/* Any address the two share: a server that rotates its addresses may give each lookup a
	 * different few */
	for (unsigned i = 0; i < answer->count && i < CHECK_DNS_ADDRESSES; ++i)
		if (has_address(target, answer->addresses[i])) {
			r->state = CHECK_PASS;
			snprintf(r->message, sizeof(r->message), "Resolved: %s", got);
			return;
		}
	r->state = CHECK_FAIL;
	snprintf(r->message, sizeof(r->message), "Resolved to %s, not the target's", got);
}

void check_badssl_judge(const CheckBadssl *test, CheckResult *r)
{
	int loaded = r->http_code > 0 && r->error == 0;
	if (!test->refuse) {
		r->state = loaded ? CHECK_PASS : CHECK_FAIL;
		if (loaded)
			snprintf(r->message, sizeof(r->message), "Loaded (HTTP %d)", r->http_code);
		else
			check_request_failure(r, "");
	} else if (loaded) {
		r->state = CHECK_FAIL;
		snprintf(r->message, sizeof(r->message), "Loaded (HTTP %d), should be refused", r->http_code);
	} else if (r->error == 0) {
		/* Neither a response nor an error: nothing refused it */
		r->state = CHECK_FAIL;
		snprintf(r->message, sizeof(r->message), "Not refused");
	} else if (check_request_unreachable(r)) {
		r->state = CHECK_FAIL;
		check_request_failure(r, "Inconclusive: ");
	} else {
		r->state = CHECK_PASS;
		check_request_failure(r, "Refused: ");
	}
}
