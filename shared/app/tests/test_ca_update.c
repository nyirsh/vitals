/* Mozilla's part of the certificate store (shared/app/ca_update.c) on this machine's Mbed TLS, from
 * curl's bundle as the app carries it (VITALS_TEST_BUNDLE) and copies of it changed: every
 * certificate Mbed TLS reads kept, one it can't left out, Sony's left out, and what isn't a bundle
 * refused with nothing made. Built in both consoles' tests */

#include "ca_update.h"
#include "download.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef VITALS_TEST_CRYPTO_PLATFORM
#include "crypto_platform.h"
#endif

/* The console's: on the PS3's tests the host's mutexes for its Mbed TLS (tests/host), else nothing */
int console_crypto_start(void)
{
#ifdef VITALS_TEST_CRYPTO_PLATFORM
	static int ready;
	if (!ready && vitals_crypto_platform_init() == 0)
		ready = 1;
	return ready ? 0 : -1;
#else
	return 0;
#endif
}

/* The download, as the test scripts it: the body, or a status and curl's code */
static const char *served;
static size_t served_length;
static long served_status;
static int served_error, downloads;
static const char *expected_trust;

int vitals_download(const VitalsDownload *request, VitalsDownloaded *result)
{
	++downloads;
	assert(strcmp(request->url, VITALS_CA_UPDATE_URL) == 0 && request->ca == expected_trust);
	assert(request->limit == VITALS_CA_BUNDLE_LIMIT && strcmp(request->user_agent, "vitals-test") == 0);
	memset(result, 0, sizeof(*result));
	if (served == NULL) {
		result->status = served_status;
		result->error = served_error;
		return -1;
	}
	result->data = malloc(served_length + 1);
	memcpy(result->data, served, served_length);
	result->data[served_length] = '\0';
	result->size = served_length;
	result->status = 200;
	return 0;
}

void vitals_download_free(VitalsDownloaded *result)
{
	free(result->data);
	result->data = NULL;
}

const char *vitals_download_error(int error)
{
	(void)error;
	return "Couldn't resolve host name";
}

static char *read_all(const char *path, size_t *length)
{
	FILE *file = fopen(path, "rb");
	assert(file != NULL);
	assert(fseek(file, 0, SEEK_END) == 0);
	long size = ftell(file);
	assert(size > 0 && fseek(file, 0, SEEK_SET) == 0);
	char *data = malloc((size_t)size + 1);
	assert(data != NULL && fread(data, 1, (size_t)size, file) == (size_t)size);
	data[size] = '\0';
	fclose(file);
	*length = (size_t)size;
	return data;
}

static const char begin[] = "-----BEGIN CERTIFICATE-----", end[] = "-----END CERTIFICATE-----";

/* The text of the nth certificate block (from 0), its end line included */
static const char *block(const char *bundle, unsigned n, size_t *length)
{
	const char *at = strstr(bundle, begin);
	for (unsigned i = 0; i < n && at != NULL; ++i)
		at = strstr(at + 1, begin);
	assert(at != NULL);
	*length = (size_t)(strstr(at, end) + sizeof(end) - 1 - at);
	return at;
}

static unsigned count(const char *text, size_t length)
{
	unsigned n = 0;
	for (const char *at = strstr(text, begin); at != NULL && at < text + length; at = strstr(at + 1, begin))
		++n;
	return n;
}

static char notes[4096];
static void note(const char *line)
{
	strncat(notes, line, sizeof(notes) - strlen(notes) - 2);
	strcat(notes, "\n");
}

int main(void)
{
	size_t length;
	char *bundle = read_all(VITALS_TEST_BUNDLE, &length);
	unsigned total = count(bundle, length);
	assert(total >= VITALS_CA_MINIMUM);
	VitalsCaBundle out;

	/* curl's bundle as the app carries it: every certificate read and kept, with its date */
	assert(vitals_ca_prepare(bundle, length, NULL, 0, &out, note) == 0);
	assert(out.read == total && out.unreadable == 0 && out.filter.kept == total && out.filter.sony == 0);
	assert(count(out.data, out.size) == total && out.dated[0] != '\0');
	assert(strstr(out.data, "Bundle of CA Root Certificates") != NULL);
	vitals_ca_free(&out);

	/* Sony's list has the first one: it's left out */
	size_t first_length;
	const char *first = block(bundle, 0, &first_length);
	char *sony = malloc(first_length + 2);
	memcpy(sony, first, first_length);
	strcpy(sony + first_length, "\n");
	assert(vitals_ca_prepare(bundle, length, sony, first_length + 1, &out, NULL) == 0);
	assert(out.filter.sony == 1 && out.filter.kept == total - 1 && count(out.data, out.size) == total - 1);
	assert(strstr(out.data, sony) == NULL);
	vitals_ca_free(&out);
	free(sony);

	/* One Mbed TLS can't read (whole PEM lines, its DER broken): left out, the rest kept */
	char *broken = malloc(length + 1);
	memcpy(broken, bundle, length + 1);
	size_t third_length;
	char *third = broken + (block(bundle, 2, &third_length) - bundle);
	char *body = strchr(third, '\n') + 1;
	memset(body, 'A', 40);
	notes[0] = '\0';
	assert(vitals_ca_prepare(broken, length, NULL, 0, &out, note) == 0);
	assert(out.read == total - 1 && out.unreadable == 1 && count(out.data, out.size) == total - 1);
	assert(strstr(out.data, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") == NULL);
	assert(strstr(notes, "Left out 1 certificates Mbed TLS can't read") != NULL);
	vitals_ca_free(&out);

	/* Not a bundle: no heading, a block without its end, too few certificates, a NUL inside,
	 * nothing; none makes anything */
	memcpy(broken, bundle, length + 1);
	char *heading = strstr(broken, "Bundle of CA Root Certificates");
	memcpy(heading, "Bundle of something else, really", 30);
	assert(vitals_ca_prepare(broken, length, NULL, 0, &out, NULL) == -1 && out.data == NULL);
	memcpy(broken, bundle, length + 1);
	char *close = strstr(broken + (block(bundle, 5, &third_length) - bundle), end);
	memcpy(close, "-----ENDS CERTIFICATE-----", 25);
	assert(vitals_ca_prepare(broken, length, NULL, 0, &out, NULL) == -1 && out.data == NULL);
	size_t cut;
	const char *last_kept = block(bundle, VITALS_CA_MINIMUM - 2, &cut);
	size_t few = (size_t)(last_kept + cut - bundle);
	notes[0] = '\0';
	assert(vitals_ca_prepare(bundle, few, NULL, 0, &out, note) == -1 && out.data == NULL);
	assert(strstr(notes, "only 99 certificates") != NULL);
	memcpy(broken, bundle, length + 1);
	broken[length / 2] = '\0';
	assert(vitals_ca_prepare(broken, length, NULL, 0, &out, NULL) == -1);
	assert(vitals_ca_prepare("", 0, NULL, 0, &out, NULL) == -1);
	free(broken);

	/* The download: trusting only the bundle the app carries, curl's taken; a failure, or what isn't
	 * a bundle, makes nothing and says why */
	const char trust[] = "the app's bundle";
	expected_trust = trust;
	served = bundle;
	served_length = length;
	notes[0] = '\0';
	assert(vitals_ca_download(trust, sizeof(trust), "vitals-test", NULL, NULL, 0, &out, note) == 0);
	assert(out.read == total && count(out.data, out.size) == total && downloads == 1);
	assert(strstr(notes, "Downloading " VITALS_CA_UPDATE_URL) != NULL && strstr(notes, "Received ") != NULL);
	vitals_ca_free(&out);
	served = NULL;
	served_status = 503;
	notes[0] = '\0';
	assert(vitals_ca_download(trust, sizeof(trust), "vitals-test", NULL, NULL, 0, &out, note) == -1 && out.data == NULL);
	assert(strstr(notes, "The server answered HTTP 503") != NULL);
	served_status = 0;
	served_error = 6;
	notes[0] = '\0';
	assert(vitals_ca_download(trust, sizeof(trust), "vitals-test", NULL, NULL, 0, &out, note) == -1 && out.data == NULL);
	assert(strstr(notes, "The download failed (6): Couldn't resolve host name") != NULL);
	served = "<html>not a bundle</html>";
	served_length = strlen(served);
	assert(vitals_ca_download(trust, sizeof(trust), "vitals-test", NULL, NULL, 0, &out, NULL) == -1 && out.data == NULL);
	free(bundle);

	puts("certificate update: curl's bundle, Sony's left out, unreadable left out, not a bundle refused, the download PASS");
	return 0;
}
