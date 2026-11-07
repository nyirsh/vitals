/* Mozilla's part of the CA store (shared/src/store_certs.c), as both consoles' apps write it: Mozilla's
 * certificates without Sony's, wherever their lines break, everything else as it is, and an earlier
 * version's merged custom certificates cut off */

#include "vitals/store_certs.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CERT(body) "-----BEGIN CERTIFICATE-----\n" body "\n-----END CERTIFICATE-----\n"

static const char mozilla[] = "##\n## Bundle of CA Root Certificates\n##\n\nRoot A\n======\n" CERT("QUFBQQ==")
                              "\nRoot B\n======\n" CERT("QkJCQg==");

static char out[8192];

static size_t store(const char *bundle, const char *sony, VitalsStoreFilter *f)
{
	size_t length = 99;
	assert(vitals_store_mozilla(bundle, strlen(bundle), sony, sony ? strlen(sony) : 0, out, sizeof(out) - 1, &length, f) == 0);
	out[length] = '\0';
	return length;
}

int main(void)
{
	VitalsStoreFilter f;

	/* No Sony CA in Mozilla's: the bundle as it is */
	assert(store(mozilla, NULL, &f) == strlen(mozilla) && strcmp(out, mozilla) == 0);
	assert(f.kept == 2 && f.sony == 0 && !f.cut_custom);
	assert(store(mozilla, CERT("Q0NDQw=="), &f) == strlen(mozilla) && f.kept == 2 && f.sony == 0);

	/* One of Sony's (its lines broken elsewhere, CRLF): left out, the rest as it is */
	const char *sony = "Sony's CA_LIST.cer\r\n-----BEGIN CERTIFICATE-----\r\nQkJC\r\nQg==\r\n-----END CERTIFICATE-----\r\n";
	store(mozilla, sony, &f);
	assert(f.kept == 1 && f.sony == 1);
	assert(strcmp(out, "##\n## Bundle of CA Root Certificates\n##\n\nRoot A\n======\n" CERT("QUFBQQ==")
	                   "\nRoot B\n======\n") == 0);

	/* An earlier version's file, the user's certificates merged after the marker: cut there */
	char earlier[4096];
	snprintf(earlier, sizeof(earlier), "%s# vitals: custom certificates (/dev_hdd0/vitals/custom-certs.pem)\n%s", mozilla,
	         CERT("RERERA=="));
	assert(store(earlier, NULL, &f) == strlen(mozilla) && strcmp(out, mozilla) == 0 && f.cut_custom && f.kept == 2);
	/* Written again, it stays the same */
	char first[4096];
	strcpy(first, out);
	assert(store(first, NULL, &f) == strlen(first) && strcmp(out, first) == 0 && !f.cut_custom);

	/* A broken block isn't a certificate, and is kept as it is (libssl skips it) */
	const char broken[] = "-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n" CERT("QkJCQg==");
	store(broken, sony, &f);
	assert(f.kept == 0 && f.sony == 1 && strcmp(out, "-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n") == 0);

	/* A bundle without its last newline gets one */
	const char cut[] = "Root A\n-----BEGIN CERTIFICATE-----\nQUFBQQ==\n-----END CERTIFICATE-----";
	store(cut, NULL, &f);
	assert(strcmp(out, "Root A\n-----BEGIN CERTIFICATE-----\nQUFBQQ==\n-----END CERTIFICATE-----\n") == 0 && f.kept == 1);

	/* Too small an output: -1, never past it; the bundle's length and one more is always enough */
	size_t length = 99;
	assert(vitals_store_mozilla(mozilla, strlen(mozilla), NULL, 0, out, strlen(mozilla) - 1, &length, &f) < 0 && length == 0);
	const char unended[] = "x\n-----BEGIN CERTIFICATE-----\nQUFBQQ==\n-----END CERTIFICATE-----";
	assert(vitals_store_mozilla(unended, strlen(unended), NULL, 0, out, strlen(unended) + 1, &length, &f) == 0);

	/* Nothing left but Sony's: empty, a part that adds nothing */
	assert(store(CERT("QkJCQg=="), sony, &f) == 0 && f.sony == 1 && f.kept == 0);
	assert(store("", NULL, &f) == 0);

	/* A marker only counts at a line's start */
	const char quoted[] = "text # vitals: custom certificates\n" CERT("QUFBQQ==");
	assert(store(quoted, NULL, &f) == strlen(quoted) && !f.cut_custom);

	puts("Mozilla's part of the store: Sony's left out wherever their lines break, earlier merges cut, the rest as it is PASS");
	return 0;
}
