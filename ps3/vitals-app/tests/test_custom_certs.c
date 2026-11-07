/* The user's certificates after Mozilla's (src/custom_certs.c), as the Vita's
 * test_certificate_update.py checks its merge: added after, once each, a broken file never in the
 * way, and an earlier merge replaced rather than added to */

#include "custom_certs.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CERT(body) "-----BEGIN CERTIFICATE-----\n" body "\n-----END CERTIFICATE-----\n"

static const char mozilla[] = "##\n## Bundle of CA Root Certificates\n##\n\nRoot A\n======\n" CERT("QUFBQQ==") "\nRoot B\n======\n" CERT("QkJCQg==");

static char out[8192];

static size_t merge(const char *bundle, const char *custom, VitalsCustomMerge *m)
{
	size_t length = vitals_bundle_merge(bundle, strlen(bundle), custom, custom ? strlen(custom) : 0, out, sizeof(out) - 1, m);
	out[length] = '\0';
	return length;
}

static unsigned count(const char *text, const char *needle)
{
	unsigned n = 0;
	for (const char *at = strstr(text, needle); at != NULL; at = strstr(at + 1, needle))
		++n;
	return n;
}

int main(void)
{
	VitalsCustomMerge m;

	/* No file, or nothing in it: the bundle as it is, no marker */
	assert(merge(mozilla, NULL, &m) == strlen(mozilla) && strcmp(out, mozilla) == 0 && m.added == 0);
	assert(merge(mozilla, "# nothing yet\n", &m) == strlen(mozilla) && m.added == 0 && m.skipped == 0);

	/* Two of the user's, after Mozilla's under the marker, comments and text around them left out */
	const char *custom = "# my server\n" CERT("Q0NDQw==") "some words\n" CERT("RERE\nRA==");
	size_t length = merge(mozilla, custom, &m);
	assert(length != 0 && m.added == 2 && m.duplicates == 0 && m.skipped == 0);
	assert(strncmp(out, mozilla, strlen(mozilla)) == 0);
	assert(strcmp(out + strlen(mozilla), VITALS_CUSTOM_MARKER CERT("Q0NDQw==") CERT("RERE\nRA==")) == 0);
	assert(strstr(out, "my server") == NULL && strstr(out, "some words") == NULL);

	/* Merging again over the merged bundle: the same, not the user's twice */
	char first[8192];
	memcpy(first, out, length + 1);
	assert(merge(first, custom, &m) == length && strcmp(out, first) == 0 && m.added == 2);
	assert(count(out, "# vitals: custom certificates") == 1);

	/* The file gone: the user's earlier ones go too */
	assert(merge(first, NULL, &m) == strlen(mozilla) && strcmp(out, mozilla) == 0);

	/* One already in Mozilla's (its lines broken elsewhere), one twice in the file: each added once */
	const char *repeats = CERT("QUFB\nQQ==") CERT("Q0NDQw==") CERT("Q0ND\r\nQw==");
	merge(mozilla, repeats, &m);
	assert(m.added == 1 && m.duplicates == 2 && count(out, "Q0NDQw==") == 1 && count(out, "QUFBQQ==") == 1);

	/* Broken blocks are skipped and never stop the rest: no end, not base64, text after END, empty */
	const char *broken = "-----BEGIN CERTIFICATE-----\nRUVFRQ==\n" CERT("not base64!") CERT("RkZGRg==")
	                     "-----BEGIN CERTIFICATE-----\nR0dHRw==\n-----END CERTIFICATE----- extra\n" CERT("");
	merge(mozilla, broken, &m);
	assert(m.added == 1 && m.skipped == 4 && strstr(out, "RkZGRg==") != NULL && strstr(out, "RUVFRQ==") == NULL);

	/* A bundle without its last newline, and a file without one either */
	const char cut[] = "Root A\n" "-----BEGIN CERTIFICATE-----\nQUFBQQ==\n-----END CERTIFICATE-----";
	merge(cut, "-----BEGIN CERTIFICATE-----\nSElISQ==\n-----END CERTIFICATE-----", &m);
	assert(m.added == 1 && strcmp(out, "Root A\n-----BEGIN CERTIFICATE-----\nQUFBQQ==\n-----END CERTIFICATE-----\n" VITALS_CUSTOM_MARKER
	                                    CERT("SElISQ==")) == 0);

	/* Too small an output: 0, never past it */
	assert(vitals_bundle_merge(mozilla, strlen(mozilla), custom, strlen(custom), out, strlen(mozilla) + 10, &m) == 0);

	/* A marker only counts at a line's start */
	const char quoted[] = "text # vitals: custom certificates\n" CERT("QUFBQQ==");
	assert(vitals_bundle_own_length(quoted, strlen(quoted)) == strlen(quoted));

	puts("custom_certs: merged after Mozilla's, once each, broken blocks skipped, an earlier merge replaced PASS");
	return 0;
}
