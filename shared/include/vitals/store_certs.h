#ifndef VITALS_STORE_CERTS_H
#define VITALS_STORE_CERTS_H

#include <stddef.h>

/* Mozilla's part of the CA store, the same on both consoles: Mozilla's bundle without the
 * certificates Sony's list already has (the Vita's sony-certs.pem, the PS3's CAs in flash), which
 * each console's app writes at an install and a certificate update; the user's custom-certs.pem is
 * read after it as it is, so nothing of the user's is written here. Plain C on the PEM text, so the
 * host tests run it as it is: a certificate is Sony's when the base64 between its lines is, wherever
 * the lines break, and everything else in Mozilla's bundle (its header, each root's title) is kept */

/* What earlier PS3 versions put before the user's certificates when they merged them into the
 * bundle: the bundle is cut there */
#define VITALS_EARLIER_CUSTOM_MARKER "# vitals: custom certificates"

typedef struct {
	/* Mozilla's certificates kept, those left out as Sony's, and whether an earlier version's
	 * merged custom certificates were cut off */
	unsigned kept, sony, cut_custom;
} VitalsStoreFilter;

/* bundle up to an earlier merge's marker, without the whole certificate blocks that sony (Sony's
 * list as PEM text, or NULL) holds; all else, comments included, as it is, ended with a line break
 * unless empty. 0 with *length what was written to out, or -1 when out (capacity bytes) is too
 * small: bundle_length + 1 is always enough */
int vitals_store_mozilla(const char *bundle, size_t bundle_length, const char *sony, size_t sony_length,
                         char *out, size_t capacity, size_t *length, VitalsStoreFilter *filter);

#endif
