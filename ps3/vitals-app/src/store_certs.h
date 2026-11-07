#ifndef VITALS_APP_STORE_CERTS_H
#define VITALS_APP_STORE_CERTS_H

#include <stddef.h>

#include "vitals_paths.h"

/* Mozilla's part of the CA store (VITALS_BUNDLE), as on the Vita: Mozilla's bundle without the
 * certificates Sony's CAs already are (common/sony_cas.h, read from flash), which the app writes at
 * every install and certificate update. libssl reads the user's custom-certs.pem itself, after it,
 * so nothing of the user's is written here. Plain C on the PEM text, so the host tests run it as it
 * is: a certificate is Sony's when the base64 between its lines is, wherever the lines break */

/* What earlier versions put before the user's certificates when they merged them into the bundle:
 * the bundle is cut there */
#define VITALS_EARLIER_CUSTOM_MARKER "# vitals: custom certificates"

typedef struct {
	/* Mozilla's certificates kept, those left out as Sony's, and whether an earlier version's
	 * merged custom certificates were cut off */
	unsigned kept, sony, cut_custom;
} VitalsStoreFilter;

/* bundle (Mozilla's, or an earlier version's file) up to an earlier merge's marker, without the
 * whole certificate blocks that sony (Sony's CAs, PEM text, may be NULL) holds; all else, comments
 * included, as it is. Returns the length written to out, or 0 when out is too small */
size_t vitals_store_mozilla(const char *bundle, size_t bundle_length, const char *sony, size_t sony_length,
                            char *out, size_t capacity, VitalsStoreFilter *filter);

#endif
