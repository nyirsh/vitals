#ifndef VITALS_APP_CUSTOM_CERTS_H
#define VITALS_APP_CUSTOM_CERTS_H

#include <stddef.h>

#include "vitals_paths.h"

/* The user's own certificates (/dev_hdd0/vitals/custom-certs.pem, for example their servers'
 * self-signed ones), added after Mozilla's in system/cacert.pem whenever the app installs, updates,
 * reinstalls or updates the certificates, as the Vita's custom-certs.pem. libssl reads every
 * certificate in cacert.pem and skips any that doesn't parse, so the merge works on the PEM text
 * alone: a certificate already there is added once, and a block that isn't a whole certificate is
 * left out */

/* The line the user's certificates come after, which the next merge cuts the bundle at */
#define VITALS_CUSTOM_MARKER "# vitals: custom certificates (" VITALS_CUSTOM_CERTS ")\n"

typedef struct {
	unsigned added, duplicates, skipped;
} VitalsCustomMerge;

/* How much of bundle is its own: everything before an earlier merge's marker line */
size_t vitals_bundle_own_length(const char *bundle, size_t length);

/* bundle's own part, then, when custom has any certificate it doesn't, the marker and each such
 * certificate (custom may be NULL). Returns the merged length, or 0 when out is too small */
size_t vitals_bundle_merge(const char *bundle, size_t bundle_length, const char *custom, size_t custom_length,
                           char *out, size_t capacity, VitalsCustomMerge *merge);

#endif
