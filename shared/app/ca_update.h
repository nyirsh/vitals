#ifndef VITALS_APP_CA_UPDATE_H
#define VITALS_APP_CA_UPDATE_H

#include <stddef.h>

#include "console.h"
#include "vitals/store_certs.h"

/* Mozilla's part of vitals' certificate store, the same on both consoles (ca_update.c): curl's copy
 * of Mozilla's bundle, checked, each certificate read with Mbed TLS (what vitals' libssl reads the
 * store with, so one it can't read is left out: it couldn't be used), and without what Sony's list
 * already has (store_certs.h). The console reads its Sony list and the bundle the app carries, and
 * writes the result */

#define VITALS_CA_UPDATE_URL "https://curl.se/ca/cacert.pem"
/* The largest bundle taken; curl's is about 230 KB */
#define VITALS_CA_BUNDLE_LIMIT (1024u * 1024u)
/* A bundle with fewer certificates Mbed TLS reads isn't taken */
#define VITALS_CA_MINIMUM 100u

typedef struct {
	/* mozilla-certs.pem's text, malloc's (vitals_ca_free) */
	char *data;
	size_t size;
	/* The bundle's certificates Mbed TLS read, and those it couldn't, left out */
	unsigned read, unreadable;
	/* Of those read: those kept, and those left out as Sony's list has them */
	VitalsStoreFilter filter;
	/* The bundle's "Certificate data from Mozilla as of: ...", or empty */
	char dated[48];
} VitalsCaBundle;

/* bundle (curl's, or the one the app carries) as Mozilla's part of the store, sony Sony's list as PEM
 * text or NULL: 0, or -1 with why in note (NULL for none) when it isn't a bundle of CA certificates
 * (curl's heading, whole PEM blocks, at least VITALS_CA_MINIMUM Mbed TLS reads) or memory ran out */
int vitals_ca_prepare(const char *bundle, size_t length, const char *sony, size_t sony_length, VitalsCaBundle *out,
                      VitalsNote note);

/* curl's bundle downloaded from VITALS_CA_UPDATE_URL trusting only trust (the bundle the app carries,
 * so it works whatever the console's TLS is), then vitals_ca_prepare'd: 0, or -1 with why in note and
 * nothing made. log gets curl's notes on the transfer, or NULL */
int vitals_ca_download(const char *trust, size_t trust_length, const char *user_agent, void (*log)(const char *line),
                       const char *sony, size_t sony_length, VitalsCaBundle *out, VitalsNote note);

void vitals_ca_free(VitalsCaBundle *bundle);

#endif
