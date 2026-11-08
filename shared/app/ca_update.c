/* Mozilla's part of vitals' certificate store, for every console (ca_update.h) */

#include "ca_update.h"

#include "download.h"

#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char begin[] = "-----BEGIN CERTIFICATE-----", end[] = "-----END CERTIFICATE-----";

static void notef(VitalsNote note, const char *format, ...) __attribute__((format(printf, 2, 3)));
static void notef(VitalsNote note, const char *format, ...)
{
	if (note == NULL)
		return;
	char line[256];
	va_list arguments;
	va_start(arguments, format);
	vsnprintf(line, sizeof(line), format, arguments);
	va_end(arguments);
	note(line);
}

/* Mbed TLS reads the PEM block from..to (to past its end line) */
static int readable(const char *from, const char *to, char *scratch)
{
	size_t length = (size_t)(to - from);
	memcpy(scratch, from, length);
	scratch[length] = '\0';
	mbedtls_x509_crt certificate;
	mbedtls_x509_crt_init(&certificate);
	int rc = mbedtls_x509_crt_parse(&certificate, (const unsigned char *)scratch, length + 1);
	mbedtls_x509_crt_free(&certificate);
	return rc == 0;
}

static int prepare(const char *bundle, size_t length, const char *sony, size_t sony_length, VitalsCaBundle *out,
                   VitalsNote note);

int vitals_ca_prepare(const char *given, size_t length, const char *sony, size_t sony_length, VitalsCaBundle *out,
                      VitalsNote note)
{
	memset(out, 0, sizeof(*out));
	if (given == NULL || length == 0 || length > VITALS_CA_BUNDLE_LIMIT || memchr(given, '\0', length) != NULL) {
		notef(note, "This isn't a bundle of CA certificates");
		return -1;
	}
	/* Its text ended where it ends, whatever follows it */
	char *bundle = malloc(length + 1);
	if (bundle == NULL) {
		notef(note, "Out of memory for the certificates");
		return -1;
	}
	memcpy(bundle, given, length);
	bundle[length] = '\0';
	int rc = prepare(bundle, length, sony, sony_length, out, note);
	free(bundle);
	return rc;
}

static int prepare(const char *bundle, size_t length, const char *sony, size_t sony_length, VitalsCaBundle *out,
                   VitalsNote note)
{
	if (strstr(bundle, "Bundle of CA Root Certificates") == NULL) {
		notef(note, "This isn't a bundle of CA certificates");
		return -1;
	}
	if (console_crypto_start() < 0 || psa_crypto_init() != PSA_SUCCESS) {
		notef(note, "The certificates can't be checked: Mbed TLS didn't start");
		return -1;
	}
	const char *dated = strstr(bundle, "Certificate data from Mozilla as of: ");
	if (dated != NULL)
		sscanf(dated + 37, "%47[^\r\n]", out->dated);
	/* The bundle again without the blocks Mbed TLS can't read, then without Sony's */
	char *readable_text = malloc(length + 1), *scratch = malloc(length + 1);
	out->data = malloc(length + 1);
	if (readable_text == NULL || scratch == NULL || out->data == NULL) {
		free(readable_text);
		free(scratch);
		vitals_ca_free(out);
		notef(note, "Out of memory for the certificates");
		return -1;
	}
	size_t used = 0;
	const char *at = bundle;
	for (const char *block = strstr(at, begin); block != NULL; block = strstr(at, begin)) {
		const char *close = strstr(block, end), *next = strstr(block + 1, begin);
		if (close == NULL || (next != NULL && next < close)) {
			notef(note, "The bundle has a broken certificate");
			free(readable_text);
			free(scratch);
			vitals_ca_free(out);
			return -1;
		}
		close += sizeof(end) - 1;
		/* What's before the block (a root's title) is kept with it either way */
		memcpy(readable_text + used, at, (size_t)(block - at));
		used += (size_t)(block - at);
		if (readable(block, close, scratch)) {
			memcpy(readable_text + used, block, (size_t)(close - block));
			used += (size_t)(close - block);
			++out->read;
		} else {
			++out->unreadable;
		}
		at = close;
	}
	size_t rest = length - (size_t)(at - bundle);
	memcpy(readable_text + used, at, rest);
	used += rest;
	readable_text[used] = '\0';
	free(scratch);
	if (out->read < VITALS_CA_MINIMUM) {
		notef(note, "The bundle has only %u certificates Mbed TLS reads", out->read);
		free(readable_text);
		vitals_ca_free(out);
		return -1;
	}
	int filtered = vitals_store_mozilla(readable_text, used, sony, sony_length, out->data, length + 1, &out->size,
	                                    &out->filter);
	free(readable_text);
	if (filtered < 0) {
		vitals_ca_free(out);
		notef(note, "Out of memory for the certificates");
		return -1;
	}
	if (out->unreadable != 0)
		notef(note, "Left out %u certificates Mbed TLS can't read, as vitals couldn't use them", out->unreadable);
	notef(note, "Mozilla's certificates%s%s: %u, and %u Sony's list already has left out",
	      out->dated[0] ? " of " : "", out->dated, out->filter.kept, out->filter.sony);
	if (out->filter.cut_custom)
		notef(note, "Took out the copy of your certificates an earlier version merged in: custom-certs.pem is read "
		            "as it is now");
	return 0;
}

int vitals_ca_download(const char *trust, size_t trust_length, const char *user_agent, void (*log)(const char *line),
                       const char *sony, size_t sony_length, VitalsCaBundle *out, VitalsNote note)
{
	memset(out, 0, sizeof(*out));
	notef(note, "Downloading " VITALS_CA_UPDATE_URL);
	VitalsDownload request = {VITALS_CA_UPDATE_URL, trust, trust_length, user_agent, NULL, 30,
	                          VITALS_CA_BUNDLE_LIMIT, NULL, log};
	VitalsDownloaded result;
	int rc = vitals_download(&request, &result);
	if (rc < 0) {
		if (result.status != 0 && result.status != 200)
			notef(note, "The server answered HTTP %ld", result.status);
		else
			notef(note, "The download failed (%d): %s", result.error,
			      result.message[0] != '\0' ? result.message : vitals_download_error(result.error));
	} else {
		notef(note, "Received %u bytes", (unsigned)result.size);
		rc = vitals_ca_prepare(result.data, result.size, sony, sony_length, out, note);
	}
	vitals_download_free(&result);
	return rc;
}

void vitals_ca_free(VitalsCaBundle *bundle)
{
	free(bundle->data);
	bundle->data = NULL;
	bundle->size = 0;
}
