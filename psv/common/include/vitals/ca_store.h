#ifndef VITALS_CA_STORE_H
#define VITALS_CA_STORE_H

#include "vitals/path.h"

/* The certificate store vitals-ssl trusts, in every process, is three files read as one, in this
 * order, each followed by a line break:
 * - Sony's list from firmware 3.74, as Sony ships it (the app's sony-certs.pem);
 * - the Mozilla certificates Sony's list lacks, which a certificate update rewrites;
 * - the user's own, ux0:data/vitals/custom-certs.pem, as the user writes it (optional; what isn't a
 *   certificate in it is skipped by the store's index).
 * The first two are vitals' own, in ux0:data/vitals/system: the system's vs0 CA_LIST.cer is left as
 * it was. Games may not open ux0:data themselves, so the kernel plugin reads the store through
 * vitals_ca_read */
#define VITALS_CA_SONY_PATH VITALS_SYSTEM_DIRECTORY "/sony-certs.pem"
#define VITALS_CA_MOZILLA_PATH VITALS_SYSTEM_DIRECTORY "/mozilla-certs.pem"
#define VITALS_CUSTOM_CERTIFICATES_PATH "ux0:data/vitals/custom-certs.pem"
/* Where earlier builds kept the three in one file, which an install takes out */
#define VITALS_CA_COMBINED_PATH VITALS_SYSTEM_DIRECTORY "/CA_LIST.cer"

/* The largest piece one call copies */
#define VITALS_CA_READ_MAX 65536u

/* A system call exported by the kernel plugin: copies up to size bytes of the store from offset
 * (at most VITALS_CA_READ_MAX) into buffer in the caller's memory; returns the number of bytes
 * copied (0 past its end), or a negative error (the file system's own when Sony's file is missing or
 * a part is unreadable) */
int vitals_ca_read(unsigned int offset, void *buffer, unsigned int size);

#endif
