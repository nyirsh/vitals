#ifndef VITALS_CA_STORE_H
#define VITALS_CA_STORE_H

#include "vitals/path.h"

/* The certificate store vitals-ssl trusts, in every process: Sony's list from firmware 3.74 as Sony
 * ships it, then Mozilla's certificates it lacks, then the user's own (custom-certs.pem), written by
 * the app. It's vitals' own, in ux0:data/vitals/system: the system's vs0 CA_LIST.cer is left as it
 * was. Games may not open ux0:data themselves, so the kernel plugin reads it through
 * vitals_ca_read */
#define VITALS_CA_STORE_PATH VITALS_SYSTEM_DIRECTORY "/CA_LIST.cer"

/* The largest piece one call copies */
#define VITALS_CA_READ_MAX 65536u

/* A system call exported by the kernel plugin: copies up to size bytes of the store from offset
 * (at most VITALS_CA_READ_MAX) into buffer in the caller's memory; returns the number of bytes
 * copied (0 past its end), or a negative error (the file system's own when the store is missing
 * or unreadable) */
int vitals_ca_read(unsigned int offset, void *buffer, unsigned int size);

#endif
