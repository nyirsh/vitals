#ifndef VITALS_USERAGENT_H
#define VITALS_USERAGENT_H

/* What vitals-http puts after an app's own User-Agent, in place of "libhttp/3.74 (PS Vita)";
 * games may not open ux0:data themselves, so the kernel plugin reads it through
 * vitals_useragent_read */
#define VITALS_USERAGENT_PATH "ux0:data/vitals/useragent.txt"

/* A system call exported by the kernel plugin: copies the file's start, up to size bytes (at
 * most VITALS_REDIRECTS_CHUNK), into buffer in the caller's memory; returns the number of bytes
 * copied or a negative error (the file system's own when the file is missing or unreadable) */
int vitals_useragent_read(void *buffer, unsigned int size);

#endif
