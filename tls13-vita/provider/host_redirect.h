#ifndef VITALS_HOST_REDIRECT_H
#define VITALS_HOST_REDIRECT_H

/* Host redirects for this app, read from ux0:data/vitals/redirects.txt through the kernel plugin
 * When the list has rules, the app's sceHttpCreateConnection, sceHttpCreateConnectionWithURL and
 * sceHttpCreateRequestWithURL calls go to the new host instead of the old one
 * Best effort: a missing or unreadable list, or a failed hook, never affects the provider */
void vitals_host_redirect_install(void);

#endif
