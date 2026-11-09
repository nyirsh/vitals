#ifndef VITALS_SWITCHES_H
#define VITALS_SWITCHES_H

/* The Options' switches, as on the PS3: while a part's .off is in ux0:data/vitals/flags, that part
 * is off. The app writes them and reboots; the kernel plugin looks for them where each part starts
 * (a module's load, the DNS list's reread, a process's redirect list), as ux0 may not be mapped
 * yet when it starts:
 * - tls.off: Sony's libssl and the browser's own TLS; vitals-http stays, and does its TLS on Sony's
 *   libssl as Sony's libhttp does (vitals-http/src/tls_sony.c);
 * - http.off: Sony's libhttp, on vitals-ssl (which has everything Sony's libhttp uses), and with it
 *   no host redirects or User-Agent suffix;
 * - dns.off: the DNS rules (dns.txt) aren't applied;
 * - redirects.off: the host redirects (redirects.txt) aren't applied; vitals-http stays */
#define VITALS_FLAGS_DIRECTORY "ux0:data/vitals/flags"
#define VITALS_TLS_OFF VITALS_FLAGS_DIRECTORY "/tls.off"
#define VITALS_HTTP_OFF VITALS_FLAGS_DIRECTORY "/http.off"
#define VITALS_DNS_OFF VITALS_FLAGS_DIRECTORY "/dns.off"
#define VITALS_REDIRECTS_OFF VITALS_FLAGS_DIRECTORY "/redirects.off"
/* The debug output's lines go to a file rather than the debug console while it's there */
#define VITALS_LOG_TO_FILE VITALS_FLAGS_DIRECTORY "/log.file"

#endif
