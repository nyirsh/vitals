#ifndef VITALS_VITA_PATHS_H
#define VITALS_VITA_PATHS_H

/* Where vitals keeps its files on the Vita, which the shared app shows and writes (shared/app/model.h,
 * ui.c, console_vita.c): the host redirects the kernel plugin applies, the DNS rules it answers lookups
 * with, the connection test's reports and the Options' switches */
#define VITALS_DIRECTORY "ux0:data/vitals"
#define VITALS_REPORTS_DIRECTORY VITALS_DIRECTORY
/* The Mozilla CA bundle the app carries (app0:), which its own downloads trust */
#define VITALS_APP_CA_BUNDLE "mozilla-certs.pem"
/* Each part's switch, as on the PS3: while its .off is there, that part is off from the next boot */
#define VITALS_FLAGS_DIRECTORY VITALS_DIRECTORY "/flags"
#define VITALS_TLS_OFF VITALS_FLAGS_DIRECTORY "/tls.off"
#define VITALS_HTTP_OFF VITALS_FLAGS_DIRECTORY "/http.off"
#define VITALS_DNS_OFF VITALS_FLAGS_DIRECTORY "/dns.off"
#define VITALS_REDIRECTS_OFF VITALS_FLAGS_DIRECTORY "/redirects.off"
#define VITALS_REDIRECTS VITALS_DIRECTORY "/redirects.txt"
#define VITALS_DNS VITALS_DIRECTORY "/dns.txt"

#endif
