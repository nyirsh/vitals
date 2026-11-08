#ifndef VITALS_VITA_PATHS_H
#define VITALS_VITA_PATHS_H

/* Where vitals keeps its files on the Vita, which the shared app shows and writes (shared/app/model.h,
 * ui.c, console_vita.c): the host redirects the kernel plugin applies, the DNS rules it answers lookups
 * with, the connection test's reports and the Options' switches */
#define VITALS_DIRECTORY "ux0:data/vitals"
#define VITALS_REPORTS_DIRECTORY VITALS_DIRECTORY "/reports"
/* The Mozilla CA bundle the app carries (app0:), which its own downloads trust */
#define VITALS_APP_CA_BUNDLE "mozilla-certs.pem"
/* Each part's switch, as on the PS3, which the kernel plugin reads (vitals/switches.h) */
#include "vitals/switches.h"
#define VITALS_REDIRECTS VITALS_DIRECTORY "/redirects.txt"
#define VITALS_DNS VITALS_DIRECTORY "/dns.txt"
/* Which release installed vitals and its modules' debug level, as on the PS3 (shared/app/installed.c) */
#define VITALS_INSTALLED VITALS_DIRECTORY "/system/installed.txt"

#endif
