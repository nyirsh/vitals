#ifndef VITALS_PATHS_H
#define VITALS_PATHS_H

/* Where vitals keeps its files on the console, for every component (libssl, libhttp, the boot plugin,
 * the DNS kernel plugin, the app; tools/ps3_comms.py has the same list). /dev_hdd0/vitals itself
 * holds only what a user might edit; the rest is in its folders:
 *   system/   the modules, Mozilla's certificates and what the installers keep (not to be edited)
 *   flags/    a component's .off: while it's there, that component is off from the next boot; and
 *             debug.1 or debug.2, the installed modules' debug level
 *   logs/     the debug builds' log and the app's
 *   reports/  the app's connection test reports
 * Only plain defines: the DNS kernel plugin includes it too */

#define VITALS_DIRECTORY "/dev_hdd0/vitals"
#define VITALS_SYSTEM_DIRECTORY VITALS_DIRECTORY "/system"
#define VITALS_FLAGS_DIRECTORY VITALS_DIRECTORY "/flags"
#define VITALS_LOGS_DIRECTORY VITALS_DIRECTORY "/logs"
#define VITALS_REPORTS_DIRECTORY VITALS_DIRECTORY "/reports"
/* The Mozilla CA bundle the app carries in its USRDIR, which its own downloads trust */
#define VITALS_APP_CA_BUNDLE "cacert.pem"

/* What a user might edit */
#define VITALS_REDIRECTS VITALS_DIRECTORY "/redirects.txt"
#define VITALS_USER_AGENT VITALS_DIRECTORY "/useragent.txt"
#define VITALS_DNS VITALS_DIRECTORY "/dns.txt"
/* Certificates of the user's own, which libssl reads as they are after Sony's and Mozilla's, so an
 * edit applies to the next game (vitals-ssl/src/ca_store.c) */
#define VITALS_CUSTOM_CERTS VITALS_DIRECTORY "/custom-certs.pem"

/* system/ */
#define VITALS_LIBSSL VITALS_SYSTEM_DIRECTORY "/libssl.sprx"
#define VITALS_LIBHTTP VITALS_SYSTEM_DIRECTORY "/libhttp.sprx"
/* The XMB's own copies, when there: the boot plugin loads these into the XMB instead, so the XMB and
 * games never load one file (vitals-boot/src/xmb.c) */
#define VITALS_LIBSSL_XMB VITALS_SYSTEM_DIRECTORY "/libssl-xmb.sprx"
#define VITALS_LIBHTTP_XMB VITALS_SYSTEM_DIRECTORY "/libhttp-xmb.sprx"
#define VITALS_DNS_PLUGIN VITALS_SYSTEM_DIRECTORY "/vitals_dns.bin"
/* Mozilla's certificates that Sony's lack, which the app writes and its certificate update rewrites
 * (shared/include/vitals/store_certs.h) */
#define VITALS_BUNDLE VITALS_SYSTEM_DIRECTORY "/mozilla-certs.pem"
/* Where earlier versions kept Mozilla's whole bundle, the user's certificates merged in: the app's
 * install takes it from there */
#define VITALS_BUNDLE_EARLIER VITALS_SYSTEM_DIRECTORY "/cacert.pem"
#define VITALS_INSTALLED VITALS_SYSTEM_DIRECTORY "/installed.txt"

/* flags/ */
#define VITALS_TLS_OFF VITALS_FLAGS_DIRECTORY "/tls.off"
#define VITALS_HTTP_OFF VITALS_FLAGS_DIRECTORY "/http.off"
#define VITALS_DNS_OFF VITALS_FLAGS_DIRECTORY "/dns.off"
#define VITALS_REDIRECTS_OFF VITALS_FLAGS_DIRECTORY "/redirects.off"
/* The app installs on a system vitals isn't made for (vitals-app/src/console.h), for testers */
#define VITALS_UNSUPPORTED_OK VITALS_FLAGS_DIRECTORY "/unsupported.ok"
/* The XMB's own TLS (the browser, PSN, the Store) stays Sony's, and so its HTTP too (vitals' libhttp
 * works on vitals' libssl): vitals-boot/src/xmb.c */
#define VITALS_XMB_TLS_OFF VITALS_FLAGS_DIRECTORY "/xmb-tls.off"
/* The XMB's own HTTP stays Sony's (its TLS can still be vitals') */
#define VITALS_XMB_HTTP_OFF VITALS_FLAGS_DIRECTORY "/xmb-http.off"
/* The single XMB switch of earlier builds: the app's install and tools/ps3_comms.py rename it
 * xmb-tls.off */
#define VITALS_XMB_OLD_OFF VITALS_FLAGS_DIRECTORY "/xmb.off"

/* logs/ */
#define VITALS_LOG VITALS_LOGS_DIRECTORY "/vitals.log"
#define VITALS_APP_LOG VITALS_LOGS_DIRECTORY "/vitals-app.log"

/* The boot plugin, where Cobra's boot_plugins.txt lists it */
#define VITALS_PLUGIN "/dev_hdd0/plugins/vitals_boot.sprx"

#endif
