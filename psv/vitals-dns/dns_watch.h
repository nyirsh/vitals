#ifndef VITALS_DNS_WATCH_H
#define VITALS_DNS_WATCH_H

#include <psp2kern/types.h>

/* DNS for every process: the system's resolver runs inside each process, in a library shared
 * between processes, so the kernel's socket calls are the one place all lookups pass through
 *
 * The rules are in VITALS_DNS_LIST_PATH, one "host target" pair per line ('#' starts a comment),
 * apart from the HTTP library's redirects.txt. The target is:
 *   another host name: an A query for host goes out asking for it, and the server's answer comes
 *     back as an answer for host, with the other name's addresses
 *   an IPv4 address: the query goes out as it is, and its answer is that address
 *   "block": the query goes out as it is, and its answer is that the name doesn't exist
 * The app still connects by the old name, so a server's certificate must be valid for that name
 * In the debug builds (DEBUG=1 and up), every query is logged too, with its process and host name */

/* Hooks the kernel's send and receive; the send hook's result, negative when it could not be
 * installed (without the receive hook, queries are only logged) */
#define VITALS_DNS_LIST_PATH "ux0:data/vitals/dns.txt"

SceUID vitals_dns_watch_start(void);
void vitals_dns_watch_stop(void);

#endif
