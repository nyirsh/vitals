#ifndef VITALS_VITA_NETWORK_H
#define VITALS_VITA_NETWORK_H

/* The network, started once and shared by the connection test and the certificate download */

/* Waits up to 10 seconds for a connection: 0, or the error. stop, when given, is asked while it
 * waits; once it says 1 the wait ends early without a result being kept, so the next caller waits
 * again. Any other result is kept */
int network_start(int (*stop)(void));
void network_stop(void);

#endif
