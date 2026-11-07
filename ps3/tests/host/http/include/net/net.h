#ifndef VITALS_HOST_NET_H
#define VITALS_HOST_NET_H

/* On a host the sockets are the system's: nothing to start */

static inline int netInitialize(void)
{
	return 0;
}

#endif
