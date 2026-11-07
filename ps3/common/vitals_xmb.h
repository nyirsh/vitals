#ifndef VITALS_XMB_H
#define VITALS_XMB_H

#include <stdint.h>

/* What vitals' boot plugin asks vitals' libssl and libhttp for when it loads them into the XMB, to
 * put them in the place of the XMB's own SSL-C and libhttp (vitals-boot/src/xmb.c): passed as
 * sys_prx_start_module's argument, it reaches the module's module_start (vitals-ssl/src/spike.c,
 * vitals-http/src/spike.c), which fills in each of its functions' NID and descriptor (libssl's 114,
 * libhttp's 201 of cellHttp and cellHttpUtil). A game starts them without one, and nothing is
 * filled in */

#define VITALS_XMB_MAGIC 0x76786D62u /* "vxmb" */
#define VITALS_XMB_FUNCTIONS 256u

typedef struct VitalsXmbFunction {
	uint32_t nid, descriptor;
} VitalsXmbFunction;

typedef struct VitalsXmbRequest {
	uint32_t magic, count;
	VitalsXmbFunction functions[VITALS_XMB_FUNCTIONS];
} VitalsXmbRequest;

#endif
