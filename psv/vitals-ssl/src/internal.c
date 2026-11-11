#include "ssl.h"

/* The three SceSslInternal exports that do nothing in Sony's either, named after their NID as
 * nothing says what they were for. Every other one is written: core.c, connection.c,
 * certificate.c and vitals.c
 * "Sony" is the function's address in the libssl the app bundles (vitals-app/assets/lssl.suprx),
 * whose code is mapped at 0x81000000 */

/* NID 0x33737FDC, Sony 0x810480A9: only returns 0, as Sony's */
int sceSslInternal33737FDC(void)
{
    return 0;
}

/* NID 0x56FE376A, Sony 0x81047F05: does nothing, as Sony's */
void sceSslInternal56FE376A(void)
{
}

/* NID 0xC0B135F0, Sony 0x81047F01: does nothing, as Sony's */
void sceSslInternalC0B135F0(void)
{
}

