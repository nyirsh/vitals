#include "vh.h"

#include "diagnostics.h"

/* Exports of Sony's libhttp that no header or NID database names. Its code shows what kind of
 * thing each is (debug dumps, settings, its allocator and loaded-certificate hooks); none is
 * reproduced. The dumps and settings succeed doing nothing, the rest report they aren't
 * supported. With debug output on, each call is logged with the values of its first four
 * argument registers, as numbers only: nothing they point at is read */

#define VH_PRIVATE(nid, result)                                                                    \
    int sceHttpPrivate##nid(unsigned int a0, unsigned int a1, unsigned int a2, unsigned int a3)    \
    {                                                                                              \
        VITALS_LOG("private export %s called args=%08X %08X %08X %08X", #nid, a0, a1, a2, a3);     \
        (void)a0, (void)a1, (void)a2, (void)a3;                                                    \
        return (result);                                                                           \
    }

/* Debug dumps: the library's state, its request and connection counts, its memory pool */
VH_PRIVATE(5B6A0ACE, 0)
VH_PRIVATE(FE60380A, 0)
VH_PRIVATE(B0E41827, 0)
VH_PRIVATE(88116DB8, 0)
VH_PRIVATE(0B0D8E7A, 0)
/* Statistics of one object */
VH_PRIVATE(54847CFE, VH_ERROR_UNSUPPORTED)
VH_PRIVATE(80E6013D, VH_ERROR_UNSUPPORTED)
/* Settings of an object, next to the nonblock, cache, ICM and gzip ones; 855D5254 is a library-wide
 * one (Sony's option 22), which adds two callbacks and a flag to the TLS contexts libssl makes */
VH_PRIVATE(43A7CC70, 0)
VH_PRIVATE(175685B8, 0)
VH_PRIVATE(F30073EC, 0)
VH_PRIVATE(30F5D11F, 0)
VH_PRIVATE(53B722F2, 0)
VH_PRIVATE(C498765A, 0)
VH_PRIVATE(855D5254, 0)
/* Allocator hooks and the list of loaded certificates ("SceLibHttpLoadedCert") */
VH_PRIVATE(E0825488, 0)
VH_PRIVATE(42108FBE, 0)
VH_PRIVATE(0CC59EF6, 0)
VH_PRIVATE(11C9BCE8, 0)
VH_PRIVATE(F8885CFD, 0)
VH_PRIVATE(031EBD2A, 0)
VH_PRIVATE(802E3C30, 0)
/* Sony's installs libhttp's certificate check on a libssl context its caller made (the NetCheck
 * dialog's own TLS, on Sony's libssl): (context, argument), 0x80435801 when one is missing. That
 * check is libhttp's code on libssl's certificates, which this library has neither of, so the
 * context is left as libssl made it; failing would end the game's PSN sign-in */
int sceHttpPrivateA9A39BA1(unsigned int context, unsigned int argument)
{
    VH_TRACE();
    VITALS_LOG("private export A9A39BA1 context=%08X argument=%08X: libssl's own checks only", context, argument);
    return context == 0 || argument == 0 ? (int)0x80435801 : 0;
}
/* Verifies a certificate against Sony's CA store, through libssl */
VH_PRIVATE(A4CF892E, VH_ERROR_UNSUPPORTED)
