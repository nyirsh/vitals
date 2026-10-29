#include "ssl.h"

/* SceSslInternal's exports that aren't written yet: named after their NID until their job is
 * worked out. None of their arguments are known yet, so each takes none and fails. The written
 * ones are in core.c, connection.c and certificate.c
 * "Sony" is the function's address in the libssl the app bundles (vitals-app/assets/lssl.suprx),
 * whose code is mapped at 0x81000000 */

/* NID 0x00ABEBC3, Sony 0x81017843 */
int sceSslInternal00ABEBC3(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x05F6A292, Sony 0x810164A3 */
int sceSslInternal05F6A292(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x09657E15, Sony 0x81021DD1 */
int sceSslInternal09657E15(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x0C693D36, Sony 0x8101AFA9 */
int sceSslInternal0C693D36(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x133ED36D, Sony 0x8100F4E9 */
int sceSslInternal133ED36D(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x26CBEEB6, Sony 0x81018BFB */
int sceSslInternal26CBEEB6(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x2B90012E, Sony 0x8101BCF7 */
int sceSslInternal2B90012E(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x33737FDC, Sony 0x810480A9: only returns 0, as Sony's */
int sceSslInternal33737FDC(void)
{
    return 0;
}

/* NID 0x3EF42454, Sony 0x8101B07F */
int sceSslInternal3EF42454(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x422DFE70, Sony 0x810481FD */
int sceSslInternal422DFE70(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x4725F9E7, Sony 0x81021521 */
int sceSslInternal4725F9E7(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x56FE376A, Sony 0x81047F05: does nothing, as Sony's */
void sceSslInternal56FE376A(void)
{
}

/* NID 0x6046C1F3, Sony 0x81019F35 */
int sceSslInternal6046C1F3(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x6D0D3B11, Sony 0x81002DD1 */
int sceSslInternal6D0D3B11(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x6F3B9809, Sony 0x81018E5B */
int sceSslInternal6F3B9809(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x92560B8D, Sony 0x81019AE3 */
int sceSslInternal92560B8D(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0xB1745DAD, Sony 0x8101B087 */
int sceSslInternalB1745DAD(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0xC0B135F0, Sony 0x81047F01: does nothing, as Sony's */
void sceSslInternalC0B135F0(void)
{
}

/* NID 0xC1299FB6, Sony 0x8102A13B */
int sceSslInternalC1299FB6(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0xCB83EA07, Sony 0x81000BCD */
int sceSslInternalCB83EA07(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0xCBEC7D13, Sony 0x8101A8A9 */
int sceSslInternalCBEC7D13(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0xD419451B, Sony 0x81018B9F */
int sceSslInternalD419451B(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0xD6D32A2F, Sony 0x8101ACBD */
int sceSslInternalD6D32A2F(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0xDABB61EE, Sony 0x8100519B */
int sceSslInternalDABB61EE(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0xDEC6DD27, Sony 0x8100AD4D */
int sceSslInternalDEC6DD27(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0xF4007DBE, Sony 0x8101639D */
int sceSslInternalF4007DBE(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0xFB51AE89, Sony 0x8100AD43 */
int sceSslInternalFB51AE89(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0xFEFE761C, Sony 0x8101F799 */
int sceSslInternalFEFE761C(void)
{
    return ssl_not_implemented(__func__);
}
