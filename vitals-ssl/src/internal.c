#include "ssl.h"

/* SceSslInternal's exports that aren't written yet: named after their NID until their job is
 * worked out. None of their arguments are known yet, so each takes none and fails. The written
 * ones are in core.c and connection.c
 * "Sony" is the function's address in the libssl the app bundles (vitals-app/assets/lssl.suprx),
 * whose code is mapped at 0x81000000 */

/* NID 0x00ABEBC3, Sony 0x81017843 */
int sceSslInternal00ABEBC3(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x04BAED82, Sony 0x81028DC1 */
int sceSslInternal04BAED82(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x05F6A292, Sony 0x810164A3 */
int sceSslInternal05F6A292(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x064DFC99, Sony 0x810481E1 */
int sceSslInternalGetCertificateAuthority(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x08179EBD, Sony 0x81001761 */
int sceSslInternal08179EBD(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x08ED1B25, Sony 0x81001C71 */
int sceSslInternal08ED1B25(void)
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

/* NID 0x144FA354, Sony 0x81004F29 */
int sceSslInternal144FA354(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x170D595D, Sony 0x81005113 */
int sceSslInternal170D595D(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x17BF2367, Sony 0x81005043 */
int sceSslInternal17BF2367(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x2074A6EB, Sony 0x81001CE9 */
int sceSslInternal2074A6EB(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x243DE290, Sony 0x810163F7 */
int sceSslInternal243DE290(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x2464F9D0, Sony 0x81001D33 */
int sceSslInternal2464F9D0(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x24C6257F, Sony 0x81019995 */
int sceSslInternal24C6257F(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x26CBEEB6, Sony 0x81018BFB */
int sceSslInternal26CBEEB6(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x29AAC768, Sony 0x810050D5 */
int sceSslInternal29AAC768(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x2B90012E, Sony 0x8101BCF7 */
int sceSslInternal2B90012E(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x306E2A22, Sony 0x81005081 */
int sceSslInternal306E2A22(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x33737FDC, Sony 0x810480A9: only returns 0, as Sony's */
int sceSslInternal33737FDC(void)
{
    return 0;
}

/* NID 0x33AC7A16, Sony 0x81000A9D */
int sceSslInternal33AC7A16(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x349B0E73, Sony 0x810481F5 */
int sceSslInternal349B0E73(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x3746501F, Sony 0x810481CD */
int sceSslInternal3746501F(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x3DE4F3DB, Sony 0x810092C9 */
int sceSslInternal3DE4F3DB(void)
{
    return ssl_not_implemented(__func__);
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

/* NID 0x46358909, Sony 0x8101FB59 */
int sceSslInternal46358909(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x4725F9E7, Sony 0x81021521 */
int sceSslInternal4725F9E7(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x4AAF0D45, Sony 0x8102A239 */
int sceSslInternal4AAF0D45(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x4D80D3F7, Sony 0x810090D3 */
int sceSslInternal4D80D3F7(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x568F0E80, Sony 0x81001AA3 */
int sceSslInternal568F0E80(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x56FE376A, Sony 0x81047F05: does nothing, as Sony's */
void sceSslInternal56FE376A(void)
{
}

/* NID 0x5E50CB55, Sony 0x81028D87 */
int sceSslInternal5E50CB55(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x6046C1F3, Sony 0x81019F35 */
int sceSslInternal6046C1F3(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x64BDF1BB, Sony 0x81004F83 */
int sceSslInternal64BDF1BB(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x6CDB4EE8, Sony 0x81028D99 */
int sceSslInternal6CDB4EE8(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x6D0D3B11, Sony 0x81002DD1 */
int sceSslInternal6D0D3B11(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x6D2A86F0, Sony 0x8102A351 */
int sceSslInternal6D2A86F0(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x6F3B9809, Sony 0x81018E5B */
int sceSslInternal6F3B9809(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x7D30F0A6, Sony 0x8101F9B1 */
int sceSslInternal7D30F0A6(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x81FA5DBE, Sony 0x81001753 */
int sceSslInternal81FA5DBE(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x88391E03, Sony 0x81028E09 */
int sceSslInternal88391E03(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x91C2531C, Sony 0x810051C5 */
int sceSslInternal91C2531C(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x92560B8D, Sony 0x81019AE3 */
int sceSslInternal92560B8D(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0x93EAE08A, Sony 0x81002953 */
int sceSslInternal93EAE08A(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0xA4EA9DE0, Sony 0x810163C5 */
int sceSslInternalA4EA9DE0(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0xB0E4CB2F, Sony 0x8101AF8F */
int sceSslInternalB0E4CB2F(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0xB1745DAD, Sony 0x8101B087 */
int sceSslInternalB1745DAD(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0xB5A099D2, Sony 0x8100505D */
int sceSslInternalB5A099D2(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0xB8E6E249, Sony 0x8101DA37 */
int sceSslInternalB8E6E249(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0xBF99D664, Sony 0x81002BF5 */
int sceSslInternalBF99D664(void)
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

/* NID 0xC4D984C2, Sony 0x8100109F */
int sceSslInternalC4D984C2(void)
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

/* NID 0xCE37B69E, Sony 0x81004FE9 */
int sceSslInternalCE37B69E(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0xD1A82B1A, Sony 0x81028DE9 */
int sceSslInternalD1A82B1A(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0xD3C049B9, Sony 0x81028CFB */
int sceSslInternalD3C049B9(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0xD419451B, Sony 0x81018B9F */
int sceSslInternalD419451B(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0xD4ADF069, Sony 0x81028D75 */
int sceSslInternalD4ADF069(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0xD68D8421, Sony 0x8100176F */
int sceSslInternalD68D8421(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0xD6D32A2F, Sony 0x8101ACBD */
int sceSslInternalD6D32A2F(void)
{
    return ssl_not_implemented(__func__);
}

/* NID 0xD776E2F8, Sony 0x81019A71 */
int sceSslInternalD776E2F8(void)
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

/* NID 0xF030A0DE, Sony 0x81002039 */
int sceSslInternalF030A0DE(void)
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
