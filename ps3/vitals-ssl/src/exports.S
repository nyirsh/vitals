/* The cellSsl library's export table, laid out as Sony's libssl lays it out: a 28-byte record
 * (version 1, attributes 0x0009), the NIDs of cellssl_exports.h in its order, and each function's
 * descriptor. PS3DK's PRX_LIBRARY_* macros emit 44-byte records with attributes 0x0001; the loader
 * takes either, as it walks records by their size byte. */

	.section ".rodata.sceExportName","a"
	.align 2
.Lname:	.asciz "cellSsl"

	.section ".rodata.sceExportNID","a"
	.align 2
.Lnids:

	.section ".rodata.sceExportAddr","a"
	.align 2
.Laddrs:

#define CELLSSL_EXPORT(nid, name)            \
	.section ".rodata.sceExportNID","a";  \
	.long nid;                            \
	.section ".rodata.sceExportAddr","a"; \
	.long name;
#include "cellssl_exports.h"

	.section ".rodata.sceExportNID","a"
.Lnids_end:

	.section ".lib.ent","a"
	.align 2
	.byte  0x1c                            /* size */
	.byte  0x00
	.short 0x0001                          /* version */
	.short 0x0009                          /* attributes, as Sony's */
	.short (.Lnids_end - .Lnids) / 4       /* functions */
	.short 0x0000                          /* variables */
	.short 0x0000                          /* TLS variables */
	.byte  0x00                            /* info hash */
	.byte  0x00                            /* TLS info hash */
	.short 0x0000
	.long  .Lname
	.long  .Lnids
	.long  .Laddrs
