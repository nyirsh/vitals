/* The export tables, laid out as Sony's libhttp lays them out: cellHttpUtil's 28-byte record, then
 * cellHttp's (version 1, attributes 0x0009), each with the NIDs of cellhttp_exports.h in its order
 * and each function's descriptor (as vitals-ssl/src/exports.S) */

	.section ".rodata.sceExportName","a"
	.align 2
.Lutil_name:	.asciz "cellHttpUtil"
.Lhttp_name:	.asciz "cellHttp"

/* cellHttpUtil's NIDs and descriptors: the header's CELLHTTPUTIL_EXPORT lines */
	.section ".rodata.sceExportNID","a"
	.align 2
.Lutil_nids:
	.section ".rodata.sceExportAddr","a"
	.align 2
.Lutil_addrs:

#define CELLHTTP_EXPORT(nid, name)
#define CELLHTTPUTIL_EXPORT(nid, name)       \
	.section ".rodata.sceExportNID","a";  \
	.long nid;                            \
	.section ".rodata.sceExportAddr","a"; \
	.long name;
#include "cellhttp_exports.h"
#undef CELLHTTP_EXPORT
#undef CELLHTTPUTIL_EXPORT

	.section ".rodata.sceExportNID","a"
.Lutil_nids_end:

/* cellHttp's: the CELLHTTP_EXPORT lines */
	.section ".rodata.sceExportNID","a"
.Lhttp_nids:
	.section ".rodata.sceExportAddr","a"
.Lhttp_addrs:

#define CELLHTTPUTIL_EXPORT(nid, name)
#define CELLHTTP_EXPORT(nid, name)           \
	.section ".rodata.sceExportNID","a";  \
	.long nid;                            \
	.section ".rodata.sceExportAddr","a"; \
	.long name;
#include "cellhttp_exports.h"

	.section ".rodata.sceExportNID","a"
.Lhttp_nids_end:

	.section ".lib.ent","a"
	.align 2
	.byte  0x1c                                    /* size */
	.byte  0x00
	.short 0x0001                                  /* version */
	.short 0x0009                                  /* attributes, as Sony's */
	.short (.Lutil_nids_end - .Lutil_nids) / 4     /* functions */
	.short 0x0000                                  /* variables */
	.short 0x0000                                  /* TLS variables */
	.byte  0x00                                    /* info hash */
	.byte  0x00                                    /* TLS info hash */
	.short 0x0000
	.long  .Lutil_name
	.long  .Lutil_nids
	.long  .Lutil_addrs

	.byte  0x1c
	.byte  0x00
	.short 0x0001
	.short 0x0009
	.short (.Lhttp_nids_end - .Lhttp_nids) / 4
	.short 0x0000
	.short 0x0000
	.byte  0x00
	.byte  0x00
	.short 0x0000
	.long  .Lhttp_name
	.long  .Lhttp_nids
	.long  .Lhttp_addrs
