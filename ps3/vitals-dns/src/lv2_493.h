#ifndef VITALS_DNS_LV2_493_H
#define VITALS_DNS_LV2_493_H

/* lv2's addresses on firmware 4.93 CEX (Evilnat's Cobra), offsets from 0x8000000000000000: the
 * values Mamba's symbols_ALL.h gives its 484C-493C block, each checked against a dump of this
 * console's lv2 (webMAN's /dump.ps3?lv2): the syscall table's 1024 entries end in zeros, every
 * descriptor in it has this TOC, and each function below has an lv2 descriptor pointing at it
 * (tools/lv2_symbols.py checks a dump again). Only addresses come from Mamba,
 * not its code (GPL-3.0) */

#define LV2_BASE 0x8000000000000000ULL
#define LV2_TOC 0x34FBB0
#define LV2_SYSCALL_TABLE 0x363BE0
/* The syscall dispatcher's call (blrl) into a syscall's handler: it loads the handler from the
 * descriptor and calls it with lv2's TOC, which it loads from LV2_TOC_SLOT */
#define LV2_SYSCALL_CALL 0x275C04
#define LV2_TOC_SLOT 0x3000

/* The handlers of the syscalls the DNS rules watch (their descriptors in the table) */
#define LV2_SYSCALL_NET_RECVFROM 707
#define LV2_SYSCALL_NET_SENDTO 710
/* lv2's own descriptors for them, which the table holds until something hooks them */
#define LV2_DESCRIPTOR_NET_RECVFROM 0x320F68
#define LV2_DESCRIPTOR_NET_SENDTO 0x320F20
/* and the handlers those descriptors point at */
#define LV2_HANDLER_NET_RECVFROM 0x122464
#define LV2_HANDLER_NET_SENDTO 0x122260

#define LV2_ALLOC 0x64824
#define LV2_DEALLOC 0x64C60
#define LV2_PAGE_ALLOCATE 0x60394
#define LV2_PAGE_FREE 0x5FDF8
#define LV2_COPY_TO_USER 0xF86C
#define LV2_COPY_FROM_USER 0xFA88
#define LV2_COPY_TO_PROCESS 0xF924
#define LV2_COPY_FROM_PROCESS 0xF734
#define LV2_PROCESS_READ_MEMORY 0x267EC0
#define LV2_PROCESS_WRITE_MEMORY 0x267D34
#define LV2_CELLFS_OPEN 0x297900
#define LV2_CELLFS_CLOSE 0x297768
#define LV2_CELLFS_READ 0x2978A4
#define LV2_CELLFS_WRITE 0x297810
#define LV2_CELLFS_LSEEK 0x296E98
#define LV2_CELLFS_STAT 0x29711C
#define LV2_CELLFS_UNLINK_INTERNAL 0x19C64C
#define LV2_OPEN_PATH 0x297638
#define LV2_MEMCPY 0x7E92C
#define LV2_MEMSET 0x4D66C
#define LV2_SPRINTF 0x4EA94
#define LV2_SNPRINTF 0x4EA00
#define LV2_PRINTF 0x2706AC
#define LV2_STRCPY 0x4D818
#define LV2_STRLEN 0x4D840
#define LV2_MUTEX_CREATE 0x1363C
#define LV2_MUTEX_DESTROY 0x135D4
#define LV2_MUTEX_LOCK 0x135CC
#define LV2_MUTEX_UNLOCK 0x135C4
#define LV2_PPU_THREAD_CREATE 0x13EC8
#define LV2_PPU_THREAD_EXIT 0x13F80
#define LV2_PPU_THREAD_JOIN 0x13FD4
#define LV2_PPU_THREAD_DELAY 0x287A4

#endif
