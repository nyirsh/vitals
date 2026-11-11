#ifndef VITALS_DNS_LV2_493_SIGNATURES_H
#define VITALS_DNS_LV2_493_SIGNATURES_H

/* Written by tools/lv2_symbols.py --write from a dump of 4.93 CEX lv2 (Evilnat's Cobra): the first
 * 4 instructions of each lv2 function the DNS plugin calls or chains to, and the syscall
 * dispatcher's last five before its call. The plugin compares them on the console before calling
 * into lv2 at all, and hooks nothing when one differs */

#include <stdint.h>

#include "lv2_493.h"

typedef struct Lv2Signature {
	uint32_t offset;
	uint32_t words[4];
} Lv2Signature;

/* The plugin reports a difference by its index here (plugin.c's STATUS_SIGNATURE) */
static const Lv2Signature k_lv2_signatures[] = {
	{LV2_CELLFS_OPEN, {0xF821FF51, 0x7C0802A6, 0xFB010070, 0xFB610088}},
	{LV2_CELLFS_CLOSE, {0xF821FF61, 0x7C0802A6, 0xFBC10090, 0xEBC225B0}},
	{LV2_CELLFS_READ, {0x2C260000, 0x7C0802A6, 0x3D208001, 0xF821FF71}},
	{LV2_CELLFS_WRITE, {0xF821FF51, 0x7C0802A6, 0xFBC100A0, 0xEBC225B0}},
	{LV2_COPY_FROM_USER, {0x2C250000, 0x7C0802A6, 0xF821FF71, 0xFBA10078}},
	{LV2_COPY_TO_USER, {0x2C250000, 0x7C0802A6, 0xF821FF71, 0xFBA10078}},
	{LV2_HANDLER_NET_RECVFROM, {0xF821FF61, 0x7C0802A6, 0xFB410070, 0xFBC10090}},
	{LV2_HANDLER_NET_SENDTO, {0xF821FF61, 0x7C0802A6, 0xFB410070, 0xFB610078}},
};
#define LV2_SIGNATURE_COUNT 8u

/* The dispatcher's instructions from LV2_SYSCALL_CALL - 16 to its call */
static const uint32_t k_lv2_dispatch[5] = {0xE9AD0000, 0xE9AD0000, 0xF821FF91, 0x7DA803A6, 0x4E800021};

#endif
