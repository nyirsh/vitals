/* The kernel plugin's first bytes: Cobra calls them once, as a function, with lv2's TOC in r2 and no
 * arguments. They find where the plugin was loaded (nothing relocates it), point
 * r2 at the plugin's own TOC, call plugin_main(base, sendto_entry, recvfrom_entry) and give the
 * caller its r2 back */

	.section .text.entry, "ax"
	.globl _start
_start:
	/* The caller's r2 is kept in this frame (at 120): its own TOC save slot (40 in its frame) is the
	 * caller's, and writing lv2's TOC there froze the console once the caller went on with it */
	mflr	0
	std	0, 16(1)
	stdu	1, -128(1)
	std	2, 120(1)
	bl	1f
1:	mflr	3
	addi	3, 3, _start - 1b	/* r3: where byte 0 is now */
	ld	4, toc_offset - _start(3)
	add	2, 3, 4			/* r2: the plugin's TOC */
	addi	4, 3, sendto_entry - _start	/* r4, r5: where the hooks start now */
	addi	5, 3, recvfrom_entry - _start
	bl	plugin_main
	nop
	ld	2, 120(1)
	addi	1, 1, 128
	ld	0, 16(1)
	mtlr	0
	blr

	.balign 8
toc_offset:
	.quad	.TOC. - _start		/* the same wherever the plugin is linked or loaded */
/* At byte 0x50, for the boot plugin (vitals-boot/src/boot.c): where plugin.c's State is, from byte 0,
 * so it can read what plugin_main did */
	.globl	state_offset
state_offset:
	.quad	g_state - _start

/* The syscall hooks' entries, which plugin_main(base, sendto_entry, recvfrom_entry) puts in lv2
 * descriptors. lv2's dispatcher (0x275C04) takes only the function from a descriptor and calls it
 * with lv2's TOC in r2, so each entry sets the plugin's TOC itself, as _start does, calls its C
 * function with the syscall's arguments untouched (r3 to r8: only r0, r11 and r12 are used here)
 * and gives lv2 its r2 back. The dispatcher's own frame (112 bytes, made just before the call) is
 * the caller's frame C may use, as the calling convention has it */
	.macro	hook_entry name, function
\name:
	mflr	0
	std	0, 16(1)
	stdu	1, -128(1)
	std	2, 120(1)
	bl	2f
2:	mflr	11
	addi	11, 11, _start - 2b
	ld	12, toc_offset - _start(11)
	add	2, 11, 12
	bl	\function
	nop
	ld	2, 120(1)
	addi	1, 1, 128
	ld	0, 16(1)
	mtlr	0
	blr
	.endm

	hook_entry sendto_entry, sendto_hook
	hook_entry recvfrom_entry, recvfrom_hook

/* uint64_t lv2_call(a0, a1, a2, a3, a4, a5, function, toc): lv2's function at its address, with
 * lv2's TOC; PS3DK's C calls through CellOS's 8-byte descriptors, lv2's are 16 */
	.section .text.lv2_call, "ax"
	.globl lv2_call
	.type lv2_call, @function
lv2_call:
	mflr	0
	std	0, 16(1)
	stdu	1, -112(1)
	std	2, 40(1)
	mtctr	9
	mr	2, 10
	bctrl
	ld	2, 40(1)
	addi	1, 1, 112
	ld	0, 16(1)
	mtlr	0
	blr
