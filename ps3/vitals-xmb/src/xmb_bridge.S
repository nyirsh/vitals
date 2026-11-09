/* The bridge from the XMB's code to vitals' libssl (xmb.c). Each of the XMB's 114 SSL functions
 * starts with a branch to an island of its own, which puts that function's vitals descriptor in r11
 * and jumps here. vitals' function needs its own TOC, and the XMB's direct calls don't load theirs
 * back after a call (their callee shared it), so this keeps the XMB's TOC and the return address in
 * a frame of its own, calls vitals' function through its descriptor, and gives both back.
 *
 * The frame is 128 bytes: the ABI's 48 of linkage area and 64 of parameter save area, which a
 * variadic callee writes its register arguments into (BIO_printf), and 16 more. The XMB's calls pass
 * at most 7 arguments, all in registers, so none is on the caller's stack.
 * r0, r11 and r12 are free at any function's start. */

	.section ".text"
	.align 2
	.globl vitals_xmb_bridge
	.type vitals_xmb_bridge, @function
vitals_xmb_bridge:
	mflr	0
	std	0, 16(1)	/* the return address, in the caller's frame, where any callee keeps it */
	stdu	1, -128(1)
	std	2, 40(1)	/* the XMB's TOC */
	lwz	0, 0(11)	/* vitals' function: its code and its TOC, from its descriptor */
	lwz	2, 4(11)
	mtctr	0
	bctrl
	ld	2, 40(1)
	addi	1, 1, 128
	ld	0, 16(1)
	mtlr	0
	blr
	.size vitals_xmb_bridge, . - vitals_xmb_bridge
