/* One flat image from byte 0: the entry, code, read-only data, data and the TOC, with .bss inside so
 * objcopy -O binary carries it. BASE only checks the image is the same wherever it's linked: nothing
 * relocates a kernel plugin */
BASE = DEFINED(BASE) ? BASE : 0;
ENTRY(_start)
SECTIONS
{
	. = BASE;
	.text : { *(.text.entry) *(.text .text.*) }
	.rodata : { *(.rodata .rodata.*) }
	. = ALIGN(8);
	.data : { *(.data .data.*) *(.sdata .sdata.*) }
	. = ALIGN(256);
	.got : { *(.got .toc) }
	.TOC. = ADDR(.got) + 0x8000;
	.bss : { *(.bss .bss.*) *(.sbss .sbss.*) *(COMMON) BYTE(0) }
	. = ALIGN(16);
	/* The linker's function descriptors (absolute addresses): nothing uses them, as the entry calls
	 * plugin_main directly, so they come last and stay out of the image (objcopy -R .opd) */
	.opd : { *(.opd) }
	/DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
