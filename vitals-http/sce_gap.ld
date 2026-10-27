/* vita-elf-create puts the module's export and import tables right after the code, and fails when
 * the data segment starts too soon after it; where the linker puts that segment (the next 64 KiB
 * boundary) depends on the code's size, so 16 KiB are always left before choosing it */
SECTIONS
{
    . = . + 0x4000;
}
INSERT AFTER .ARM.exidx;
