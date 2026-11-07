/* vita-elf-create appends the module's own tables (about 3 KiB) to the end of the code segment,
 * in the space left before the data segment, which the default script starts at the next 64 KiB
 * boundary. When the code happens to end too close to that boundary the conversion fails
 * ("Cannot allocate ... bytes for SCE data at end of segment 0; segment 1 overlaps"), so this
 * pads the code segment past the boundary whenever less than 8 KiB would be left */
SECTIONS
{
    .vitals.sce_space :
    {
        LONG(0);
        . = . + ((ALIGN(ABSOLUTE(.), 0x10000) - ABSOLUTE(.)) < 0x2000 ? 0x2000 : 0);
    }
}
INSERT AFTER .eh_frame;
