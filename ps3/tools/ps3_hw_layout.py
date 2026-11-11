#!/usr/bin/env python3
"""Gives a PRX built with vitals' linker script (cmake/vitals-prx.ld) Sony's ELF flags, in place, and
checks its segments are the ones a console loads:

    tools/ps3_hw_layout.py <module.prx>

A console's kernel (4.93, Cobra) refuses PS3DK's own layout, one PT_LOAD segment marked read, write
and execute (0x7) with ELF flags 0x1, real-signed or fake-signed alike; RPCS3 loads it. Sony's
modules have ELF flags 0x1000000 and their code and data in separate segments: code 0x400005
(read, execute and the PS3's 0x400000), data 0x600006 (read, write, 0x400000 | 0x200000). The
linker script makes the segments; prx-gen writes ELF flags 0x1, which this sets to Sony's."""

import struct
import sys

ELF_FLAGS_SONY = 0x1000000
PT_LOAD = 1
SEGMENTS_SONY = (0x400005, 0x600006)


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    path = sys.argv[1]
    with open(path, "rb") as file:
        data = bytearray(file.read())
    phoff = struct.unpack_from(">Q", data, 0x20)[0]
    phentsize, phnum = struct.unpack_from(">HH", data, 0x36)
    flags = []
    for i in range(phnum):
        kind, segment_flags = struct.unpack_from(">II", data, phoff + phentsize * i)
        if kind == PT_LOAD:
            flags.append(segment_flags)
    if tuple(flags) != SEGMENTS_SONY:
        found = ", ".join(f"0x{f:x}" for f in flags)
        sys.exit(f"{path}: PT_LOAD segments {found}, expected code 0x400005 and data 0x600006 "
                 "(link it with cmake/vitals-prx.ld)")
    struct.pack_into(">I", data, 0x30, ELF_FLAGS_SONY)
    with open(path, "wb") as file:
        file.write(data)
    print(f"{path}: ELF flags 0x{ELF_FLAGS_SONY:x}, code 0x400005 and data 0x600006")


if __name__ == "__main__":
    main()
