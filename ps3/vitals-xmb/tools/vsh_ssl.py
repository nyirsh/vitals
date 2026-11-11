#!/usr/bin/env python3
"""How the XMB (vsh.elf, decrypted) holds and uses its own copy of SSL-C, for patching it to vitals'
libssl:

    vitals-xmb/tools/vsh_ssl.py [--vsh ../dumps/ps3/4.93-cex/vsh/evilnat-cobra-8.5/vsh.elf] [--libssl ../dumps/ps3/4.93-cex/libssl.prx] [--header FILE]

- the function starts (OPDs and bl targets) and the direct calls;
- SSL-C's bounds, found by matching libssl.prx's functions to vsh.elf's by their code with the
  addresses masked (the two are the same code, linked at other places);
- every call from outside SSL-C into it that isn't one of the 114 cellSsl exports, every pointer to
  an SSL-C function that code outside it loads, and every TOC slot (global) both use;
- which exports each part of the XMB calls.

--header writes the boot plugin's tables (vitals-xmb/src/xmb_493.h), for SSL-C's 114 functions and
libhttp's 201 (cellHttp and cellHttpUtil): each one's NID, descriptor, code address and first
instruction, which the boot plugin checks and then writes over with a branch (some exports are a
single instruction); and each library's island area, code of its own that nothing but its exports
reaches, dead once they go elsewhere, where the branches land: its address and a checksum of what's
there, which the boot plugin checks too."""

import argparse
import bisect
import os
import struct
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "tools"))
import nids  # noqa: E402
from prx import Prx  # noqa: E402

# vsh.elf 4.93's export table entries (found from the library names' strings)
CELLSSL_NIDS, CELLSSL_ADDRESSES, CELLSSL_COUNT = 0x640F54, 0x64119C, 114
CELLHTTP_NIDS, CELLHTTP_ADDRESSES, CELLHTTP_COUNT = 0x640924, 0x640C78, 181
CELLHTTPUTIL_NIDS, CELLHTTPUTIL_ADDRESSES, CELLHTTPUTIL_COUNT = 0x640858, 0x6408C8, 20
# Where each library's code is: SSL-C, and the XMB's libhttp just before it
SSL_BOUNDS = (0x587600, 0x5D1854)
HTTP_BOUNDS = (0x559BDC, 0x587600)
DFORM = {14, 15, 24, 25, *range(32, 56), 58, 62}
# Each export's island, where its first instruction branches to (vitals-xmb/src/xmb.c): its
# vitals descriptor into r11, then the bridge's address into r12 and a jump there
ISLAND_WORDS = 6
# The island area: SSL-C's largest function that nothing outside SSL-C calls or points at, and no
# function at all calls directly (an entry of its own tables)
ISLAND_AREA = 0x5B0478
# libhttp's: the start of its longest stretch of internal functions, with no export in it (34 KB,
# between cellHttp's last and cellHttpUtil's first), all of it dead once the exports go elsewhere
HTTP_ISLAND_AREA = 0x57ACA0


class Vsh:
    def __init__(self, path):
        with open(path, "rb") as file:
            self.data = file.read()
        phoff = struct.unpack_from(">Q", self.data, 0x20)[0]
        self.segments = []
        for i in range(struct.unpack_from(">H", self.data, 0x38)[0]):
            kind, _flags, offset, vaddr, _paddr, filesz, _memsz, _align = struct.unpack_from(
                ">IIQQQQQQ", self.data, phoff + 56 * i)
            if kind == 1 and filesz:
                self.segments.append((offset, vaddr, filesz))
        self.text = self.segments[0]
        # The TOC every cellSsl export's descriptor carries
        self.toc = self.u32(self.u32(CELLSSL_ADDRESSES) + 4)

    def offset(self, vaddr):
        for offset, start, size in self.segments:
            if start <= vaddr < start + size:
                return offset + vaddr - start
        return None

    def u32(self, vaddr):
        return struct.unpack_from(">I", self.data, self.offset(vaddr))[0]

    def code(self, start, end):
        base = self.offset(start)
        return [struct.unpack_from(">I", self.data, base + o)[0] for o in range(0, end - start, 4)]


def bl_target(at, word):
    if word >> 26 == 18 and word & 3 == 1:
        displacement = word & 0x03FFFFFC
        return at + (displacement - 0x04000000 if displacement & 0x02000000 else displacement)
    return None


def signature(words):
    """The code with what linking changes masked: branch targets, address halves, TOC offsets"""
    return tuple(w & 0xFC000003 if w >> 26 == 18 else w & 0xFFFF0000 if w >> 26 in DFORM else w for w in words)


def vsh_functions(vsh):
    offset, start, size = vsh.text
    starts, calls = set(), []
    for data_offset, _vaddr, data_size in vsh.segments[1:]:
        for o in range(0, data_size - 7, 4):
            address, toc = struct.unpack_from(">II", vsh.data, data_offset + o)
            if toc == vsh.toc and start <= address < start + size and address % 4 == 0:
                starts.add(address)
    for o in range(0, size, 4):
        at = start + o
        target = bl_target(at, struct.unpack_from(">I", vsh.data, offset + o)[0])
        if target is not None and start <= target < start + size:
            starts.add(target)
            calls.append((at, target))
    return sorted(starts), calls


def prx_signatures(path):
    prx = Prx(path)
    _name, _attributes, _version, toc, *_rest = prx.info()
    loaded = [s for s in prx.segments if s[0] == 1]
    _kind, text_offset, text_start, _paddr, text_size, _memsz = loaded[0]
    words = [struct.unpack_from(">I", prx.data, text_offset + o)[0] for o in range(0, text_size, 4)]
    starts = set()
    for _kind, offset, _vaddr, _paddr, size, _memsz in loaded[1:]:
        for o in range(0, size - 7, 4):
            address, entry_toc = struct.unpack_from(">II", prx.data, offset + o)
            if entry_toc == toc and text_start <= address < text_start + text_size:
                starts.add(address)
    for i, word in enumerate(words):
        target = bl_target(text_start + 4 * i, word)
        if target is not None and text_start <= target < text_start + text_size:
            starts.add(target)
    starts = sorted(starts)
    found = defaultdict(list)
    for i, a in enumerate(starts):
        b = starts[i + 1] if i + 1 < len(starts) else text_start + text_size
        found[signature(words[(a - text_start) // 4:(b - text_start) // 4])].append(a)
    return {s: a[0] for s, a in found.items() if len(a) == 1 and len(s) > 2}


def fnv1a(data):
    value = 0x811C9DC5
    for byte in data:
        value = ((value ^ byte) * 0x01000193) & 0xFFFFFFFF
    return value


def library_rows(vsh, libraries, area, size, bounds, starts, calls, exports_must_be_outside):
    """The table's rows for one patch: each function's library, NID, descriptor, code address and first
    instruction, after checking the island area holds its islands, in reach of a branch"""
    rows, exports = [], set()
    for index, (nids_at, addresses_at, count) in libraries:
        for i in range(count):
            nid = vsh.u32(nids_at + 4 * i)
            descriptor = vsh.u32(addresses_at + 4 * i)
            address = vsh.u32(descriptor)
            exports.add(address)
            if abs(area + size - address) >= 1 << 25 or abs(area - address) >= 1 << 25:
                sys.exit(f"{address:#x} is out of a branch's reach of the islands at {area:#x}")
            rows.append(f"\t{{{index}u, 0x{nid:08X}u, 0x{descriptor:08X}u, 0x{address:08X}u, 0x{vsh.u32(address):08X}u}},")
    if not bounds[0] <= area < area + size <= bounds[1] or area not in starts:
        sys.exit(f"{area:#x} isn't a function of the library, with room for {size} bytes")
    if any(area <= e < area + size for e in exports):
        sys.exit(f"{area:#x}: an export is where the islands would go")
    if exports_must_be_outside and any(target == area for _source, target in calls):
        sys.exit(f"{area:#x} is called directly")
    return rows, fnv1a(vsh.data[vsh.offset(area):vsh.offset(area) + size])


def write_header(vsh, starts, calls, path):
    ssl_size = 4 * ISLAND_WORDS * CELLSSL_COUNT
    http_count = CELLHTTP_COUNT + CELLHTTPUTIL_COUNT
    http_size = 4 * ISLAND_WORDS * http_count
    ssl_rows, ssl_sum = library_rows(vsh, [(0, (CELLSSL_NIDS, CELLSSL_ADDRESSES, CELLSSL_COUNT))], ISLAND_AREA, ssl_size,
                                     SSL_BOUNDS, starts, calls, True)
    http_rows, http_sum = library_rows(vsh, [(1, (CELLHTTP_NIDS, CELLHTTP_ADDRESSES, CELLHTTP_COUNT)),
                                             (2, (CELLHTTPUTIL_NIDS, CELLHTTPUTIL_ADDRESSES, CELLHTTPUTIL_COUNT))],
                                       HTTP_ISLAND_AREA, http_size, HTTP_BOUNDS, starts, calls, False)
    with open(path, "w", encoding="utf-8") as file:
        file.write(f"""/* Generated by vitals-xmb/tools/vsh_ssl.py --header from 4.93's vsh.elf; do not edit.
 * The XMB's own SSL-C and libhttp exports, in its export tables' order: each one's library (0
 * cellSsl, 1 cellHttp, 2 cellHttpUtil), NID, its descriptor and code in the XMB, and its first
 * instruction, which the boot plugin checks before writing a branch over it; and each library's
 * island area, where the branches go (code of the library that nothing reaches but its own exports),
 * with the FNV-1a checksum of what's there */

#define XMB_ISLAND_WORDS {ISLAND_WORDS}u

typedef struct XmbFunction {{
\tuint32_t library, nid, descriptor, code, first;
}} XmbFunction;

#define XMB_SSL_COUNT {CELLSSL_COUNT}u
#define XMB_SSL_ISLAND_AREA 0x{ISLAND_AREA:08X}u
#define XMB_SSL_ISLAND_AREA_SIZE {ssl_size}u
#define XMB_SSL_ISLAND_AREA_FNV1A 0x{ssl_sum:08X}u

static const XmbFunction k_xmb_ssl[XMB_SSL_COUNT] = {{
""" + "\n".join(ssl_rows) + f"""
}};

#define XMB_HTTP_COUNT {http_count}u
#define XMB_HTTP_ISLAND_AREA 0x{HTTP_ISLAND_AREA:08X}u
#define XMB_HTTP_ISLAND_AREA_SIZE {http_size}u
#define XMB_HTTP_ISLAND_AREA_FNV1A 0x{http_sum:08X}u

static const XmbFunction k_xmb_http[XMB_HTTP_COUNT] = {{
""" + "\n".join(http_rows) + "\n};\n")
    print(f"{path}: SSL-C {CELLSSL_COUNT} functions, islands at {ISLAND_AREA:#x} ({ssl_size} bytes); "
          f"libhttp {http_count}, islands at {HTTP_ISLAND_AREA:#x} ({http_size} bytes)")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    # The repository's dumps/ps3/4.93-cex (not committed: Sony's modules), the firmware the tables are
    # for, and the XMB from the custom firmware it was dumped on (vsh/<cfw>/)
    dumps = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(HERE))), "dumps", "ps3", "4.93-cex")
    parser.add_argument("--vsh", default=os.path.join(dumps, "vsh", "evilnat-cobra-8.5", "vsh.elf"))
    parser.add_argument("--libssl", default=os.path.join(dumps, "libssl.prx"))
    parser.add_argument("--header", help="write the boot plugin's tables of SSL-C's and libhttp's functions there")
    arguments = parser.parse_args()
    vsh = Vsh(arguments.vsh)
    names = nids.load_names()
    starts, calls = vsh_functions(vsh)
    function_of = lambda a: starts[bisect.bisect_right(starts, a) - 1]  # noqa: E731
    end_of = lambda a: starts[bisect.bisect_right(starts, a)]  # noqa: E731
    exports = {}
    for i in range(CELLSSL_COUNT):
        nid = vsh.u32(CELLSSL_NIDS + 4 * i)
        exports[vsh.u32(vsh.u32(CELLSSL_ADDRESSES + 4 * i))] = names.get(nid, f"cellSsl_{nid:08X}")
    http = [vsh.u32(vsh.u32(CELLHTTP_ADDRESSES + 4 * i)) for i in range(CELLHTTP_COUNT)]
    print(f"vsh.elf: {len(starts)} functions, {len(calls)} calls, TOC {vsh.toc:#x}")
    if arguments.header:
        write_header(vsh, starts, calls, arguments.header)
        return

    # SSL-C: libssl.prx's functions found in vsh.elf; the dense run of them, from the first export
    known = prx_signatures(arguments.libssl)
    window = [a for a in starts if min(exports) - 0x40000 <= a < max(exports) + 0x40000]
    matched = sorted(a for a in window if signature(vsh.code(a, end_of(a))) in known)
    dense = [a for a in matched if min(exports) <= a <= max(exports) + 0x10000]
    low, high = min(exports), end_of(dense[-1])
    inside = lambda a: low <= a < high  # noqa: E731
    print(f"SSL-C: {low:#x}-{high:#x} ({(high - low) // 1024} KB), {sum(inside(a) for a in matched)} of its "
          f"functions matched to libssl.prx, all {sum(inside(a) for a in exports)} exports in it; "
          f"the XMB's libhttp: {min(http):#x}-{max(http):#x}")

    internal = defaultdict(set)
    for source, target in calls:
        if inside(target) and not inside(source) and target not in exports:
            internal[target].add(function_of(source))
    print(f"Calls from outside SSL-C to its non-exported functions: {len(internal)}")
    for target, sources in sorted(internal.items()):
        print(f"  {target:#x} <- {', '.join(hex(s) for s in sorted(sources))}")

    pointers, toc_users = {}, defaultdict(set)
    for data_offset, vaddr, size in vsh.segments[1:]:
        for o in range(0, size - 7, 4):
            address, toc = struct.unpack_from(">II", vsh.data, data_offset + o)
            if toc == vsh.toc and inside(address):
                pointers[vaddr + o] = address
    offset, start, size = vsh.text
    for o in range(0, size, 4):
        word = struct.unpack_from(">I", vsh.data, offset + o)[0]
        if (word >> 16) & 31 == 2 and word >> 26 in (14, 32, 58):
            displacement = word & (0xFFFC if word >> 26 == 58 else 0xFFFF)
            toc_users[vsh.toc + (displacement - 0x10000 if displacement & 0x8000 else displacement)].add(
                function_of(start + o))
    loaded = sorted({descriptor for slot, users in toc_users.items() for descriptor in pointers
                     if any(not inside(u) for u in users) and vsh.offset(slot) is not None
                     and vsh.u32(slot) == descriptor})
    print(f"Pointers to SSL-C functions that code outside it loads: {len(loaded)}")
    shared = sorted(slot for slot, users in toc_users.items()
                    if any(inside(u) for u in users) and any(not inside(u) for u in users))
    print(f"Globals (TOC slots) used both inside and outside SSL-C: {len(shared)}")
    for slot in shared:
        value = vsh.u32(slot) if vsh.offset(slot) is not None else None
        text = b""
        if value is not None and vsh.offset(value) is not None:
            text = vsh.data[vsh.offset(value):vsh.offset(value) + 48].replace(b"\0", b" ")
        print(f"  {slot:#x} = {value:#x}: {text!r}")

    print("The exports each part of the XMB calls (outside SSL-C):")
    by_area = defaultdict(Counter)
    for source, target in calls:
        if target in exports and not inside(source):
            area = "its libhttp" if min(http) - 0x8000 <= source < low else f"{function_of(source) >> 16 << 16:#08x}"
            by_area[area][exports[target]] += 1
    for area, counter in sorted(by_area.items(), key=lambda item: (item[0] != "its libhttp", item[0])):
        listed = ", ".join(sorted(counter)) if area != "its libhttp" else f"{len(counter)} functions"
        print(f"  {area}: {sum(counter.values())} calls: {listed}")


if __name__ == "__main__":
    main()
