#!/usr/bin/env python3
"""Checks vitals-dns/src/lv2_493.h's addresses against a dump of a console's lv2 (webMAN's
/dump.ps3?lv2 writes /dev_hdd0/dump_lv2.bin: lv2's memory from 0x8000000000000000), and writes or
checks the signatures the DNS plugin compares on the console before it calls into lv2
(vitals-dns/src/lv2_493_signatures.h):

    tools/lv2_symbols.py build/lv2/dump_lv2_493.bin             check both against the dump
    tools/lv2_symbols.py build/lv2/dump_lv2_493.bin --write     write the signatures from the dump

The syscall table must hold 1024 kernel descriptors followed by zeros, all with LV2_TOC; each
function must have an lv2 descriptor (with that TOC) pointing at it; the dispatcher's call
(LV2_SYSCALL_CALL) must be a blrl, after it loads the handler from its descriptor; LV2_TOC_SLOT must
hold lv2's TOC. A signature is the first SIGNATURE_WORDS instructions of each function the plugin
calls or hooks, and the dispatcher's last five before its call. Exits 1 on any mismatch. Dumps hold
the console's memory: keep them in build/, never in the repository."""
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HEADER = ROOT / "vitals-dns" / "src" / "lv2_493.h"
SIGNATURES = ROOT / "vitals-dns" / "src" / "lv2_493_signatures.h"
BASE = 0x8000000000000000
SIGNATURE_WORDS = 4
# The functions the plugin calls (lv2_call) or chains its hooks to
SIGNED = ("LV2_CELLFS_OPEN", "LV2_CELLFS_CLOSE", "LV2_CELLFS_READ", "LV2_CELLFS_WRITE", "LV2_COPY_FROM_USER",
          "LV2_COPY_TO_USER", "LV2_HANDLER_NET_RECVFROM", "LV2_HANDLER_NET_SENDTO")
# The dispatcher: ld r13,0(r13) twice (the descriptor, then the handler), stdu r1,-112(r1), mtlr r13, blrl
DISPATCH_WORDS = 5


def words(dump, offset, count):
    return list(struct.unpack_from(f">{count}I", dump, offset))


def signatures_text(dump, values):
    lines = ["#ifndef VITALS_DNS_LV2_493_SIGNATURES_H", "#define VITALS_DNS_LV2_493_SIGNATURES_H", "",
             "/* Written by tools/lv2_symbols.py --write from a dump of 4.93 CEX lv2 (Evilnat's Cobra): the first",
             f" * {SIGNATURE_WORDS} instructions of each lv2 function the DNS plugin calls or chains to, and the syscall",
             " * dispatcher's last five before its call. The plugin compares them on the console before calling",
             " * into lv2 at all, and hooks nothing when one differs */", "",
             "#include <stdint.h>", "", "#include \"lv2_493.h\"", "",
             "typedef struct Lv2Signature {", "\tuint32_t offset;", f"\tuint32_t words[{SIGNATURE_WORDS}];", "} Lv2Signature;", "",
             "/* The plugin reports a difference by its index here (plugin.c's STATUS_SIGNATURE) */",
             "static const Lv2Signature k_lv2_signatures[] = {"]
    for name in SIGNED:
        listed = ", ".join(f"0x{w:08X}" for w in words(dump, values[name], SIGNATURE_WORDS))
        lines.append(f"\t{{{name}, {{{listed}}}}},")
    lines.append("};")
    lines.append(f"#define LV2_SIGNATURE_COUNT {len(SIGNED)}u")
    dispatch = values["LV2_SYSCALL_CALL"] - 4 * (DISPATCH_WORDS - 1)
    listed = ", ".join(f"0x{w:08X}" for w in words(dump, dispatch, DISPATCH_WORDS))
    lines += ["", "/* The dispatcher's instructions from LV2_SYSCALL_CALL - 16 to its call */",
              f"static const uint32_t k_lv2_dispatch[{DISPATCH_WORDS}] = {{{listed}}};", "", "#endif", ""]
    return "\n".join(lines)


def main():
    arguments = sys.argv[1:]
    write = "--write" in arguments
    arguments = [a for a in arguments if a != "--write"]
    if len(arguments) != 1:
        sys.exit(__doc__)
    dump = Path(arguments[0]).read_bytes()
    values = {name: int(value, 16) for name, value in re.findall(r"#define (LV2_\w+) (0x[0-9A-Fa-f]+)\b", HEADER.read_text())}
    values.pop("LV2_BASE", None)

    def q(offset):
        return struct.unpack_from(">Q", dump, offset)[0]

    toc, table, call = BASE + values["LV2_TOC"], values["LV2_SYSCALL_TABLE"], values["LV2_SYSCALL_CALL"]
    failed = []
    descriptors = [q(table + 8 * n) for n in range(1024)]
    if q(table + 8 * 1024) != 0 or any(d >> 32 != 0x80000000 or q(d - BASE + 8) != toc for d in descriptors):
        failed.append("LV2_SYSCALL_TABLE / LV2_TOC")
    if words(dump, call, 1)[0] != 0x4E800021:
        failed.append("LV2_SYSCALL_CALL (not a blrl)")
    if q(values["LV2_TOC_SLOT"]) != toc:
        failed.append("LV2_TOC_SLOT (doesn't hold lv2's TOC)")
    own = {707: ("LV2_DESCRIPTOR_NET_RECVFROM", "LV2_HANDLER_NET_RECVFROM"),
           710: ("LV2_DESCRIPTOR_NET_SENDTO", "LV2_HANDLER_NET_SENDTO")}
    for number, (descriptor, handler) in own.items():
        if q(table + 8 * number) - BASE != values[descriptor]:
            failed.append(f"syscall {number}'s descriptor ({descriptor})")
        elif q(values[descriptor]) - BASE != values[handler]:
            failed.append(f"syscall {number}'s handler ({handler})")
    pointed = set()
    for offset in range(0, len(dump) - 16, 8):
        if q(offset + 8) == toc and q(offset) >> 32 == 0x80000000:
            pointed.add(q(offset) - BASE)
    skip = {"LV2_TOC", "LV2_SYSCALL_TABLE", "LV2_SYSCALL_CALL", "LV2_TOC_SLOT", "LV2_DESCRIPTOR_NET_RECVFROM",
            "LV2_DESCRIPTOR_NET_SENDTO", "LV2_SYSCALL_NET_RECVFROM", "LV2_SYSCALL_NET_SENDTO"}
    functions = {name: offset for name, offset in values.items() if name not in skip}
    for name, offset in functions.items():
        if offset not in pointed:
            failed.append(name)

    expected = signatures_text(dump, values)
    if write:
        SIGNATURES.write_text(expected)
        print(f"{SIGNATURES.relative_to(ROOT)} written from this dump")
    elif not SIGNATURES.exists() or SIGNATURES.read_text() != expected:
        failed.append(f"{SIGNATURES.relative_to(ROOT)} (differs from this dump's; --write to write it)")
    for number in (707, 710):
        print(f"syscall {number}: descriptor {descriptors[number]:#x}, handler {q(descriptors[number] - BASE):#x}")
    if failed:
        print("not matching this dump:", ", ".join(failed))
        return 1
    print(f"all {len(functions) + 7} addresses and {len(SIGNED) + 1} signatures match this dump")
    return 0


if __name__ == "__main__":
    sys.exit(main())
