#!/usr/bin/env python3
"""Disassembles a decrypted PS3 module's code with its names: what each call goes to (an import, an
export, or sub_<address>), and what each TOC load reads (its value, and the text it points at):

    tools/ps3_disasm.py <module.prx> fn <name or 0xaddress> [--max N]
    tools/ps3_disasm.py <module.prx> callers <import name> [--before N]

fn prints a function, from its start to the next known function (at most --max instructions, 400);
callers lists each call to an import, with the --before instructions (12) that set up its arguments.
PS3DK's objdump does the disassembling, in the vitals-ps3-sdk image (nyirsh/vitals-ps3-sdk, or VITALS_PS3_SDK_IMAGE); the code
segment's listing is kept in build/disasm/ for the next run."""

import argparse
import hashlib
import os
import re
import struct
import subprocess
import sys

from nids import load_names
from prx import Prx

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CACHE = os.path.join(ROOT, "build", "disasm")
IMAGE = os.environ.get("VITALS_PS3_SDK_IMAGE", "nyirsh/vitals-ps3-sdk:latest")

LINE = re.compile(r"^\s*([0-9a-f]+):\t(?:[0-9a-f]{2} ){4}\t(.*)$")
BRANCH = re.compile(r"\b(bl|b|bne|beq|blt|bgt|ble|bge)[+-]?\s+(?:cr\d,)?0x([0-9a-f]+)")
TOC_LOAD = re.compile(r"\b(lwz|ld|addi)\s+r\d+,(-?\d+)\(r2\)|\baddi\s+r\d+,r2,(-?\d+)")


def listing(prx, path):
    """[(address, instruction)] for the code segment, from the cache or objdump"""
    _kind, offset, vaddr, _paddr, filesz, _memsz = prx.segments[0]
    code = prx.data[offset:offset + filesz]
    digest = hashlib.sha1(code).hexdigest()[:12]
    cached = os.path.join(CACHE, f"{os.path.basename(path)}.{digest}.s")
    if not os.path.isfile(cached):
        os.makedirs(CACHE, exist_ok=True)
        raw = cached + ".bin"
        with open(raw, "wb") as file:
            file.write(code)
        command = ("source /opt/ps3dk-src/scripts/env.sh >/dev/null && powerpc64-ps3-elf-objdump -D -b binary "
                   f"-m powerpc:common64 -EB --adjust-vma={vaddr:#x} /c/{os.path.basename(raw)}")
        result = subprocess.run(["docker", "run", "--rm", "-v", f"{CACHE}:/c", IMAGE, "bash", "-c", command],
                                capture_output=True, text=True, check=True)
        os.remove(raw)
        with open(cached, "w") as file:
            file.write(result.stdout)
    lines = []
    with open(cached) as file:
        for text in file:
            match = LINE.match(text)
            if match:
                lines.append((int(match.group(1), 16), match.group(2).strip()))
    return lines


def symbols(prx):
    """Code addresses' names: imports' stubs, exports' code, and their descriptors"""
    names = load_names()
    found = {}
    for library, entries in prx.imports():
        for nid, stub in entries:
            found[stub] = names.get(nid, f"{library}_{nid:08X}")
    for library, _functions, _variables, entries in prx.exports():
        for nid, descriptor in entries:
            name = names.get(nid, f"{library or 'module'}_{nid:08X}")
            try:
                code = prx.u32(descriptor)
            except ValueError:
                continue
            found.setdefault(code, name)
            found.setdefault(descriptor, name + "@opd")
    return found


def describe_toc(prx, toc, offset):
    try:
        value = prx.u32(toc + offset)
    except ValueError:
        return None
    text = ""
    try:
        string = prx.text(value)
        if 2 <= len(string) <= 80 and all(32 <= ord(c) < 127 for c in string):
            text = f' "{string}"'
    except ValueError:
        pass
    return f"toc[{offset}] = {value:#x}{text}"


def annotate(prx, toc, names, instruction, load_op=True):
    notes = []
    match = BRANCH.search(instruction)
    if match:
        target = int(match.group(2), 16)
        if match.group(1) == "bl":
            notes.append(names.get(target, f"sub_{target:x}"))
        elif target in names:
            notes.append(names[target])
    match = TOC_LOAD.search(instruction)
    if match:
        if match.group(3) is not None:
            notes.append(f"r2{int(match.group(3)):+d}")
        else:
            described = describe_toc(prx, toc, int(match.group(2)))
            if described:
                notes.append(described)
    return f"{instruction:<44} # {'; '.join(notes)}" if notes else instruction


def starts(lines, names):
    """Where functions start: the known names, and every bl's target"""
    found = set(a for a in names if not names[a].endswith("@opd"))
    for _address, instruction in lines:
        match = BRANCH.search(instruction)
        if match and match.group(1) == "bl":
            found.add(int(match.group(2), 16))
    return sorted(found)


def prologue(lines, i, boundaries):
    """The start of the function holding lines[i]: the nearest known start, or a later stack frame's
    set-up (stdu r1, with mflr just before or after) when one comes first, for the functions only
    called through a pointer"""
    known = max((s for s in boundaries if s <= lines[i][0]), default=None)
    for j in range(i, -1, -1):
        address, text = lines[j]
        if known is not None and address <= known:
            return known
        if text.startswith("stdu") and "r1,-" in text:
            nearby = [t for _a, t in lines[max(0, j - 1):j + 2]]
            if any(t.startswith("mflr") for t in nearby):
                return address
    return known


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("module")
    sub = parser.add_subparsers(dest="command", required=True)
    function = sub.add_parser("fn")
    function.add_argument("target")
    function.add_argument("--max", type=int, default=400)
    callers = sub.add_parser("callers")
    callers.add_argument("target")
    callers.add_argument("--before", type=int, default=12)
    arguments = parser.parse_args()

    prx = Prx(arguments.module)
    toc = prx.info()[3]
    names = symbols(prx)
    lines = listing(prx, arguments.module)
    index = {address: i for i, (address, _text) in enumerate(lines)}
    by_name = {name: address for address, name in names.items()}

    if arguments.command == "fn":
        target = arguments.target
        address = int(target, 16) if target.startswith("0x") else by_name.get(target)
        if address is None:
            sys.exit(f"{target}: no such function in {arguments.module}")
        if address in names and names[address].endswith("@opd"):
            address = prx.u32(address)
        if address not in index:
            sys.exit(f"{address:#x} isn't in the code segment")
        boundaries = starts(lines, names)
        following = next((s for s in boundaries if s > address), None)
        print(f"{address:#x} {names.get(address, f'sub_{address:x}')}:")
        for address_now, instruction in lines[index[address]:index[address] + arguments.max]:
            if following is not None and address_now >= following:
                break
            print(f"  {address_now:6x}  {annotate(prx, toc, names, instruction)}")
    else:
        stub = by_name.get(arguments.target)
        if stub is None:
            sys.exit(f"{arguments.target}: {arguments.module} doesn't import it")
        boundaries = starts(lines, names)
        sites = [i for i, (_a, text) in enumerate(lines)
                 if (m := BRANCH.search(text)) and m.group(1) == "bl" and int(m.group(2), 16) == stub]
        for i in sites:
            address = lines[i][0]
            owner = prologue(lines, i, boundaries)
            print(f"-- {address:#x} in {names.get(owner, f'sub_{owner:x}') if owner is not None else '?'}")
            for address_now, instruction in lines[max(0, i - arguments.before):i + 2]:
                print(f"  {address_now:6x}  {annotate(prx, toc, names, instruction)}")
        print(f"{len(sites)} calls")


if __name__ == "__main__":
    main()
