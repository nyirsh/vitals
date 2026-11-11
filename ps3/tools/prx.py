"""A PS3 PRX (decrypted, ELF) as its module info describes it: name, version, TOC, the libraries
it exports and the ones it imports, each with its function NIDs and addresses.

The module info is at the first segment's p_paddr minus its p_offset, as a virtual address; the
export entries (0x1C bytes each) and import entries (0x2C) it points at give a library's name, its
NID table and its address (export) or stub (import) table. Everything is big-endian."""

import struct


class Prx:
    def __init__(self, path):
        with open(path, "rb") as file:
            self.data = file.read()
        if self.data[:4] != b"\x7fELF" or self.data[4] != 2 or self.data[5] != 2:
            raise ValueError(f"{path}: not a big-endian ELF64 (decrypt it first)")
        phoff = struct.unpack_from(">Q", self.data, 0x20)[0]
        count = struct.unpack_from(">H", self.data, 0x38)[0]
        self.segments = []
        for i in range(count):
            kind, _flags, offset, vaddr, paddr, filesz, memsz, _align = struct.unpack_from(
                ">IIQQQQQQ", self.data, phoff + 56 * i)
            self.segments.append((kind, offset, vaddr, paddr, filesz, memsz))
        _kind, offset, _vaddr, paddr, _filesz, _memsz = self.segments[0]
        self.module_info = paddr - offset

    def file_offset(self, vaddr):
        for kind, offset, start, _paddr, filesz, _memsz in self.segments:
            if kind == 1 and start <= vaddr < start + filesz:
                return offset + vaddr - start
        raise ValueError(f"address {vaddr:#x} is in no loaded segment")

    def u32(self, vaddr):
        return struct.unpack_from(">I", self.data, self.file_offset(vaddr))[0]

    def u16(self, vaddr):
        return struct.unpack_from(">H", self.data, self.file_offset(vaddr))[0]

    def text(self, vaddr):
        start = self.file_offset(vaddr)
        return self.data[start:self.data.index(b"\0", start)].decode("latin1")

    def info(self):
        """(name, attributes, (major, minor), toc, exports_start, exports_end, imports_start, imports_end)"""
        start = self.file_offset(self.module_info)
        attributes, major, minor = struct.unpack_from(">HBB", self.data, start)
        name = self.data[start + 4:start + 32].split(b"\0")[0].decode("latin1")
        toc, exports_start, exports_end, imports_start, imports_end = struct.unpack_from(
            ">IIIII", self.data, start + 32)
        return name, attributes, (major, minor), toc, exports_start, exports_end, imports_start, imports_end

    def _entries(self, start, end):
        at = start
        while at < end:
            size = self.data[self.file_offset(at)]
            if size == 0:
                raise ValueError(f"empty library entry at {at:#x}")
            yield at, size
            at += size

    def exports(self):
        """[(library, function count, variable count, [(nid, address)])]; the module's own entry
        (start, stop, module info) has no library name"""
        _n, _a, _v, _t, start, end, _is, _ie = self.info()
        result = []
        for at, _size in self._entries(start, end):
            functions, variables = self.u16(at + 6), self.u16(at + 8)
            name, nids, addresses = self.u32(at + 0x10), self.u32(at + 0x14), self.u32(at + 0x18)
            entries = [(self.u32(nids + 4 * i), self.u32(addresses + 4 * i)) for i in range(functions + variables)]
            result.append((self.text(name) if name else None, functions, variables, entries))
        return result

    def imports(self):
        """[(library, [(nid, stub address)])]"""
        _n, _a, _v, _t, _es, _ee, start, end = self.info()
        result = []
        for at, _size in self._entries(start, end):
            functions = self.u16(at + 6)
            name, nids, stubs = self.u32(at + 0x10), self.u32(at + 0x14), self.u32(at + 0x18)
            entries = [(self.u32(nids + 4 * i), self.u32(stubs + 4 * i)) for i in range(functions)]
            result.append((self.text(name) if name else None, entries))
        return result
