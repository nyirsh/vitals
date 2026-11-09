"""Parse the plaintext SELF modules built by this project (name, imports, exports)."""

from pathlib import Path
import struct
import zlib


class Module:
    def __init__(self, path, data=None):
        self.path = Path(path)
        self.data = self.path.read_bytes() if data is None else data
        if self.data[:7] != b'\x7fELF\x01\x01\x01':
            raise ValueError('Expected plaintext ELF: ' + str(path))
        offset = struct.unpack_from('<I', self.data, 28)[0]
        size, count = struct.unpack_from('<HH', self.data, 42)
        self.segments = [struct.unpack_from('<8I', self.data, offset + i * size) for i in range(count)]
        entry = struct.unpack_from('<I', self.data, 24)[0]
        self.metadata_segment, self.metadata_offset = entry >> 30, entry & 0x3fffffff
        self.info = self.segment(self.metadata_segment)[self.metadata_offset:self.metadata_offset + 0x5c]
        if len(self.info) != 0x5c:
            raise ValueError('Truncated module metadata')
        self.name = self.info[4:31].split(b'\0', 1)[0].decode('ascii')
        self.nid = struct.unpack_from('<I', self.info, 0x34)[0]
        self.text = self.segment(0)
        self.exports = self.libraries(True)
        self.imports = self.libraries(False)

    def segment(self, index):
        segment = self.segments[index]
        return self.data[segment[1]:segment[1] + segment[4]]

    def read(self, address, size):
        for kind, offset, base, _, length, *_ in self.segments:
            if kind == 1 and base <= address and address + size <= base + length:
                return self.data[offset + address - base:offset + address - base + size]
        raise ValueError('Unmapped module address')

    def libraries(self, export):
        begin, end = struct.unpack_from('<II', self.info, 0x24 if export else 0x2c)
        records = {}
        while begin < end:
            size = self.text[begin] if export else struct.unpack_from('<H', self.text, begin)[0]
            count = struct.unpack_from('<H', self.text, begin + 6)[0]
            if export and size == 0x20:
                library, _, nids, entries = struct.unpack_from('<4I', self.text, begin + 16)
            elif not export and size == 0x34:
                library = struct.unpack_from('<I', self.text, begin + 16)[0]
                nids, entries = struct.unpack_from('<2I', self.text, begin + 28)
            elif not export and size == 0x24:
                library, _, nids, entries = struct.unpack_from('<4I', self.text, begin + 12)
            else:
                raise ValueError(f'Unknown library record size {size} in {self.path}, export={export}')
            for i in range(count):
                nid = struct.unpack('<I', self.read(nids + i * 4, 4))[0]
                address = struct.unpack('<I', self.read(entries + i * 4, 4))[0]
                records[library, nid] = address
            begin += size
        if begin != end:
            raise ValueError('Library table span mismatch')
        return records


def bundled_module(path):
    """Read our plaintext compressed SELF, without accepting encrypted firmware."""
    data = path.read_bytes()
    if len(data) < 0x80 or data[:4] != b'SCE\0':
        raise ValueError('Expected bundled plaintext SELF: ' + str(path))
    elf_offset, phdr_offset = struct.unpack_from('<QQ', data, 0x40)
    records_offset = struct.unpack_from('<Q', data, 0x58)[0]
    header = data[elf_offset:elf_offset + 52]
    if len(header) != 52 or header[:7] != b'\x7fELF\x01\x01\x01':
        raise ValueError('Invalid bundled ELF header')
    phdr_size, count = struct.unpack_from('<HH', header, 42)
    if phdr_size != 32 or count > 16 or phdr_offset + count * 32 > len(data) or records_offset + count * 32 > len(data):
        raise ValueError('Bundled segment table bounds')
    program_headers = data[phdr_offset:phdr_offset + count * 32]
    segments = [struct.unpack_from('<8I', program_headers, i * 32) for i in range(count)]
    size = max(segment[1] + segment[4] for segment in segments)
    if size > 16 * 1024 * 1024:
        raise ValueError('Bundled ELF size limit')
    elf = bytearray(size)
    elf[:52] = header
    for i, segment in enumerate(segments):
        offset, length, compression, encryption = struct.unpack_from('<4Q', data, records_offset + i * 32)
        if encryption != 2 or compression not in (1, 2) or offset + length > len(data):
            raise ValueError('Bundled segment must be bounded plaintext')
        payload = data[offset:offset + length]
        if compression == 2:
            payload = zlib.decompress(payload)
        if len(payload) != segment[4]:
            raise ValueError('Bundled decompressed segment size')
        elf[segment[1]:segment[1] + segment[4]] = payload
    phoff = struct.unpack_from('<I', header, 28)[0]
    elf[phoff:phoff + len(program_headers)] = program_headers
    return Module(path, bytes(elf))
