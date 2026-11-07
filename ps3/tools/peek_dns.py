#!/usr/bin/env python3
"""Reads the DNS kernel plugin's counts and its last DNS queries from the console's lv2 memory, with
webMAN's /peek.lv2 (the plugin logs where they are, with Full debug installed: "counts at
0x8000000000xxxxxx" in vitals.log):

    tools/peek_dns.py <offset from lv2's base, in hex, e.g. 63b9c0>

The layout is vitals-dns/kernel/plugin.c's State: a "vitalsdn" marker, the sendto and recvfrom
calls, the queries seen, the rules loaded, the answers rewritten, the queries renamed and what the
plugin did when it started (its status), then the
last 8 queries (a 56-byte name, its type, how it went out: 1 to port 53, 2 connected, plus 16 when a
rule applied and 32 when it was renamed)."""
import sys, urllib.request, re, html, struct
sys.path.insert(0, 'tools')
import ps3_comms as p
p.load_env()
OFFSET = int(sys.argv[1], 16)

def peek(offset):
    body = urllib.request.urlopen(f"http://{p.host()}/peek.lv2?{offset:x}", timeout=20).read().decode('latin1')
    t = html.unescape(re.sub(r'<[^>]+>', '\n', re.sub(r'<script.*?</script>', '', body, flags=re.S)))
    rows = {}
    for line in t.splitlines():
        parts = line.split()
        if len(parts) >= 17 and re.fullmatch(r'[0-9A-Fa-f]{8}', parts[0]) and all(re.fullmatch(r'[0-9A-Fa-f]{2}', b) for b in parts[1:17]):
            rows[int(parts[0], 16)] = bytes.fromhex("".join(parts[1:17]))
    return rows

rows = {}
for start in (OFFSET & ~0xf, (OFFSET & ~0xf) + 0x100, (OFFSET & ~0xf) + 0x200):
    rows.update(peek(start))
data = b"".join(rows[a] for a in sorted(rows) if a >= OFFSET & ~0xf)[OFFSET & 0xf:]
assert data[:8] == b"vitalsdn", data[:16]
sendto, recvfrom, queries, rules, rewritten, renamed, status = struct.unpack(">QQQQQQQ", data[8:64])
STATUS = {1: "started", 3: "off (dns.off)", 4: "no rules in dns.txt",
          5: "not hooked: the syscall table isn't lv2's own", 6: "hooked",
          0x100: "not 4.93's lv2: the syscall dispatcher differs", 0x101: "not 4.93's lv2: its TOC isn't where expected"}
SIGNED = ("cellFsOpen", "cellFsClose", "cellFsRead", "cellFsWrite", "copy_from_user", "copy_to_user",
          "recvfrom's handler", "sendto's handler")
text = STATUS.get(status) or (f"not 4.93's lv2: {SIGNED[status - 0x200]} differs" if 0x200 <= status < 0x200 + len(SIGNED)
                              else f"{status:#x}")
print(f"status: {text}")
print(f"sendto {sendto}, recvfrom {recvfrom}, DNS queries seen {queries}, rules {rules}, queries renamed {renamed}, "
      f"answers rewritten {rewritten}")
for i in range(min(queries, 8)):
    slot = data[64 + 64 * i: 64 + 64 * (i + 1)]
    name = slot[:56].split(b"\0")[0].decode('latin1')
    kind, how = struct.unpack(">II", slot[56:64])
    way = {1: 'to port 53', 2: 'connected'}.get(how & 15, '?')
    print(f"  {name}  type {kind}  {way}{'  RULE' if how & 16 else ''}{' renamed' if how & 32 else ''}")
