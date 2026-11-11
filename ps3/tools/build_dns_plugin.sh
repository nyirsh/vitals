#!/bin/bash
# Builds vitals' DNS kernel plugin (vitals-dns/kernel) into build/vitals-dns/vitals_dns.bin, inside the
# vitals-ps3-sdk image (make dns-plugin runs it there). lv2 code, with PS3DK's compiler in LP64 (lv2's
# pointers are 64-bit), freestanding: one flat image from byte 0 (vitals-dns/kernel/plugin.ld).
# Nothing relocates a kernel plugin, so it's linked at two addresses and the two images must be the
# same; then it's padded as Cobra wants it: more than 0x230 bytes, a multiple of 8.
# tools/build_dns_plugin.sh 1 or 2 builds the debug log's level in build/vitals-dns-debugN (make
# dns-plugin DEBUG=N), as libssl and libhttp have theirs.
# For diagnosis, tools/build_dns_plugin.sh pass-through builds build/vitals-dns-pass/vitals_dns.bin,
# whose hooks only count their calls and pass them on, and watch-only build/vitals-dns-watch's, which
# also copies and reads queries but applies no rule (plugin.c)
set -euo pipefail
source /opt/ps3dk-src/scripts/env.sh > /dev/null
out=build/vitals-dns
variant=()
case "${1:-0}" in
0) ;;
1 | 2) out=build/vitals-dns-debug$1; variant=(-DVITALS_DEBUG=$1) ;;
pass-through) out=build/vitals-dns-pass; variant=(-DVITALS_DNS_PASS_THROUGH) ;;
watch-only) out=build/vitals-dns-watch; variant=(-DVITALS_DNS_WATCH_ONLY) ;;
*) echo "usage: tools/build_dns_plugin.sh [0 | 1 | 2 | pass-through | watch-only]" >&2; exit 1 ;;
esac
mkdir -p "$out"
cflags=(-mlp64 -O2 -ffreestanding -fno-builtin -fno-jump-tables -nostdlib -fno-stack-protector -fno-asynchronous-unwind-tables
	-fno-unwind-tables -ffunction-sections -fdata-sections -fno-zero-initialized-in-bss -Wall -Wextra -Werror
	-fno-tree-loop-distribute-patterns -Ivitals-dns/src -I../shared/dns -I../shared/include -Icommon)
powerpc64-ps3-elf-gcc "${cflags[@]}" -c vitals-dns/kernel/entry.S -o "$out/entry.o"
powerpc64-ps3-elf-gcc "${cflags[@]}" "${variant[@]}" -c vitals-dns/kernel/plugin.c -o "$out/plugin.o"
# The DNS message code shared with the Vita (../shared/dns), as the host tests run it
powerpc64-ps3-elf-gcc "${cflags[@]}" -c ../shared/dns/dns_message.c -o "$out/dns_message.o"
# The rules engine (vitals-dns/src) and the list parser (../shared/src/host_map.c); without the
# callback-based list reader (redirect_list.c), as C function pointers can't work here
powerpc64-ps3-elf-gcc "${cflags[@]}" -DVITALS_DNS_NO_READER -c vitals-dns/src/dns_rules.c -o "$out/dns_rules.o"
powerpc64-ps3-elf-gcc "${cflags[@]}" -c ../shared/src/host_map.c -o "$out/host_map.o"
for base in 0 0x100000; do
	# .bss is turned into data on purpose (plugin.ld), which ld mentions
	powerpc64-ps3-elf-gcc -mlp64 -nostdlib -nostartfiles -static -T vitals-dns/kernel/plugin.ld \
		-Wl,--defsym,BASE=$base -Wl,--no-warn-rwx-segments -o "$out/plugin-$base.elf" "$out/entry.o" "$out/plugin.o" "$out/dns_message.o" \
		"$out/dns_rules.o" "$out/host_map.o" \
		2>&1 | { grep -v "type changed to PROGBITS" || true; }
	powerpc64-ps3-elf-objcopy -O binary -R .opd "$out/plugin-$base.elf" "$out/plugin-$base.bin"
done
if ! cmp -s "$out/plugin-0.bin" "$out/plugin-0x100000.bin"; then
	echo "the plugin's image depends on where it's linked: something in it needs relocating" >&2
	exit 1
fi
# The only indirect call may be lv2_call's: a C function pointer goes through PS3DK's 32-bit CellOS
# descriptors, which can't hold a kernel address (and aren't in the image), so calling one jumps
# nowhere. One did: the list reader's callbacks froze the console
indirect=$(powerpc64-ps3-elf-objdump -d "$out/plugin-0.elf" | grep -cE $'\t(bctrl?|bcctrl?)( |$)' || true)
if [ "$indirect" != 1 ]; then
	echo "the plugin has $indirect indirect calls, only lv2_call's may be there: a C function pointer can't work here" >&2
	powerpc64-ps3-elf-objdump -d "$out/plugin-0.elf" | grep -E $'\t(bctrl?|bcctrl?)( |$)' >&2
	exit 1
fi
size=$(stat -c %s "$out/plugin-0.bin")
padded=$(( size > 0x238 ? size : 0x238 ))
padded=$(( (padded + 7) / 8 * 8 ))
cp "$out/plugin-0.bin" "$out/vitals_dns.bin"
truncate -s "$padded" "$out/vitals_dns.bin"
echo "$out/vitals_dns.bin: $padded bytes, the same image at any address"
