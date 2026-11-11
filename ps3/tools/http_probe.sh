#!/bin/sh
# Runs the libhttp probe (tests/http-probe) in RPCS3 against tests/http-probe/server.py and keeps
# its lines in build/http-probe/<label>.txt:
#   tools/http_probe.sh sony                       Sony's libhttp
#   tools/http_probe.sh vitals <libhttp module>    vitals' (VITALS_HTTP for rpcs3_run.sh), then
#                                                  the diff against Sony's (tests/http-probe/sony-4.93.txt),
#                                                  which has to be vitals-differences.txt's
#   tools/http_probe.sh host <probe binary>        the probe built for this machine with vitals'
#                                                  libhttp and libssl (tests/host/http, make test),
#                                                  its diff against Sony's host-differences.txt's:
#                                                  vitals-differences.txt's, and the host's own
#                                                  (64-bit pointers in header lists' sizes, and a
#                                                  refused connection's real ECONNREFUSED where
#                                                  RPCS3's gives 0x80710316)
# libssl is vitals' release build either way. sony-4.93.txt is Sony's 4.93 libhttp's run, in RPCS3.
# With VITALS_PROBE_SSL=sony, libssl stays RPCS3's own, Sony's, for either libhttp: its lines go in
# build/http-probe/<label>-sony-ssl.txt, and vitals' are compared with Sony's libhttp's on that same
# libssl (run `sony` first), as vitals' libhttp runs with tls.off
set -eu
label=$1
sony_ssl=${VITALS_PROBE_SSL:-}
here=$(cd "$(dirname "$0")/.." && pwd)
out="$here/build/http-probe"
mkdir -p "$out"
# The https servers' certificates: a CA, one valid for 127.0.0.1, one for another name, one
# self-signed and one expired; the CA goes where the probe reads it (RPCS3 empties /dev_hdd0/tmp)
tls="$out/tls"
if [ ! -f "$tls/expired.pem" ]; then
	mkdir -p "$tls"
	(
		cd "$tls"
		openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 -subj "/O=vitals probe/CN=vitals probe CA" \
			-addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
			-keyout ca.key -out ca.pem 2> /dev/null
		for name in valid wronghost expired; do
			case $name in wronghost) san="DNS:wrong.example";; *) san="IP:127.0.0.1";; esac
			printf 'subjectAltName=%s\nbasicConstraints=CA:FALSE\n' "$san" > $name.ext
			# Sony's check compares the host with the CN and DNS names, not IP addresses
			case $name in wronghost) cn=wrong.example;; *) cn=127.0.0.1;; esac
			openssl req -newkey rsa:2048 -nodes -subj "/O=vitals probe/CN=$cn" -keyout $name.key -out $name.csr 2> /dev/null
			if [ $name = expired ]; then
				# openssl ca takes dates in the past on every OpenSSL version; x509 only from 3.4
				mkdir -p expired-ca
				: > expired-ca/index.txt
				echo 01 > expired-ca/serial
				printf '[ca]\ndefault_ca=d\n[d]\ndatabase=expired-ca/index.txt\nserial=expired-ca/serial\nnew_certs_dir=expired-ca\ndefault_md=sha256\npolicy=p\n[p]\ncommonName=supplied\norganizationName=optional\n' > expired-ca/config
				openssl ca -batch -notext -preserveDN -config expired-ca/config -cert ca.pem -keyfile ca.key -in $name.csr \
					-startdate 20200101000000Z -enddate 20210101000000Z -extfile $name.ext -out $name.pem 2> /dev/null
			else
				openssl x509 -req -in $name.csr -CA ca.pem -CAkey ca.key -CAcreateserial -sha256 -days 3650 \
					-extfile $name.ext -out $name.pem 2> /dev/null
			fi
		done
		openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 -subj "/O=vitals probe/CN=127.0.0.1" \
			-addext "subjectAltName=IP:127.0.0.1" -keyout selfsigned.key -out selfsigned.pem 2> /dev/null
	)
fi
probe_hdd="$HOME/Library/Application Support/rpcs3/dev_hdd0/vitals-probe"
mkdir -p "$probe_hdd"
cp "$tls/ca.pem" "$probe_hdd/ca.pem"
# vitals' additions (source/additions.c): a redirect list and a User-Agent line in /dev_hdd0/vitals/
# for the run, RPCS3's own put back after it
if [ "$label" = host ]; then
	vitals_dir="$out/host-hdd/vitals"
else
	vitals_dir="$HOME/Library/Application Support/rpcs3/dev_hdd0/vitals"
fi
mkdir -p "$vitals_dir" "$out/kept"
for file in redirects.txt useragent.txt; do
	rm -f "$out/kept/$file"
	[ -f "$vitals_dir/$file" ] && mv "$vitals_dir/$file" "$out/kept/$file"
done
printf '# the probe'"'"'s (tools/http_probe.sh)\nold.vitals-probe.invalid  127.0.0.1\n' > "$vitals_dir/redirects.txt"
printf '# the probe'"'"'s (tools/http_probe.sh)\n\n  libhttp/4.9.3-000 (CellOS) vitals-probe/1.0  \n' > "$vitals_dir/useragent.txt"
restore() {
	for file in redirects.txt useragent.txt; do
		rm -f "$vitals_dir/$file"
		[ -f "$out/kept/$file" ] && mv "$out/kept/$file" "$vitals_dir/$file"
	done
	return 0
}
python3 -I "$here/tests/http-probe/server.py" 18080 "$tls" > "$out/server.log" 2>&1 &
server=$!
trap 'kill $server 2> /dev/null || true; restore' EXIT INT TERM
sleep 1
if [ "$label" = host ]; then
	# AddressSanitizer's reports go to stderr, and fail the run
	host_hdd="$out/host-hdd"
	mkdir -p "$host_hdd/vitals-probe"
	cp "$tls/ca.pem" "$host_hdd/vitals-probe/ca.pem"
	# The probe ends without freeing what it was testing with, which only Linux's sanitizer minds
	ASAN_OPTIONS=detect_leaks=0 VITALS_PROBE_HDD=$host_hdd "$2" > "$out/host.raw" || echo "probe: exited with $?" >> "$out/host.raw"
	# The recorded differences have macOS's ECONNREFUSED (61, 0x3d); Linux's is 111 (0x6f)
	sed 's/0x8071056f/0x8071053d/g' "$out/host.raw" > "$out/host.raw.same" && mv "$out/host.raw.same" "$out/host.raw"
	cat "$out/host.raw"
else
	libssl="$here/build/vitals-ssl/libssl.fake.sprx"
	if [ "$sony_ssl" = sony ]; then
		# A copy: rpcs3_run.sh puts the module it's given over RPCS3's own, and back after
		cp "$HOME/Library/Application Support/rpcs3/dev_flash/sys/external/libssl.sprx" "$out/sony-libssl.sprx"
		libssl="$out/sony-libssl.sprx"
	fi
	if [ "$label" = vitals ]; then
		VITALS_HTTP=$2 "$here/tools/rpcs3_run.sh" "$libssl" "$here/build/http-probe/http-probe.elf" 60
	else
		"$here/tools/rpcs3_run.sh" "$libssl" "$here/build/http-probe/http-probe.elf" 60
	fi
fi | sed -n 's/^ *probe: //p' > "$out/$label${sony_ssl:+-sony-ssl}.txt"
result="$out/$label${sony_ssl:+-sony-ssl}.txt"
echo "$result: $(wc -l < "$result") lines"
# vitals' differs from Sony's where it does on purpose: those lines (Sony's "< ", vitals' "> ", in
# order, without line numbers) are in tests/http-probe/vitals-differences.txt, and any other
# difference fails the run. VITALS_PROBE_RECORD=1 writes that file from this run, to review
if [ "$label" = vitals ] || [ "$label" = host ]; then
	expected="$here/tests/http-probe/$label-differences.txt"
	baseline="$here/tests/http-probe/sony-4.93.txt"
	[ "$sony_ssl" = sony ] && baseline="$out/sony-sony-ssl.txt"
	python3 -c 'import difflib, sys
old, new = (open(p, encoding="latin1").read().splitlines() for p in sys.argv[1:3])
with open(sys.argv[3], "w", encoding="latin1") as out:
    for tag, a, b, c, d in difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes():
        if tag != "equal":
            out.writelines([f"< {line}\n" for line in old[a:b]] + [f"> {line}\n" for line in new[c:d]])' \
		"$baseline" "$result" "$out/differences.txt"
	if [ "${VITALS_PROBE_RECORD:-0}" = 1 ]; then
		cp "$out/differences.txt" "$expected"
		echo "$expected: $(wc -l < "$expected") lines recorded"
	elif [ ! -s "$out/differences.txt" ] && [ ! -s "$expected" ]; then
		echo "the same as Sony's libhttp"
	elif [ -f "$expected" ] && cmp -s "$out/differences.txt" "$expected"; then
		echo "the same as Sony's libhttp, but for the $(grep -c '^>' "$expected") documented lines (tests/http-probe/$label-differences.txt)"
	else
		diff "$expected" "$out/differences.txt" || true
		exit 1
	fi
fi
