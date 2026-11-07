#!/bin/sh
# Runs an app in RPCS3 with vitals' libssl in Sony's place, prints the TTY, then puts Sony's back:
#   tools/rpcs3_run.sh build/vitals-ssl/libssl.fake.sprx <app.elf> [seconds]
# RPCS3 loads the real libssl and libhttp by default; its first run of a new build can sit
# compiling for a while, so give that one longer. RPCS3's network is turned on for the run
# (config.yml's "Internet enabled: Connected") and set back as it was after. With VITALS_HTTP set to
# a module, it goes in libhttp's place too (vitals' libhttp, make http), and Sony's goes back after;
# RPCS3 answers cellHttp with its own functions (HLE) unless config.yml's "Libraries Control" lists
# libhttp.sprx:lle, which every run sets, so Sony's real libhttp or vitals' runs (config.yml is
# restored after).
set -eu

module=$1
app=$2
seconds=${3:-60}
rpcs3=${RPCS3:-/Applications/RPCS3.app/Contents/MacOS/rpcs3}
external="$HOME/Library/Application Support/rpcs3/dev_flash/sys/external"
logs="$HOME/Library/Caches/rpcs3"
config="$HOME/Library/Application Support/rpcs3/config.yml"
# Mozilla's CA bundle, where vitals' libssl reads it (VITALS_BUNDLE, else the Vita's, in ../vita)
bundle=${VITALS_BUNDLE:-$(dirname "$0")/../../vita/vitals-app/assets/mozilla-certs.pem}
hdd="$HOME/Library/Application Support/rpcs3/dev_hdd0"

[ -f "$external/libssl.sprx" ] || { echo "no libssl.sprx in RPCS3's dev_flash (install the firmware first)" >&2; exit 1; }
[ ! -e "$external/libssl.sprx.sony" ] || { echo "$external/libssl.sprx.sony exists: a run was interrupted; put it back as libssl.sprx first" >&2; exit 1; }

[ ! -e "$config.vitals" ] || { echo "$config.vitals exists: a run was interrupted; put it back as config.yml first" >&2; exit 1; }
http=${VITALS_HTTP:-}
if [ -n "$http" ]; then
	[ -f "$external/libhttp.sprx" ] || { echo "no libhttp.sprx in RPCS3's dev_flash" >&2; exit 1; }
	[ ! -e "$external/libhttp.sprx.sony" ] || { echo "$external/libhttp.sprx.sony exists: a run was interrupted; put it back as libhttp.sprx first" >&2; exit 1; }
	cp -p "$external/libhttp.sprx" "$external/libhttp.sprx.sony"
fi

cp -p "$external/libssl.sprx" "$external/libssl.sprx.sony"
cp -p "$config" "$config.vitals"
restore() {
	mv -f "$external/libssl.sprx.sony" "$external/libssl.sprx"
	if [ -n "$http" ]; then mv -f "$external/libhttp.sprx.sony" "$external/libhttp.sprx"; fi
	mv -f "$config.vitals" "$config"
}
trap restore EXIT INT TERM
cp "$module" "$external/libssl.sprx"
if [ -n "$http" ]; then cp "$http" "$external/libhttp.sprx"; fi
if [ -f "$bundle" ]; then mkdir -p "$hdd/vitals/system" && cp "$bundle" "$hdd/vitals/system/mozilla-certs.pem"; fi
perl -pi -e 's/^(\s*Internet enabled:).*/$1 Connected/' "$config"
perl -0pi -e 's/(\n  Libraries Control:)\n    \[\]/$1\n    - libhttp.sprx:lle/' "$config"
grep -q "libhttp.sprx:lle" "$config" || echo "warning: couldn't set libhttp.sprx:lle in $config; RPCS3 may use its own cellHttp" >&2

case $app in /*) ;; *) app="$PWD/$app" ;; esac
# RPCS3 ignores SIGALRM, so it runs in the background and is stopped when the time is up
"$rpcs3" --no-gui "$app" > /dev/null 2>&1 &
pid=$!
perl -e 'select(undef, undef, undef, shift)' "$seconds"
kill -9 "$pid" 2> /dev/null || true
wait "$pid" 2> /dev/null || true

cat "$logs/TTY.log"
grep -E '·[EF] ' "$logs/RPCS3.log" | grep -v 'RSX:' | head -20 || true
