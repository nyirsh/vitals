#!/usr/bin/env bash
# vitals @VERSION@ for RPCS3, on macOS and Linux: modern TLS (1.2 and 1.3) and host redirects for the
# games RPCS3 runs, by putting vitals' libssl and libhttp in RPCS3's dev_flash in place of Sony's,
# which it keeps to put back. Everything it installs is inside this file.
#
#   bash @NAME@                    the menu
#   bash @NAME@ install|uninstall|status|certificates [--rpcs3 <folder>]
#
# RPCS3's folder is found on its own (macOS: ~/Library/Application Support/rpcs3; Linux:
# ~/.config/rpcs3, or Flatpak's), or given with --rpcs3. Made by rpcs3/make_installers.py from
# rpcs3/install.sh: edit that, not a generated copy
set -u

VERSION="@VERSION@"
# Sony's CAs as vitals' libssl reads them (ps3/common/sony_cas.h): "file offset length", length 0
# for the whole file. Mozilla's certificates leave these out, as the PS3 app's install does
SONY_CAS="@SONY_CAS@"
MOZILLA_URL="https://curl.se/ca/cacert.pem"

RPCS3_DIR=""
FLASH=""
HDD=""
PAYLOAD=""
YAML=""

# ---- output ----

say() { printf '%s\n' "$*"; }
fail() { printf 'Error: %s\n' "$*" >&2; return 1; }
pause() { [ -t 0 ] && { printf '\nPress Enter to go back to the menu...'; read -r _; }; return 0; }

# ---- RPCS3's folders ----

is_rpcs3_dir() { [ -f "$1/config.yml" ] || [ -f "$1/config/config.yml" ] || [ -d "$1/dev_flash" ]; }

candidates() {
	case "$(uname -s)" in
	Darwin) printf '%s\n' "$HOME/Library/Application Support/rpcs3" ;;
	*)
		printf '%s\n' "${XDG_CONFIG_HOME:-$HOME/.config}/rpcs3" "$HOME/.var/app/net.rpcs3.RPCS3/config/rpcs3" \
			"$HOME/snap/rpcs3-emu/current/.config/rpcs3"
		;;
	esac
}

# The value of a "key: value" line of RPCS3's vfs.yml, unquoted
vfs_value() {
	local file=$1 key=$2
	awk -v key="$key" 'index($0, key ":") == 1 {
		value = substr($0, length(key) + 2); sub(/^[ \t]+/, "", value); sub(/[ \t\r]+$/, "", value)
		if (value ~ /^".*"$/ || value ~ /^'"'"'.*'"'"'$/) value = substr(value, 2, length(value) - 2)
		print value; exit }' "$file"
}

# dev_flash and dev_hdd0 where vfs.yml puts them, else in RPCS3's folder
locate_devices() {
	local vfs="" emulator="$RPCS3_DIR/" value
	FLASH="$RPCS3_DIR/dev_flash"
	HDD="$RPCS3_DIR/dev_hdd0"
	for vfs in "$RPCS3_DIR/config/vfs.yml" "$RPCS3_DIR/vfs.yml"; do [ -f "$vfs" ] && break; vfs=""; done
	YAML="$RPCS3_DIR/config.yml"
	[ -f "$RPCS3_DIR/config/config.yml" ] && YAML="$RPCS3_DIR/config/config.yml"
	[ -n "$vfs" ] || return 0
	value=$(vfs_value "$vfs" '$(EmulatorDir)')
	[ -n "$value" ] && emulator=$value
	value=$(vfs_value "$vfs" "/dev_flash/")
	[ -n "$value" ] && FLASH=${value//\$(EmulatorDir)/$emulator}
	value=$(vfs_value "$vfs" "/dev_hdd0/")
	[ -n "$value" ] && HDD=${value//\$(EmulatorDir)/$emulator}
	FLASH=${FLASH%/}
	HDD=${HDD%/}
}

find_rpcs3() {
	local given=$1 dir
	if [ -n "$given" ]; then
		is_rpcs3_dir "$given" || { fail "$given isn't RPCS3's folder (no config.yml or dev_flash in it)"; return 1; }
		RPCS3_DIR=${given%/}
	else
		while IFS= read -r dir; do
			if is_rpcs3_dir "$dir"; then RPCS3_DIR=$dir; break; fi
		done <<EOF
$(candidates)
EOF
	fi
	while [ -z "$RPCS3_DIR" ]; do
		[ -t 0 ] || { fail "RPCS3's folder wasn't found: give it with --rpcs3 <folder>"; return 1; }
		say "RPCS3's folder wasn't found. Type its path (the folder with config.yml and dev_flash),"
		printf 'or leave it empty to quit: '
		read -r dir
		[ -n "$dir" ] || return 1
		dir=${dir/#\~/$HOME}
		if is_rpcs3_dir "$dir"; then RPCS3_DIR=${dir%/}; else say "That isn't RPCS3's folder."; fi
	done
	locate_devices
}

rpcs3_running() {
	case "$(uname -s)" in
	Darwin) pgrep -f 'RPCS3.app/Contents/MacOS/rpcs3' >/dev/null 2>&1 ;;
	*) pgrep -x rpcs3 >/dev/null 2>&1 || pgrep -f 'rpcs3.*AppImage' >/dev/null 2>&1 ;;
	esac
}

network_off() { [ -f "$YAML" ] && grep -Eq '^[[:space:]]*Internet enabled:[[:space:]]*Disconnected' "$YAML"; }

# ---- what this file carries ----

payload() {
	[ -n "$PAYLOAD" ] && return 0
	PAYLOAD=$(mktemp -d "${TMPDIR:-/tmp}/vitals-rpcs3.XXXXXX") || return 1
	local decode="base64 -d"
	printf 'YQ==' | base64 -d >/dev/null 2>&1 || decode="base64 -D"
	awk 'found { print } /^__VITALS_PAYLOAD__$/ { found = 1 }' "$0" | $decode | tar -xzf - -C "$PAYLOAD" ||
		{ fail "this file's own files can't be read: download it again"; return 1; }
}

cleanup() { [ -n "$PAYLOAD" ] && [ -d "$PAYLOAD" ] && rm -rf -- "$PAYLOAD"; }
trap cleanup EXIT

# ---- vitals' files in RPCS3 ----

vitals_dir() { printf '%s/vitals' "$HDD"; }
system_dir() { printf '%s/vitals/system' "$HDD"; }
flags_dir() { printf '%s/vitals/flags' "$HDD"; }
external() { printf '%s/sys/external/%s' "$FLASH" "$1"; }

# vitals' builds are fake-signed SELFs (key revision 0x8000), Sony's never are
is_vitals_module() { [ -f "$1" ] && [ "$(od -An -tx1 -j8 -N1 "$1" | tr -d ' \n')" = "80" ]; }

installed_version() {
	local file
	file="$(system_dir)/installed.txt"
	[ -f "$file" ] && sed -n 's/^version=//p' "$file" | head -n 1
}

debug_level() {
	if [ -f "$(flags_dir)/debug.2" ]; then echo 2; elif [ -f "$(flags_dir)/debug.1" ]; then echo 1; else echo 0; fi
}

level_name() { case $1 in 1) echo "Basic debug" ;; 2) echo "Full debug" ;; *) echo "Off" ;; esac; }

build_name() { if [ "$2" = 0 ]; then echo "$1.sprx"; else echo "$1-debug$2.sprx"; fi; }

flag() { [ -f "$(flags_dir)/$1" ]; }

set_flag() {
	mkdir -p "$(flags_dir)" || return 1
	if [ "$2" = 1 ]; then : >"$(flags_dir)/$1"; else rm -f -- "$(flags_dir)/$1"; fi
}

# A copy that's never left half-written
put() {
	cp -- "$1" "$2.vitals-new" && mv -f -- "$2.vitals-new" "$2" || { rm -f -- "$2.vitals-new"; fail "can't write $2"; }
}

# Sony's libssl and libhttp, kept in system/sony before vitals' first take their place
keep_sony() {
	local name kept current
	mkdir -p "$(system_dir)/sony" || return 1
	for name in libssl.sprx libhttp.sprx; do
		kept="$(system_dir)/sony/$name"
		current=$(external "$name")
		[ -f "$kept" ] && continue
		[ -f "$current" ] || { fail "RPCS3 has no $name: install the PS3 firmware in RPCS3 first"; return 1; }
		if is_vitals_module "$current"; then
			fail "RPCS3's $name is already vitals' and Sony's isn't kept: reinstall the firmware in RPCS3, then vitals"
			return 1
		fi
		cp -- "$current" "$kept" || { fail "can't keep Sony's $name"; return 1; }
		say "Kept Sony's $name"
	done
}

# dev_flash as the Options say: vitals' libssl unless TLS is off, vitals' libhttp unless HTTP is off
apply() {
	local tls_from="$(system_dir)/libssl.sprx" http_from="$(system_dir)/libhttp.sprx"
	flag tls.off && tls_from="$(system_dir)/sony/libssl.sprx"
	flag http.off && http_from="$(system_dir)/sony/libhttp.sprx"
	put "$tls_from" "$(external libssl.sprx)" && put "$http_from" "$(external libhttp.sprx)"
}

copy_builds() {
	local level=$1
	payload || return 1
	mkdir -p "$(system_dir)" "$(flags_dir)" || return 1
	put "$PAYLOAD/$(build_name libssl "$level")" "$(system_dir)/libssl.sprx" &&
		put "$PAYLOAD/$(build_name libhttp "$level")" "$(system_dir)/libhttp.sprx" || return 1
	rm -f -- "$(flags_dir)/debug.1" "$(flags_dir)/debug.2"
	[ "$level" = 0 ] || : >"$(flags_dir)/debug.$level"
	say "Debug output: $(level_name "$level")"
}

# Sony's CAs one after another, as RPCS3's flash has them
sony_text() {
	local line file offset length path
	while read -r file offset length; do
		[ -n "$file" ] || continue
		path="$FLASH/data/cert/$file"
		[ -f "$path" ] || continue
		if [ "$length" = 0 ]; then cat -- "$path"; else tail -c "+$((offset + 1))" -- "$path" | head -c "$length"; fi
		echo
	done <<EOF
$SONY_CAS
EOF
}

# Mozilla's bundle ($1) without the certificates Sony's list has, into $2: the PS3 app's
# store_certs.c, on whole certificate blocks matched by their base64
store_mozilla() {
	local sony
	sony=$(mktemp "${TMPDIR:-/tmp}/vitals-sony.XXXXXX") || return 1
	sony_text >"$sony"
	awk -v sonyfile="$sony" '
		function body(text) { gsub(/[^A-Za-z0-9+\/=]/, "", text); return text }
		BEGIN {
			while ((getline line < sonyfile) > 0) {
				if (line ~ /^-----BEGIN CERTIFICATE-----/) { inside = 1; text = ""; continue }
				if (inside && line ~ /^-----END CERTIFICATE-----/) { inside = 0; known[body(text)] = 1; continue }
				if (inside) text = text line
			}
			inside = 0
		}
		/^-----BEGIN CERTIFICATE-----/ { inside = 1; block = $0 "\n"; text = ""; next }
		inside && /^-----END CERTIFICATE-----/ {
			inside = 0; block = block $0 "\n"
			if (body(text) in known) left++; else { printf "%s", block; kept++ }
			next
		}
		inside { block = block $0 "\n"; text = text $0; next }
		{ print }
		END {
			if (inside) printf "%s", block
			printf "Mozilla'"'"'s certificates: %d, and %d Sony'"'"'s already has left out\n", kept, left > "/dev/stderr"
		}' "$1" >"$2.vitals-new" && mv -f -- "$2.vitals-new" "$2"
	local rc=$?
	rm -f -- "$sony"
	[ $rc = 0 ] || fail "can't write $2"
}

# ---- what the menu does ----

do_install() {
	local level version
	version=$(installed_version)
	rpcs3_running && { fail "RPCS3 is running: close it first"; return 1; }
	[ -f "$(external libssl.sprx)" ] || { fail "RPCS3 has no firmware: install it first (File, Install Firmware)"; return 1; }
	payload || return 1
	mkdir -p "$(system_dir)" "$(flags_dir)" "$(vitals_dir)/logs" || { fail "can't make $(vitals_dir)"; return 1; }
	keep_sony || return 1
	level=$(debug_level)
	copy_builds "$level" || return 1
	if [ -f "$(system_dir)/mozilla-certs.pem" ]; then
		say "Kept Mozilla's certificates already in $(system_dir)/mozilla-certs.pem"
	else
		store_mozilla "$PAYLOAD/cacert.pem" "$(system_dir)/mozilla-certs.pem" || return 1
	fi
	if [ -f "$(vitals_dir)/redirects.txt" ]; then
		say "Kept $(vitals_dir)/redirects.txt"
	else
		cp -- "$PAYLOAD/redirects.txt" "$(vitals_dir)/redirects.txt" && say "Wrote the example $(vitals_dir)/redirects.txt"
	fi
	apply || return 1
	printf 'version=%s\n' "$VERSION" >"$(system_dir)/installed.txt" || return 1
	rm -f -- "$(vitals_dir)/logs/vitals.log"
	if [ -z "$version" ]; then say "vitals $VERSION installed"
	elif [ "$version" = "$VERSION" ]; then say "vitals $VERSION reinstalled"
	else say "vitals $version replaced with $VERSION"; fi
	network_off && say "Note: RPCS3's network is off (Configuration, Network, Network Status: Connected)"
	return 0
}

do_uninstall() {
	local name kept
	rpcs3_running && { fail "RPCS3 is running: close it first"; return 1; }
	for name in libssl.sprx libhttp.sprx; do
		kept="$(system_dir)/sony/$name"
		if [ -f "$kept" ]; then
			put "$kept" "$(external "$name")" && say "Put Sony's $name back" || return 1
		elif is_vitals_module "$(external "$name")"; then
			say "Sony's $name isn't kept: reinstall the firmware in RPCS3 to get it back"
		fi
	done
	rm -f -- "$(system_dir)/sony/libssl.sprx" "$(system_dir)/sony/libhttp.sprx" "$(system_dir)/libssl.sprx" \
		"$(system_dir)/libhttp.sprx" "$(system_dir)/mozilla-certs.pem" "$(system_dir)/installed.txt" \
		"$(flags_dir)/debug.1" "$(flags_dir)/debug.2" "$(vitals_dir)/logs/vitals.log" "$(vitals_dir)/logs/vitals-app.log"
	# The user's lists and the Options' switches stay, as the app leaves them
	rmdir "$(system_dir)/sony" "$(system_dir)" "$(vitals_dir)/logs" "$(flags_dir)" "$(vitals_dir)" 2>/dev/null
	say "vitals uninstalled"
}

do_certificates() {
	local download sum expected actual
	download=$(mktemp "${TMPDIR:-/tmp}/vitals-cacert.XXXXXX") || return 1
	say "Downloading Mozilla's certificates from $MOZILLA_URL..."
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL "$MOZILLA_URL" -o "$download" && expected=$(curl -fsSL "$MOZILLA_URL.sha256")
	elif command -v wget >/dev/null 2>&1; then
		wget -q "$MOZILLA_URL" -O "$download" && expected=$(wget -qO- "$MOZILLA_URL.sha256")
	else
		rm -f -- "$download"
		fail "neither curl nor wget is here to download with"
		return 1
	fi || { rm -f -- "$download"; fail "the download failed: the certificates weren't changed"; return 1; }
	if command -v sha256sum >/dev/null 2>&1; then sum=sha256sum; else sum="shasum -a 256"; fi
	actual=$($sum "$download" | awk '{print $1}')
	expected=$(printf '%s' "$expected" | awk '{print $1}')
	if [ "$actual" != "$expected" ] || [ "$(grep -c 'BEGIN CERTIFICATE' "$download")" -lt 100 ]; then
		rm -f -- "$download"
		fail "the download doesn't match curl's checksum: the certificates weren't changed"
		return 1
	fi
	mkdir -p "$(system_dir)" && store_mozilla "$download" "$(system_dir)/mozilla-certs.pem"
	local rc=$?
	rm -f -- "$download"
	[ $rc = 0 ] && say "Written to $(system_dir)/mozilla-certs.pem"
	return $rc
}

certificates_date() {
	local file
	file="$(system_dir)/mozilla-certs.pem"
	[ -f "$file" ] || return 0
	if date -r "$file" +%Y-%m-%d >/dev/null 2>&1; then date -r "$file" +%Y-%m-%d; else stat -c %y "$file" | cut -c1-10; fi
}

status_line() {
	local version
	version=$(installed_version)
	if [ -z "$version" ]; then
		echo "not installed"
	elif ! flag tls.off && ! is_vitals_module "$(external libssl.sprx)"; then
		echo "$version, but RPCS3's libssl is Sony's again (a firmware reinstall?): Reinstall"
	else
		echo "$version installed, debug output $(level_name "$(debug_level)")"
	fi
}

do_status() {
	say "RPCS3: $RPCS3_DIR"
	say "dev_flash: $FLASH"
	say "dev_hdd0: $HDD"
	say "vitals: $(status_line)"
	say "TLS: $(tls_state)"
	say "HTTP: $(http_state)"
	local date
	date=$(certificates_date)
	[ -n "$date" ] && say "Certificates: last update $date"
	network_off && say "RPCS3's network is off (Configuration, Network, Network Status: Connected)"
	return 0
}

tls_state() { if flag tls.off; then echo "Off (Sony TLS)"; else echo "On (vitals TLS)"; fi; }

http_state() {
	if flag http.off; then echo "Off (Sony HTTP, no redirects)"
	elif flag redirects.off; then echo "Redirects off (vitals HTTP)"
	else echo "On (vitals HTTP and redirects)"; fi
}

show_document() {
	payload || return 1
	if [ -t 1 ] && command -v less >/dev/null 2>&1; then
		cat -- "$@" | less -R
	else
		cat -- "$@"
		pause
	fi
}

# Applies a switch's change right away when vitals is installed
switched() {
	[ -n "$(installed_version)" ] || return 0
	rpcs3_running && say "RPCS3 is running: the change applies from its next start"
	apply
}

options_menu() {
	local choice level
	while :; do
		say ""
		say "Options"
		say "  1) TLS: $(tls_state)"
		say "  2) HTTP: $(http_state)"
		say "  3) Debug output: $(level_name "$(debug_level)") (the log goes to $(vitals_dir)/logs/vitals.log)"
		say "     DNS rules aren't in RPCS3: use its own Configuration, Network, IP/Hosts switches"
		say "  0) Back"
		printf 'Choose: '
		read -r choice || return 0
		case $choice in
		1) if flag tls.off; then set_flag tls.off 0; else set_flag tls.off 1; fi && switched ;;
		2)
			if flag http.off; then
				set_flag http.off 0 && set_flag redirects.off 0
			elif flag redirects.off; then
				set_flag redirects.off 0 && set_flag http.off 1
			else
				set_flag redirects.off 1
			fi && switched
			;;
		3)
			level=$(( ($(debug_level) + 1) % 3 ))
			if [ -n "$(installed_version)" ]; then
				rpcs3_running && { fail "RPCS3 is running: close it first"; continue; }
				copy_builds "$level" && apply
			else
				set_flag debug.1 0 && set_flag debug.2 0 && { [ "$level" = 0 ] || set_flag "debug.$level" 1; }
			fi
			;;
		0 | "") return 0 ;;
		esac
	done
}

menu() {
	local choice version action
	while :; do
		version=$(installed_version)
		if [ -z "$version" ]; then action=Install; elif [ "$version" = "$VERSION" ]; then action=Reinstall; else action=Update; fi
		say ""
		say "vitals $VERSION for RPCS3"
		say "RPCS3: $RPCS3_DIR"
		say "vitals: $(status_line)"
		local date
		date=$(certificates_date)
		[ -n "$date" ] && say "Certificates: last update $date"
		network_off && say "Note: RPCS3's network is off (Configuration, Network, Network Status: Connected)"
		rpcs3_running && say "Note: RPCS3 is running: close it before installing or uninstalling"
		say ""
		case $action in
		Install) say "  1) Install: lets games connect to modern secure (TLS 1.2 and 1.3) sites" ;;
		Update) say "  1) Update: replaces vitals $version with $VERSION" ;;
		*) say "  1) Reinstall: fixes a broken installation" ;;
		esac
		[ -n "$version" ] && say "  2) Uninstall: puts Sony's libraries back and removes vitals' files"
		say "  3) Update certificates: downloads the latest trusted websites certificates"
		say "  4) Options: turns each part of vitals on or off, and picks the debug output"
		say "  5) Changelog"
		say "  6) Credits"
		say "  0) Exit"
		printf 'Choose: '
		read -r choice || return 0
		say ""
		case $choice in
		1) do_install; pause ;;
		2) [ -n "$version" ] && { do_uninstall; pause; } ;;
		3) do_certificates; pause ;;
		4) options_menu ;;
		5) payload && show_document "$PAYLOAD/CHANGELOG.md" ;;
		6) payload && show_document "$PAYLOAD/CREDITS.md" "$PAYLOAD/THIRD_PARTY_NOTICES.md" ;;
		0) return 0 ;;
		esac
	done
}

main() {
	local action="" given=""
	while [ $# -gt 0 ]; do
		case $1 in
		--rpcs3) given=${2:-}; shift ;;
		--rpcs3=*) given=${1#--rpcs3=} ;;
		-h | --help) sed -n '2,12p' "$0"; return 0 ;;
		install | uninstall | status | certificates) action=$1 ;;
		*) fail "unknown argument $1 (--help)"; return 2 ;;
		esac
		shift
	done
	find_rpcs3 "$given" || return 1
	case $action in
	install) do_install ;;
	uninstall) do_uninstall ;;
	status) do_status ;;
	certificates) do_certificates ;;
	*) menu ;;
	esac
}

main "$@"
exit $?
