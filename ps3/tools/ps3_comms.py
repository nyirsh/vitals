#!/usr/bin/env python3
"""Puts vitals on a PS3 over FTP (webMAN MOD's server), and takes it off again:

    tools/ps3_comms.py install [--signed] [--debug N]
                                          the modules (libssl, libhttp, the boot plugin, the DNS
                                          kernel plugin), Mozilla's CA bundle, the example
                                          redirects.txt and dns.txt, the boot_plugins.txt line,
                                          a fresh log
    tools/ps3_comms.py log                  fetches /dev_hdd0/vitals/logs/vitals.log (into build/)
    tools/ps3_comms.py uninstall            the lines out of the two lists, the modules deleted
    tools/ps3_comms.py status               what's on the console now
    tools/ps3_comms.py reboot               a full reboot through webMAN MOD, waiting until it's back
    tools/ps3_comms.py app                  uploads the vitals app (make app) to /dev_hdd0/packages/,
                                          for the XMB's Package Manager to install

The console is PS3_HOST, port PS3_PORT (21), from the environment or else from .env at the top of
the repository (copy .env.example). install uploads the fake-signed containers unless --signed
asks for the real-signed ones (don't, on a console: the PlayStation Store app hangs on a black
screen loading the real-signed libssl and libhttp), the release builds of libssl, libhttp, the boot plugin and the DNS
plugin (build/vitals-ssl, build/vitals-http, build/vitals-boot, build/vitals-dns) unless --debug 1 or
2 asks for debug ones (build/vitals-ssl-debugN and the like, make install DEBUG=N builds them), and Mozilla's CA bundle (VITALS_BUNDLE, else the app's,
vitals-app/assets/mozilla-certs.pem) when the console has none, so the app's Update certificates
isn't undone, with the user's custom-certs.pem added after Mozilla's as the app adds them; the
example redirects.txt and dns.txt likewise only when the console has none, so the user's lists stay. The boot plugin maps libssl and libhttp at every boot, and loads the DNS
kernel plugin (make dns-plugin), except on a boot after one that didn't end properly
(vitals-boot/src/boot.c). The DNS plugin isn't listed in boot_plugins_kernel.txt: loaded from there it froze the
console at every boot, so install takes out any line an earlier version put
there. It keeps a copy of each list in build/ before changing it. A reboot applies install and uninstall: a hard one,
as Cobra loads its boot plugins when the system starts (webMAN MOD's /restart.ps3?hard, on its web
server at PS3_HTTP_PORT, 80)."""

import argparse
import datetime
import ftplib
import io
import os
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BUILD = os.path.join(ROOT, "build")

BOOT_PLUGINS = "/dev_hdd0/boot_plugins.txt"
PLUGIN = "/dev_hdd0/plugins/vitals_boot.sprx"
BOOT_PLUGINS_KERNEL = "/dev_hdd0/boot_plugins_kernel.txt"
# vitals' files, as common/vitals_paths.h has them: /dev_hdd0/vitals holds only the user's lists; the
# modules and what the installers keep are in system/, the switches in flags/, the logs in logs/,
# the app's connection test reports in reports/
VITALS = "/dev_hdd0/vitals"
SYSTEM = VITALS + "/system"
FLAGS = VITALS + "/flags"
LOGS = VITALS + "/logs"
REPORTS = VITALS + "/reports"
REDIRECTS = VITALS + "/redirects.txt"
DNS = VITALS + "/dns.txt"
USER_AGENT = VITALS + "/useragent.txt"
# The user's own certificates, added after Mozilla's in the bundle (vitals-app/src/custom_certs.c)
CUSTOM_CERTS = VITALS + "/custom-certs.pem"
CUSTOM_MARKER = b"# vitals: custom certificates (" + CUSTOM_CERTS.encode() + b")\n"
LIBSSL = SYSTEM + "/libssl.sprx"
LIBHTTP = SYSTEM + "/libhttp.sprx"
DNS_PLUGIN = SYSTEM + "/vitals_dns.bin"
BUNDLE = SYSTEM + "/cacert.pem"
# Which version and debug level are installed, as the vitals app writes it (vitals-app/src/install.c)
INSTALLED = SYSTEM + "/installed.txt"
# The boot plugin's mark of a boot that maps vitals' libhttp, for the app's test
LIBHTTP_ACTIVE = SYSTEM + "/libhttp.active"
# Each component's switch: while it's there, that component is off from the next boot
# (xmb-tls.off and xmb-http.off count only for a boot plugin built with XMB=1, which isn't installed)
SWITCHES = [FLAGS + "/" + name for name in ("tls.off", "http.off", "dns.off", "redirects.off")]
DNS_OFF = FLAGS + "/dns.off"
LOG = LOGS + "/vitals.log"
APP_LOG = LOGS + "/vitals-app.log"
ASSETS = os.path.join(ROOT, "vitals-app", "assets")
# Earlier versions kept everything in /dev_hdd0/vitals itself and the logs in /dev_hdd0/tmp: install
# moves what the user chose or got to its folder (MOVED), and deletes the rest (GONE)
# (and the single XMB switch of earlier builds, xmb.off, is xmb-tls.off now)
MOVED = {VITALS + "/cacert.pem": BUNDLE, VITALS + "/dns.off": DNS_OFF, FLAGS + "/xmb.off": FLAGS + "/xmb-tls.off"}
GONE = [VITALS + "/" + name for name in ("libssl.sprx", "libhttp.sprx", "vitals_dns.bin", "installed.txt",
                                         "libhttp.active", "libhttp.once", "dns.once", "dns.loading", "dns.delay",
                                         "boot_plugins.txt.bak", "boot_plugins_kernel.txt.bak")] + [
    "/dev_hdd0/tmp/vitals.log", "/dev_hdd0/tmp/vitals-app.log"]
PACKAGES = "/dev_hdd0/packages"


def load_env():
    """.env's KEY=VALUE lines into the environment, where they aren't set already (# comments)"""
    try:
        with open(os.path.join(ROOT, ".env"), encoding="utf-8") as env:
            lines = env.read().splitlines()
    except FileNotFoundError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.startswith("export "):
            key = key[len("export "):]
        key = key.strip()
        if not os.environ.get(key):
            os.environ[key] = value.strip().strip("'\"")


def host():
    value = os.environ.get("PS3_HOST", "")
    if not value:
        sys.exit("PS3_HOST isn't set: put the console's address in .env (cp .env.example .env)")
    return value


def connect():
    # webMAN MOD's replies after a listing carry bytes that aren't UTF-8 (0xb0, a degree sign)
    ftp = ftplib.FTP(encoding="latin1")
    ftp.connect(host(), int(os.environ.get("PS3_PORT", "21")), timeout=30)
    ftp.login()
    return ftp


def reboot():
    """A hard reboot through webMAN MOD (without a trailing $, webMAN's default mode stays as it
    is), then waits until its FTP server answers again"""
    url = f"http://{host()}:{os.environ.get('PS3_HTTP_PORT', '80')}/restart.ps3?hard"
    try:
        urllib.request.urlopen(url, timeout=15).read()
    except (urllib.error.URLError, OSError):
        pass  # webMAN may drop the connection as the console goes down
    print(f"{url}: rebooting")
    # First until FTP stops answering (the console is going down), then until it answers again
    for going_down, limit in ((True, 60), (False, 240)):
        deadline = time.monotonic() + limit
        while time.monotonic() < deadline:
            try:
                connect().quit()
                answering = True
            except ftplib.all_errors:  # OSError included
                answering = False
            if answering != going_down:
                break
            time.sleep(2 if going_down else 5)
        else:
            sys.exit("The console didn't go down within a minute: is webMAN MOD's web server on?"
                     if going_down else "The console didn't answer within 4 minutes: check it")
    print("The console is back.")


def read(ftp, path):
    """The file's bytes, or None when it isn't there"""
    data = io.BytesIO()
    try:
        ftp.retrbinary("RETR " + path, data.write)
    except ftplib.error_perm:
        return None
    return data.getvalue()


def write(ftp, path, data):
    ftp.storbinary("STOR " + path, io.BytesIO(data))


def make_directory(ftp, path):
    try:
        ftp.mkd(path)
    except ftplib.error_perm:
        pass  # already there


def delete(ftp, path):
    try:
        ftp.delete(path)
        return True
    except ftplib.error_perm:
        return False


def plugin_lines(data):
    """boot_plugins.txt's lines and the line ending it uses"""
    text = (data or b"").decode("latin1")
    ending = "\r\n" if "\r\n" in text else "\n"
    return [line for line in text.splitlines()], ending


def add_line(ftp, path, entry):
    """entry at the end of the list at path, unless it's there; a copy of the list in build/ first"""
    current = read(ftp, path)
    if current is not None:
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = os.path.join(BUILD, f"{os.path.basename(path)}.{stamp}")
        os.makedirs(BUILD, exist_ok=True)
        with open(backup, "wb") as file:
            file.write(current)
        print(f"{path} kept as {os.path.relpath(backup, ROOT)}")
    lines, ending = plugin_lines(current)
    if entry not in (line.strip() for line in lines):
        lines.append(entry)
        write(ftp, path, (ending.join(lines) + ending).encode("latin1"))
        print(f"{path}: added {entry}")
    else:
        print(f"{path}: already has {entry}")


def remove_line(ftp, path, entry):
    """entry out of the list at path, the rest as it was"""
    current = read(ftp, path)
    if current is None:
        return
    lines, ending = plugin_lines(current)
    kept = [line for line in lines if line.strip() != entry]
    if len(kept) != len(lines):
        write(ftp, path, (ending.join(kept) + ending).encode("latin1") if kept else b"")
        print(f"{path}: removed {entry}")


def bundle_source():
    """Mozilla's CA bundle: VITALS_BUNDLE, else the app's (curl's cacert.pem, make update-certs)"""
    return os.environ.get("VITALS_BUNDLE", os.path.join(ASSETS, "mozilla-certs.pem"))


PEM_BEGIN, PEM_END = b"-----BEGIN CERTIFICATE-----", b"-----END CERTIFICATE-----"
BASE64 = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
SPACES = frozenset(b" \t\r\n")


def find_line(data, needle, start=0):
    """Where needle starts a line in data from start, or len(data)"""
    at = data.find(needle, start)
    while at != -1:
        if at == 0 or data[at - 1] == 0x0A:
            return at
        at = data.find(needle, at + 1)
    return len(data)


def pem_blocks(data):
    """Each certificate block in data, as the app's custom_certs.c reads them: (whole, start, end, base64)
    for a whole one, its base64 without spaces; base64 None for a broken one (no END, another block
    before it, anything but base64 inside, text after END, or empty)"""
    at = 0
    while True:
        start = find_line(data, PEM_BEGIN, at)
        if start == len(data):
            return
        body = start + len(PEM_BEGIN)
        close, again = data.find(PEM_END, body), find_line(data, PEM_BEGIN, body)
        if close == -1 or again < close:
            yield False, start, again, None
            at = again
            continue
        end = data.find(b"\n", close)
        end = len(data) if end == -1 else end + 1
        inside, after = data[body:close], data[close + len(PEM_END):end]
        whole = (all(c in BASE64 or c in SPACES for c in inside) and any(c in BASE64 for c in inside)
                 and all(c in SPACES for c in after))
        yield whole, start, end, bytes(c for c in inside if c in BASE64) if whole else None
        at = end


def merge_custom_certificates(bundle, custom):
    """The bundle with the user's certificates after Mozilla's, as the vitals app merges them
    (vitals-app/src/custom_certs.c): an earlier merge cut off at its marker line, then, when custom has
    any certificate the bundle doesn't, the marker and each such certificate once. custom may be None.
    Returns (merged, added, duplicates, skipped)"""
    own = bundle[:find_line(bundle, b"# vitals: custom certificates")]
    if own and not own.endswith(b"\n"):
        own += b"\n"
    seen = {body for whole, _start, _end, body in pem_blocks(own) if whole}
    merged, added, duplicates, skipped = [own], 0, 0, 0
    for whole, start, end, body in pem_blocks(custom or b""):
        if not whole:
            skipped += 1
        elif body in seen:
            duplicates += 1
        else:
            seen.add(body)
            if added == 0:
                merged.append(CUSTOM_MARKER)
            block = custom[start:end]
            merged.append(block if block.endswith(b"\n") else block + b"\n")
            added += 1
    return b"".join(merged), added, duplicates, skipped


def install_custom_certificates(ftp):
    """custom-certs.pem merged into the console's bundle as the app does it at an install, the bundle's
    date kept (the app's "Last update": Mozilla's, not this merge's) with MFMT where the server has it"""
    bundle = read(ftp, BUNDLE)
    if bundle is None:
        return
    custom = read(ftp, CUSTOM_CERTS)
    merged, added, duplicates, skipped = merge_custom_certificates(bundle, custom)
    if merged == bundle:
        if custom is not None:
            print(f"{CUSTOM_CERTS}: {added} already in {BUNDLE}")
    else:
        try:
            stamp = ftp.sendcmd("MDTM " + BUNDLE).split()[-1]
        except ftplib.all_errors:
            stamp = None
        write(ftp, BUNDLE, merged)
        if stamp:
            try:
                ftp.sendcmd(f"MFMT {stamp} {BUNDLE}")
            except ftplib.all_errors:
                pass  # the date moves to now: the app's Update certificates sets it again
        print(f"{CUSTOM_CERTS}: {added} added to {BUNDLE}" if custom is not None
              else f"{BUNDLE}: earlier custom certificates taken out ({CUSTOM_CERTS} is gone)")
    if duplicates:
        print(f"{CUSTOM_CERTS}: {duplicates} already there, added once")
    if skipped:
        print(f"{CUSTOM_CERTS}: {skipped} skipped, not a whole certificate")


def install(ftp, signed, debug):
    suffix = ".sprx" if signed else ".fake.sprx"
    sources = {LIBSSL: os.path.join(BUILD, f"vitals-ssl-debug{debug}" if debug else "vitals-ssl", "libssl" + suffix),
               LIBHTTP: os.path.join(BUILD, f"vitals-http-debug{debug}" if debug else "vitals-http", "libhttp" + suffix),
               PLUGIN: os.path.join(BUILD, f"vitals-boot-debug{debug}" if debug else "vitals-boot", "vitals_boot" + suffix),
               DNS_PLUGIN: os.path.join(BUILD, f"vitals-dns-debug{debug}" if debug else "vitals-dns", "vitals_dns.bin"),
               BUNDLE: bundle_source(),
               REDIRECTS: os.path.join(ASSETS, "redirects.txt"),
               DNS: os.path.join(ASSETS, "dns.txt")}
    for target, source in sources.items():
        if not os.path.isfile(source):
            sys.exit(f"{source} is missing: " + ("set VITALS_BUNDLE to Mozilla's CA bundle" if target == BUNDLE
                                                else "build the modules first"))
    for folder in (VITALS, SYSTEM, FLAGS, LOGS, REPORTS, "/dev_hdd0/plugins"):
        make_directory(ftp, folder)
    move_earlier_layout(ftp)
    # The console's bundle may be newer (the vitals app's Update certificates), and its lists are the
    # user's: only missing ones are sent
    for kept in (BUNDLE, REDIRECTS, DNS):
        if read(ftp, kept) is not None:
            del sources[kept]
            print(f"{kept}: kept (the console's own)")
    for target, source in sources.items():
        with open(source, "rb") as file:
            write(ftp, target, file.read())
        print(f"{os.path.relpath(source, ROOT)} -> {target}")
    install_custom_certificates(ftp)
    add_line(ftp, BOOT_PLUGINS, PLUGIN)
    with open(os.path.join(ROOT, "..", "VERSION"), encoding="utf-8") as file:
        version = file.read().strip()
    write(ftp, INSTALLED, f"version={version}\ndebug={debug or 0}\n".encode())
    print(f"{INSTALLED}: version {version}, debug level {debug or 0}")
    # Never listed: loaded at boot, the DNS plugin froze the console at every boot
    remove_line(ftp, BOOT_PLUGINS_KERNEL, VITALS + "/vitals_dns.bin")
    remove_line(ftp, BOOT_PLUGINS_KERNEL, DNS_PLUGIN)
    if delete(ftp, LOG):
        print(f"{LOG}: old log deleted")
    print("Reboot the console to apply it.")


def move_earlier_layout(ftp):
    """An earlier version's files: the certificate update's bundle, dns.off, xmb.off and the app's reports to
    their folders, the rest deleted (MOVED, GONE)"""
    for old, new in MOVED.items():
        if read(ftp, old) is None:
            continue
        if read(ftp, new) is None:
            ftp.rename(old, new)
            print(f"{old} -> {new} (an earlier version's place)")
        else:
            delete(ftp, old)
    for old in GONE:
        if delete(ftp, old):
            print(f"{old}: deleted (an earlier version's place)")
    try:
        names = [name.rsplit("/", 1)[-1] for name in ftp.nlst(VITALS)]
    except ftplib.error_perm:
        names = []
    for name in names:
        if name.startswith("connection-test-") and name.endswith(".txt"):
            ftp.rename(f"{VITALS}/{name}", f"{REPORTS}/{name}")
            print(f"{VITALS}/{name} -> {REPORTS}/ (an earlier version's place)")


def uninstall(ftp):
    remove_line(ftp, BOOT_PLUGINS, PLUGIN)
    remove_line(ftp, BOOT_PLUGINS_KERNEL, DNS_PLUGIN)
    move_earlier_layout(ftp)
    # system/ and logs/ go; the user's lists, flags/ and reports/ stay, as on the Vita
    for path in (PLUGIN, LIBSSL, LIBHTTP, DNS_PLUGIN, BUNDLE, INSTALLED, LIBHTTP_ACTIVE,
                 SYSTEM + "/boot_plugins.txt.bak", SYSTEM + "/boot_plugins_kernel.txt.bak", LOG, APP_LOG):
        if delete(ftp, path):
            print(f"{path}: deleted")
    for folder in (SYSTEM, LOGS, FLAGS, REPORTS, VITALS):
        try:
            ftp.rmd(folder)
            print(f"{folder}: deleted")
        except ftplib.error_perm:
            pass
    print("Reboot the console to apply it.")


def fetch_log(ftp):
    data = read(ftp, LOG)
    if data is None:
        sys.exit(f"{LOG}: not there (did the console reboot with the plugin?)")
    os.makedirs(BUILD, exist_ok=True)
    local = os.path.join(BUILD, "vitals.log")
    with open(local, "wb") as file:
        file.write(data)
    sys.stdout.write(data.decode("latin1"))
    print(f"-- saved as {os.path.relpath(local, ROOT)}")


def upload_app(ftp):
    """build/vitals-app/vitals-app.pkg as /dev_hdd0/packages/vitals-<version>.pkg"""
    source = os.path.join(BUILD, "vitals-app", "vitals-app.pkg")
    if not os.path.isfile(source):
        sys.exit(f"{source} is missing: build the app first (make app)")
    with open(os.path.join(ROOT, "..", "VERSION"), encoding="utf-8") as file:
        version = file.read().strip()
    target = f"{PACKAGES}/vitals-{version}.pkg"
    make_directory(ftp, PACKAGES)
    with open(source, "rb") as file:
        ftp.storbinary("STOR " + target, file)
    print(f"{os.path.relpath(source, ROOT)} -> {target} ({os.path.getsize(source)} bytes)")
    print("Install it from the XMB: Game, Package Manager, Install Package Files, Standard.")


def status(ftp):
    for listed in (BOOT_PLUGINS, BOOT_PLUGINS_KERNEL):
        lines, _ending = plugin_lines(read(ftp, listed))
        print(f"{listed}:")
        for line in lines:
            print(f"  {line}")
    for path in [PLUGIN, LIBSSL, LIBHTTP, DNS_PLUGIN, LIBHTTP_ACTIVE, BUNDLE, INSTALLED, REDIRECTS, DNS, USER_AGENT, CUSTOM_CERTS,
                 *SWITCHES, LOG, APP_LOG]:
        try:
            size = ftp.size(path)
        except ftplib.error_perm:
            size = None
        print(f"{path}: {'missing' if size is None else f'{size} bytes'}")


def main():
    load_env()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("install", "log", "uninstall", "status", "reboot", "app"))
    parser.add_argument("--signed", action="store_true", help="install the real-signed containers (the Store app hangs loading them)")
    parser.add_argument("--debug", type=int, choices=(0, 1, 2), default=0,
                        help="install libssl's and libhttp's debug builds of that level (build/vitals-ssl-debugN, build/vitals-http-debugN)")
    arguments = parser.parse_args()
    if arguments.command == "reboot":
        reboot()
        return
    ftp = connect()
    try:
        if arguments.command == "install":
            install(ftp, arguments.signed, arguments.debug)
        elif arguments.command == "uninstall":
            uninstall(ftp)
        elif arguments.command == "app":
            upload_app(ftp)
        elif arguments.command == "log":
            fetch_log(ftp)
        else:
            status(ftp)
    finally:
        ftp.quit()


if __name__ == "__main__":
    main()
