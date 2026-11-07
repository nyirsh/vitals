#!/usr/bin/env python3
"""Puts vitals on a PS3 over FTP (webMAN MOD's server), and takes it off again:

    tools/ps3_comms.py install [--signed] [--debug N]
                                          the modules (libssl, libhttp, the boot plugin, the DNS
                                          kernel plugin), Mozilla's CA bundle, the example
                                          redirects.txt and dns.txt, the boot_plugins.txt line,
                                          a fresh log
    tools/ps3_comms.py log                  fetches /dev_hdd0/vitals/logs/vitals.log (into build/)
    tools/ps3_comms.py app-log              fetches the app's own, /dev_hdd0/vitals/logs/vitals-app.log
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
isn't undone, without Sony's CAs (read from the console's flash) as the app writes it; the
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
import re
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
# The user's own certificates, which libssl reads as they are after Sony's and Mozilla's
CUSTOM_CERTS = VITALS + "/custom-certs.pem"
# What earlier versions put before the user's certificates they merged into the bundle
# (shared/include/vitals/store_certs.h): the bundle is cut there
EARLIER_CUSTOM_MARKER = b"# vitals: custom certificates"
LIBSSL = SYSTEM + "/libssl.sprx"
LIBHTTP = SYSTEM + "/libhttp.sprx"
DNS_PLUGIN = SYSTEM + "/vitals_dns.bin"
# Mozilla's certificates that Sony's lack (common/vitals_paths.h); earlier versions' whole bundle
BUNDLE = SYSTEM + "/mozilla-certs.pem"
BUNDLE_EARLIER = SYSTEM + "/cacert.pem"
# Sony's CAs, which libssl reads from flash (common/sony_cas.h)
SONY_CERTS = "/dev_flash/data/cert"
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
MOVED = {VITALS + "/cacert.pem": BUNDLE, BUNDLE_EARLIER: BUNDLE, VITALS + "/dns.off": DNS_OFF, FLAGS + "/xmb.off": FLAGS + "/xmb-tls.off"}
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
    """Each certificate block in data, as the apps' shared store_certs.c reads them: (whole, start, end, base64)
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


def sony_cas():
    """Sony's CAs as common/sony_cas.h lists them: (file, offset, length), length 0 for the whole file"""
    with open(os.path.join(ROOT, "common", "sony_cas.h"), encoding="utf-8") as file:
        header = file.read()
    entries = re.findall(r"\{(\d+), \d+, (\d+), (\d+), 0x[0-9a-f]+u, \{", header)
    return [(f"CA{int(number):02d}.cer" if int(number) else "CA_LIST.cer", int(offset), int(length))
            for number, offset, length in entries]


def sony_text(read_file):
    """Sony's CAs one after another (read_file(name) gives a flash file's bytes, or None), as the app
    reads them to leave out of Mozilla's file"""
    files, parts = {}, []
    for name, offset, length in sony_cas():
        if name not in files:
            files[name] = read_file(name)
        data = files[name]
        if data is not None:
            parts.append((data[offset:offset + length] if length else data) + b"\n")
    return b"".join(parts) or None


def store_mozilla(bundle, sony):
    """Mozilla's part of the store, as the vitals app writes it (shared/src/store_certs.c): bundle
    up to an earlier merge's marker line, without the whole certificates sony (bytes, or None) holds,
    everything else as it is. Returns (data, kept, left out as Sony's, earlier merge cut)"""
    own = bundle[:find_line(bundle, EARLIER_CUSTOM_MARKER)]
    sonys = {body for whole, _start, _end, body in pem_blocks(sony or b"") if whole}
    out, kept, left_out, at = [], 0, 0, 0
    for whole, start, end, body in pem_blocks(own):
        out.append(own[at:start])
        if whole and body in sonys:
            left_out += 1
        else:
            out.append(own[start:end])
            kept += whole
        at = end
    out.append(own[at:])
    data = b"".join(out)
    if data and not data.endswith(b"\n"):
        data += b"\n"
    return data, kept, left_out, len(own) != len(bundle)


def install_mozilla(ftp, bundle, keep_date):
    """Mozilla's part of the store onto the console, Sony's CAs (read from its flash) left out; the
    date kept when it's the console's own bundle (the app's "Last update") with MFMT where the server
    has it"""
    data, kept, left_out, cut = store_mozilla(bundle, sony_text(lambda name: read(ftp, f"{SONY_CERTS}/{name}")))
    if keep_date and data == bundle:
        print(f"{BUNDLE}: kept (the console's own), {kept} certificates")
        return
    stamp = None
    if keep_date:
        try:
            stamp = ftp.sendcmd("MDTM " + BUNDLE).split()[-1]
        except ftplib.all_errors:
            stamp = None
    write(ftp, BUNDLE, data)
    if stamp:
        try:
            ftp.sendcmd(f"MFMT {stamp} {BUNDLE}")
        except ftplib.all_errors:
            pass  # the date moves to now: the app's Update certificates sets it again
    print(f"{BUNDLE}: {kept} of Mozilla's certificates, {left_out} Sony's already has left out")
    if cut:
        print(f"{BUNDLE}: the copy of {CUSTOM_CERTS} an earlier version merged in taken out (it's read as it is now)")


def install(ftp, signed, debug):
    suffix = ".sprx" if signed else ".fake.sprx"
    sources = {LIBSSL: os.path.join(BUILD, f"vitals-ssl-debug{debug}" if debug else "vitals-ssl", "libssl" + suffix),
               LIBHTTP: os.path.join(BUILD, f"vitals-http-debug{debug}" if debug else "vitals-http", "libhttp" + suffix),
               PLUGIN: os.path.join(BUILD, f"vitals-boot-debug{debug}" if debug else "vitals-boot", "vitals_boot" + suffix),
               DNS_PLUGIN: os.path.join(BUILD, f"vitals-dns-debug{debug}" if debug else "vitals-dns", "vitals_dns.bin"),
               REDIRECTS: os.path.join(ASSETS, "redirects.txt"),
               DNS: os.path.join(ASSETS, "dns.txt")}
    for target, source in sources.items():
        if not os.path.isfile(source):
            sys.exit(f"{source} is missing: build the modules first")
    if not os.path.isfile(bundle_source()):
        sys.exit(f"{bundle_source()} is missing: set VITALS_BUNDLE to Mozilla's CA bundle")
    for folder in (VITALS, SYSTEM, FLAGS, LOGS, REPORTS, "/dev_hdd0/plugins"):
        make_directory(ftp, folder)
    move_earlier_layout(ftp)
    # The console's bundle may be newer (the vitals app's Update certificates), and its lists are the
    # user's: only missing ones are sent
    console_bundle = read(ftp, BUNDLE)
    if console_bundle is not None:
        install_mozilla(ftp, console_bundle, True)
    else:
        with open(bundle_source(), "rb") as file:
            install_mozilla(ftp, file.read(), False)
    for kept in (REDIRECTS, DNS):
        if read(ftp, kept) is not None:
            del sources[kept]
            print(f"{kept}: kept (the console's own)")
    for target, source in sources.items():
        with open(source, "rb") as file:
            write(ftp, target, file.read())
        print(f"{os.path.relpath(source, ROOT)} -> {target}")
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
    for path in (PLUGIN, LIBSSL, LIBHTTP, DNS_PLUGIN, BUNDLE, BUNDLE_EARLIER, INSTALLED, LIBHTTP_ACTIVE,
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


def fetch_log(ftp, path=LOG):
    data = read(ftp, path)
    if data is None:
        sys.exit(f"{path}: not there" + (" (did the console reboot with the plugin?)" if path == LOG else " (has the app run?)"))
    os.makedirs(BUILD, exist_ok=True)
    local = os.path.join(BUILD, os.path.basename(path))
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
    parser.add_argument("command", choices=("install", "log", "app-log", "uninstall", "status", "reboot", "app"))
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
        elif arguments.command == "app-log":
            fetch_log(ftp, APP_LOG)
        else:
            status(ftp)
    finally:
        ftp.quit()


if __name__ == "__main__":
    main()
