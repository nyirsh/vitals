#!/usr/bin/env python3
"""The RPCS3 installers, each one file with vitals inside it, for the release (make in rpcs3/, which
builds the PS3 app first):

    build/linux-rpcs3-install.sh     install.sh, run with bash
    build/macos-rpcs3-install.sh     the same script, under its macOS name
    build/windows-rpcs3-install.bat  install.ps1, a .bat that runs its PowerShell

What they carry is the PS3 app's own (its staged USRDIR, make app in ps3/): the three debug
levels' libssl and libhttp, fake-signed as RPCS3 and a console's custom firmware load them, Mozilla's bundle, the
example redirects.txt, the changelog, the credits and the third-party notices with their licenses.
Sony's CAs, which Mozilla's certificates leave out, are ps3/common/sony_cas.h's. The payload follows a
line __VITALS_PAYLOAD__ as base64: a .tar.gz for the shell script, a .zip for Windows', both the same
byte for byte at every build of the same files"""
import argparse
import base64
import io
import os
from pathlib import Path
import re
import sys
import tarfile
import zipfile

HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parent
PS3 = REPOSITORY / "ps3"
MARKER = "__VITALS_PAYLOAD__"
MODULES = [f"{module}{suffix}.sprx" for module in ("libssl", "libhttp") for suffix in ("", "-debug1", "-debug2")]
FILES = MODULES + ["cacert.pem", "redirects.txt", "CHANGELOG.md", "CREDITS.md", "THIRD_PARTY_NOTICES.md"]
# A zip's earliest date, for builds that don't depend on when they ran
ZIP_DATE = (1980, 1, 1, 0, 0, 0)


def sony_cas():
    """ps3/common/sony_cas.h's list as "file offset length" lines (length 0: the whole file)"""
    header = (PS3 / "common" / "sony_cas.h").read_text(encoding="utf-8")
    entries = re.findall(r"\{(\d+), \d+, (\d+), (\d+), 0x[0-9a-f]+u, \{", header)
    if not entries:
        raise SystemExit("ps3/common/sony_cas.h: no CAs found")
    return "\n".join(f"{f'CA{int(n):02d}.cer' if int(n) else 'CA_LIST.cer'} {int(offset)} {int(length)}"
                     for n, offset, length in entries)


def collect(usrdir):
    """(name in the payload, bytes) for everything the installers carry"""
    missing = [name for name in FILES if not (usrdir / name).is_file()]
    if missing:
        raise SystemExit(f"{usrdir}: no {', '.join(missing)} (make app in ps3/ first)")
    files = []
    for name in FILES:
        data = (usrdir / name).read_bytes()
        # RPCS3 and the console's custom firmware load fake-signed modules (key revision 0x8000);
        # the scripts tell vitals' from Sony's by it
        if name in MODULES and (len(data) < 9 or data[:4] != b"SCE\0" or data[8] != 0x80):
            raise SystemExit(f"{usrdir / name} isn't fake-signed: make app without SIGNED=1")
        files.append((name, data))
    for licence in sorted((usrdir / "licenses").glob("*.txt")):
        files.append((f"licenses/{licence.name}", licence.read_bytes()))
    return files


def tar_gz(files):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in files:
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), 0o644, 0
            archive.addfile(info, io.BytesIO(data))
    import gzip
    return gzip.compress(raw.getvalue(), compresslevel=9, mtime=0)


def zip_file(files):
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in files:
            info = zipfile.ZipInfo(name, ZIP_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, data)
    return raw.getvalue()


def lines(data):
    text = base64.b64encode(data).decode("ascii")
    return [text[i:i + 76] for i in range(0, len(text), 76)]


def fill(template, version, name, cas):
    text = template.replace("@VERSION@", version).replace("@NAME@", name).replace("@SONY_CAS@", cas)
    left = re.findall(r"@[A-Z_]+@", text)
    if left:
        raise SystemExit(f"left unfilled: {', '.join(sorted(set(left)))}")
    if re.search(rf"^{MARKER}$", text, re.M):
        raise SystemExit(f"the template has a line {MARKER} of its own")
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--usrdir", type=Path, default=PS3 / "build/vitals-app/pkg_files/USRDIR")
    parser.add_argument("--out", type=Path, default=HERE / "build")
    args = parser.parse_args()
    version = (REPOSITORY / "VERSION").read_text(encoding="utf-8").strip()
    cas = sony_cas()
    files = collect(args.usrdir)
    args.out.mkdir(parents=True, exist_ok=True)

    shell = (HERE / "install.sh").read_text(encoding="utf-8")
    payload = "\n".join([MARKER, *lines(tar_gz(files))]) + "\n"
    for name in ("linux-rpcs3-install.sh", "macos-rpcs3-install.sh"):
        path = args.out / name
        path.write_bytes((fill(shell, version, name, cas) + payload).encode("utf-8"))
        os.chmod(path, 0o755)
        print(f"{path}: {path.stat().st_size} bytes")

    # cmd reads a .bat line by line and wants CRLF
    windows = fill((HERE / "install.ps1").read_text(encoding="utf-8"), version, "windows-rpcs3-install.bat", cas)
    text = windows.replace("\r\n", "\n") + "\n".join([MARKER, *lines(zip_file(files))]) + "\n"
    path = args.out / "windows-rpcs3-install.bat"
    path.write_bytes(text.replace("\n", "\r\n").encode("utf-8"))
    print(f"{path}: {path.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
