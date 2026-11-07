#!/usr/bin/env python3
"""Talks to a Vita over FTP (VitaShell's server, started with SELECT in VitaShell):

    tools/vita_comms.py app [VPK]      uploads the vitals app (make, build/vitals-app/vitals-app.vpk, or
                                       VPK) to ux0:data/vitals/vitals-app.vpk, for VitaShell to install
    tools/vita_comms.py fetch          fetches the app's test reports and BrowserLeaks dumps from
                                       ux0:data/vitals, the crash dumps from ux0:data and any SceWebKit
                                       dumps from ux0:data/vitals-dump into build/vita-fetch/, then
                                       deletes them from the Vita
    tools/vita_comms.py status         what's on the Vita now: config.txt, vitals' plugin and modules,
                                       the certificate store, the user's lists and the switches

The Vita is VITA_HOST, port VITA_PORT (1337, VitaShell's), from the environment or else from .env at
the top of vita/ (copy .env.example). Installing, uninstalling and the debug output are the app's: they
need vs0: mounted for writing and a reboot, which the app takes care of.

What fetch brings back can hold PSN details (the reports list each request): it stays in build/, which
isn't committed."""

import argparse
import ftplib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BUILD = os.path.join(ROOT, "build")
FETCHED = os.path.join(BUILD, "vita-fetch")
APP_VPK = os.path.join(BUILD, "vitals-app", "vitals-app.vpk")

# VitaShell's FTP paths: each device is a folder at the top, named with its colon
VITALS = "/ux0:/data/vitals"
APP_TARGET = VITALS + "/vitals-app.vpk"
CONFIG = "/ur0:/tai/config.txt"
# What the app installs (vitals-app/install.c): the kernel plugin in ur0:tai, vitals' modules in
# ux0:data/vitals/system
INSTALLED = [
    "/ur0:/tai/vitals.skprx",
    VITALS + "/system/libhttp.suprx",
    VITALS + "/system/libssl.suprx",
    VITALS + "/system/ScePsp2Compat.suprx",
    VITALS + "/system/vitals.suprx",
    # vitals' certificate store (the system's own on vs0 is left as it was)
    VITALS + "/system/CA_LIST.cer",
]
# The user's lists and certificates
LISTS = [VITALS + "/" + name for name in ("redirects.txt", "dns.txt", "custom-certs.pem")]
# The Options' switches (vitals-app/vitals_paths.h): each part is off while its .off is there
SWITCHES = [VITALS + "/flags/" + name for name in ("tls.off", "http.off", "dns.off", "redirects.off")]
# What fetch takes: (folder, the names it takes, whether the folder may be missing)
FETCH = [
    (VITALS, ("vitals-testresults-", "browserleaks-"), False),
    ("/ux0:/data", ("psp2core-",), False),
    # A temporary SceWebKit dump, when the folder is there
    ("/ux0:/data/vitals-dump", ("SceWebKit-",), True),
]


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
    value = os.environ.get("VITA_HOST", "")
    if not value:
        sys.exit("VITA_HOST isn't set: put the Vita's address in .env (cp .env.example .env)")
    return value


def connect():
    ftp = ftplib.FTP(encoding="latin1")
    try:
        ftp.connect(host(), int(os.environ.get("VITA_PORT", "1337")), timeout=30)
    except OSError as error:
        sys.exit(f"{host()}: {error} (is VitaShell's FTP server on? SELECT in VitaShell starts it)")
    ftp.login()
    return ftp


def enter(ftp, path):
    """Into the folder path is in: its name there. Every command works in the current folder, with the
    file's name alone, as with VitaShell's server elsewhere"""
    folder, name = path.rsplit("/", 1)
    ftp.cwd(folder)
    return name


def listing(ftp, folder):
    """The files in folder as {name: size}, without its folders; None when it isn't there. VitaShell's
    LIST is ls -l's: the name is the ninth field, and a folder's line starts with d"""
    lines = []
    try:
        ftp.cwd(folder)
        ftp.retrlines("LIST", lines.append)
    except ftplib.error_perm:
        return None
    files = {}
    for line in lines:
        fields = line.split(None, 8)
        if len(fields) < 9 or line.startswith("d"):
            continue
        try:
            files[fields[8]] = int(fields[4])
        except ValueError:
            files[fields[8]] = None
    return files


def make_directory(ftp, path):
    try:
        ftp.mkd(path)
    except ftplib.error_perm:
        pass  # already there


def upload_app(ftp, source):
    """The app's VPK as ux0:data/vitals/vitals-app.vpk"""
    if not os.path.isfile(source):
        sys.exit(f"{source} is missing: build the app first (make)")
    make_directory(ftp, VITALS)
    with open(source, "rb") as file:
        ftp.storbinary("STOR " + enter(ftp, APP_TARGET), file)
    print(f"{os.path.relpath(source, ROOT)} -> {APP_TARGET} ({os.path.getsize(source)} bytes)")
    print("Install it with VitaShell: ux0:data/vitals/vitals-app.vpk, Cross, then Install.")


def fetch(ftp):
    """Each wanted file into build/vita-fetch/, then deleted from the Vita once it's saved"""
    os.makedirs(FETCHED, exist_ok=True)
    count = 0
    for folder, prefixes, optional in FETCH:
        files = listing(ftp, folder)
        if files is None:
            if not optional:
                print(f"{folder}: not there")
            continue
        for name in sorted(files):
            if not name.startswith(prefixes):
                continue
            path = f"{folder}/{name}"
            target = os.path.join(FETCHED, name)
            with open(target, "wb") as out:
                ftp.retrbinary("RETR " + name, out.write)
            # VitaShell answers 226 rather than 250
            reply = ftp.sendcmd("DELE " + name)
            if not reply.startswith("2"):
                raise ftplib.error_reply(reply)
            print(f"{path} -> {os.path.relpath(target, ROOT)}")
            count += 1
    print(f"{count} fetched" if count else "Nothing to fetch.")


def status(ftp):
    data = []
    try:
        ftp.retrbinary("RETR " + enter(ftp, CONFIG), data.append)
        print(f"{CONFIG}:")
        for line in b"".join(data).decode("latin1").splitlines():
            print(f"  {line}")
    except ftplib.error_perm:
        print(f"{CONFIG}: missing")
    folders = {}
    for path in INSTALLED + LISTS + SWITCHES + [APP_TARGET]:
        folder, name = path.rsplit("/", 1)
        if folder not in folders:
            folders[folder] = listing(ftp, folder) or {}
        size = folders[folder].get(name, "missing")
        print(f"{path}: {size if size == 'missing' else f'{size} bytes'}")


def main():
    load_env()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("app", "fetch", "status"))
    parser.add_argument("vpk", nargs="?", default=APP_VPK, help="the VPK app uploads (build/vitals-app/vitals-app.vpk)")
    arguments = parser.parse_args()
    ftp = connect()
    try:
        if arguments.command == "app":
            upload_app(ftp, os.path.abspath(arguments.vpk))
        elif arguments.command == "fetch":
            fetch(ftp)
        else:
            status(ftp)
    finally:
        ftp.quit()


if __name__ == "__main__":
    main()
