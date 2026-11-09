#!/usr/bin/env python3
"""Talks to a Vita over FTP (VitaShell's server, started with SELECT in VitaShell):

    tools/vita_comms.py app [VPK]      uploads the vitals app (make, build/vitals-app/vitals-app.vpk, or
                                       VPK) to ux0:data/vitals/vitals-app-<VERSION>.vpk, for VitaShell to install
    tools/vita_comms.py log            prints vitals.log (Options, Logs: File), and keeps it in fetched/psv/
    tools/vita_comms.py app-log        prints the app's vitals-app.log, and keeps it in fetched/psv/
    tools/vita_comms.py fetch          copies the app's test reports (ux0:data/vitals/reports, and
                                       ux0:data/vitals from earlier versions), the crash dumps from
                                       ux0:data and any SceWebKit dumps from ux0:data/vitals-dump into
                                       ../fetched/psv/, leaving them on the Vita; the debug output's log files too
    tools/vita_comms.py status         what's on the Vita now: config.txt, vitals' plugin and modules,
                                       the certificate store, the user's lists and the switches

The Vita is VITA_HOST, port VITA_PORT (1337, VitaShell's), from the environment or else from .env at
the top of the repository (copy .env.example). Installing, uninstalling and the debug output are the app's: they
need vs0: mounted for writing and a reboot, which the app takes care of.

What fetch brings back can hold PSN details (the reports list each request): it stays in fetched/, which
isn't committed."""

import argparse
import ftplib
import io
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "..", "shared", "tools"))
import console_ftp  # noqa: E402
from console_ftp import listing, load_env, make_directory  # noqa: E402
BUILD = os.path.join(ROOT, "build")
FETCHED = console_ftp.fetched_folder("psv")
APP_VPK = os.path.join(BUILD, "vitals-app", "vitals-app.vpk")

# VitaShell's FTP paths: each device is a folder at the top, named with its colon
VITALS = "/ux0:/data/vitals"
APP_NAME = f"vitals-app-{console_ftp.release()}.vpk"
APP_TARGET = VITALS + "/" + APP_NAME
LOG = VITALS + "/logs/vitals.log"
APP_LOG = VITALS + "/logs/vitals-app.log"
CONFIG = "/ur0:/tai/config.txt"
# What the app installs (vitals-app/install.c): the kernel plugin in ur0:tai, vitals' modules in
# ux0:data/vitals/system
INSTALLED = [
    "/ur0:/tai/vitals.skprx",
    VITALS + "/system/libhttp.suprx",
    VITALS + "/system/libssl.suprx",
    VITALS + "/system/ScePsp2Compat.suprx",
    VITALS + "/system/vitals.suprx",
    # vitals' certificate store, with the user's custom-certs.pem (the system's own on vs0 is left
    # as it was)
    VITALS + "/system/sony-certs.pem",
    VITALS + "/system/mozilla-certs.pem",
]
# The user's lists and certificates
LISTS = [VITALS + "/" + name for name in ("redirects.txt", "dns.txt", "custom-certs.pem")]
# The Options' switches (vitals-app/vitals_paths.h): each part is off while its .off is there
SWITCHES = [VITALS + "/flags/" + name for name in ("tls.off", "http.off", "dns.off", "redirects.off")]
# What fetch takes: (folder, the names it takes, whether the folder may be missing)
FETCH = [
    (VITALS + "/reports", ("connection-test-",), True),
    # Where earlier versions saved them, until the installer moves them to reports/
    # The debug output's file (Options, Logs: File), the last boot's, and the app's own
    (VITALS + "/logs", ("vitals.log", "vitals-app.log"), True),
    (VITALS, ("vitals-testresults-", "browserleaks-"), False),
    ("/ux0:/data", ("psp2core-",), False),
    # A temporary SceWebKit dump, when the folder is there
    ("/ux0:/data/vitals-dump", ("SceWebKit-",), True),
]


def host():
    return console_ftp.host("VITA_HOST", "the Vita")


def connect():
    return console_ftp.connect(host(), int(os.environ.get("VITA_PORT", "1337")),
                               "is VitaShell's FTP server on? SELECT in VitaShell starts it")


def enter(ftp, path):
    """Into the folder path is in: its name there. Every command works in the current folder, with the
    file's name alone, as with VitaShell's server elsewhere"""
    folder, name = path.rsplit("/", 1)
    ftp.cwd(folder)
    return name


def upload_app(ftp, source):
    """The app's VPK as ux0:data/vitals/vitals-app-<VERSION>.vpk"""
    if not os.path.isfile(source):
        sys.exit(f"{source} is missing: build the app first (make)")
    make_directory(ftp, VITALS)
    with open(source, "rb") as file:
        ftp.storbinary("STOR " + enter(ftp, APP_TARGET), file)
    print(f"{os.path.relpath(source, ROOT)} -> {APP_TARGET} ({os.path.getsize(source)} bytes)")
    print(f"Install it with VitaShell: ux0:data/vitals/{APP_NAME}, Cross, then Install.")


def fetch_log(ftp, path):
    """The log at path saved in fetched/psv/ and printed, left on the Vita"""
    data = io.BytesIO()
    try:
        ftp.retrbinary("RETR " + enter(ftp, path), data.write)
    except ftplib.error_perm:
        sys.exit(f"{path}: not there (they're written with debug output on and Logs set to File, in the app's Options)")
    console_ftp.show_log(data.getvalue(), FETCHED, path.rsplit("/", 1)[1], console_ftp.REPOSITORY)


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
    for path in INSTALLED + LISTS + SWITCHES + [LOG, APP_LOG, APP_TARGET]:
        folder, name = path.rsplit("/", 1)
        if folder not in folders:
            folders[folder] = listing(ftp, folder) or {}
        size = folders[folder].get(name, "missing")
        print(f"{path}: {size if size == 'missing' else f'{size} bytes'}")


def main():
    load_env()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("app", "log", "app-log", "fetch", "status"))
    parser.add_argument("vpk", nargs="?", default=APP_VPK, help="the VPK app uploads (build/vitals-app/vitals-app.vpk)")
    arguments = parser.parse_args()
    ftp = connect()
    try:
        if arguments.command == "app":
            upload_app(ftp, os.path.abspath(arguments.vpk))
        elif arguments.command == "log":
            fetch_log(ftp, LOG)
        elif arguments.command == "app-log":
            fetch_log(ftp, APP_LOG)
        elif arguments.command == "fetch":
            console_ftp.fetch(ftp, FETCH, FETCHED, console_ftp.REPOSITORY)
        else:
            status(ftp)
    finally:
        ftp.quit()


if __name__ == "__main__":
    main()
