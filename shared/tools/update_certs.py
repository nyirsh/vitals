#!/usr/bin/env python3
"""Refreshes the Mozilla CA bundle both apps carry (shared/assets/mozilla-certs.pem) and what's built
from it. Downloads curl's cacert.pem, checks it against the SHA-256 curl publishes next to it and that
it looks like a CA bundle (curl's header, at least 100 certificates, the apps' own check), rebuilds the
Vita's certs.cer (the store as its kernel plugin reads it, without the user's own: Sony's list, then
the Mozilla certificates it lacks, with the app's own store filter compiled for the host) and updates
certificate-sources.json. Nothing changes when all of it is already current; review and commit the
result.

    shared/tools/update_certs.py [--bundle cacert.pem]

make update-certs runs it, from either console."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
ASSETS = ROOT / "shared" / "assets"
VITA_APP = ROOT / "vita" / "vitals-app"
SOURCE_URL = "https://curl.se/ca/cacert.pem"
# The apps refuse a downloaded bundle with fewer
MINIMUM_CERTIFICATES = 100


def download(url):
    request = urllib.request.Request(url, headers={"User-Agent": "vitals-certificate-updater"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def certificate_ders(data):
    blocks = re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", data, re.S)
    return blocks, {base64.b64decode(re.sub(rb"-----[^\n]+-----|\s+", b"", block)) for block in blocks}


def describe(data):
    blocks, unique = certificate_ders(data)
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "certificate_blocks": len(blocks), "unique_certificates": len(unique)}


def mozilla_date(data):
    match = re.search(rb"Certificate data from Mozilla as of: (.+?)\s*\n", data)
    if match is None:
        raise SystemExit("The bundle's header has no Mozilla date: not curl's cacert.pem")
    return datetime.strptime(match.group(1).decode(), "%a %b %d %H:%M:%S %Y GMT").strftime("%Y-%m-%d")


def combined_store(vita_assets, mozilla):
    """The Vita's certs.cer: Sony's file as it is, then Mozilla's part as the app writes it from the
    bundle it carries, each followed by a line break (vitals/ca_store.h)"""
    with tempfile.TemporaryDirectory(prefix="vitals-certs-") as temporary:
        directory = Path(temporary)
        tool = directory / "store_certs"
        shared = ROOT / "shared"
        subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-O1", "-I", str(shared / "include"),
                        str(shared / "src" / "store_certs.c"), str(VITA_APP / "tools" / "store_certs_cli.c"),
                        "-o", str(tool)], check=True)
        (directory / "mozilla-certs.pem").write_bytes(mozilla)
        added = directory / "mozilla-added.pem"
        result = subprocess.run([str(tool), str(vita_assets / "sony-certs.pem"), str(directory / "mozilla-certs.pem"),
                                 str(added)], capture_output=True, text=True)
        if result.returncode != 0:
            raise SystemExit("Merging failed: " + (result.stderr or result.stdout).strip())
        return (vita_assets / "sony-certs.pem").read_bytes() + b"\n" + added.read_bytes() + b"\n"


def update(assets, vita_assets, mozilla):
    """The new bundle, the Vita's store and the manifest written; False when they were all current"""
    manifest_path = assets / "certificate-sources.json"
    manifest = json.loads(manifest_path.read_text())
    combined = combined_store(vita_assets, mozilla)
    same_bundle = hashlib.sha256(mozilla).hexdigest() == manifest["mozilla"]["sha256"]
    if same_bundle and hashlib.sha256(combined).hexdigest() == manifest["combined"]["sha256"]:
        return False
    if not same_bundle:
        manifest["mozilla"].update(source_date=mozilla_date(mozilla),
                                   fetched_date=datetime.now(timezone.utc).strftime("%Y-%m-%d"), **describe(mozilla))
        (assets / "mozilla-certs.pem").write_bytes(mozilla)
    manifest["combined"].update(describe(combined))
    (vita_assets / "certs.cer").write_bytes(combined)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bundle", type=Path, help="use this cacert.pem instead of downloading it")
    parser.add_argument("--assets", type=Path, default=ASSETS)
    parser.add_argument("--vita-assets", type=Path, default=VITA_APP / "assets")
    args = parser.parse_args()
    if args.bundle is not None:
        mozilla = args.bundle.read_bytes()
    else:
        mozilla = download(SOURCE_URL)
        expected = download(SOURCE_URL + ".sha256").split()[0].decode()
        if hashlib.sha256(mozilla).hexdigest() != expected:
            raise SystemExit("The downloaded bundle doesn't match curl's published SHA-256")
    source_date = mozilla_date(mozilla)
    count = len(certificate_ders(mozilla)[1])
    if count < MINIMUM_CERTIFICATES:
        raise SystemExit(f"The bundle has {count} certificates: fewer than the apps accept ({MINIMUM_CERTIFICATES})")
    if not update(args.assets, args.vita_assets, mozilla):
        print(f"The bundled Mozilla certificates are already current (Mozilla data of {source_date}).")
        return 0
    print(f"Updated to Mozilla data of {source_date}: {count} certificates. Review and commit shared/assets "
          "and vita/vitals-app/assets.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
