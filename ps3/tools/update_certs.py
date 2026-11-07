#!/usr/bin/env python3
"""Refreshes the app's bundled Mozilla CA bundle (vitals-app/assets/mozilla-certs.pem), as the Vita's
vitals-app/tools/update_certs.py does for its own: downloads curl's cacert.pem, checks it against the
SHA-256 curl publishes next to it and that it looks like a CA bundle (the app's own check: curl's
header, at least 100 certificates), then updates certificate-sources.json. The PS3 installs
Mozilla's bundle as it is (/dev_hdd0/vitals/system/cacert.pem), so there's nothing to merge with Sony's.
Nothing changes when the bundle is already current; review and commit the result.

    tools/update_certs.py [--bundle cacert.pem]
"""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "vitals-app" / "assets"
SOURCE_URL = "https://curl.se/ca/cacert.pem"
# The app refuses a downloaded bundle with fewer (vitals-app/src/install.c)
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


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bundle", type=Path, help="use this cacert.pem instead of downloading it")
    parser.add_argument("--assets", type=Path, default=ASSETS)
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
        raise SystemExit(f"The bundle has {count} certificates: fewer than the app accepts ({MINIMUM_CERTIFICATES})")
    manifest_path = args.assets / "certificate-sources.json"
    manifest = json.loads(manifest_path.read_text())
    if hashlib.sha256(mozilla).hexdigest() == manifest["mozilla"]["sha256"]:
        print(f"The bundled Mozilla certificates are already current (Mozilla data of {source_date}).")
        return 0
    manifest["mozilla"].update(source_date=source_date, fetched_date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                               **describe(mozilla))
    (args.assets / "mozilla-certs.pem").write_bytes(mozilla)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Updated to Mozilla data of {source_date}: {count} certificates. Review and commit vitals-app/assets/.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
