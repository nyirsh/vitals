#!/usr/bin/env python3
"""Refresh the installer's bundled Mozilla CA snapshot and the merged bundle built from it.

Downloads curl's Mozilla bundle, checks it against the SHA-256 that curl publishes next to it,
rebuilds certs.cer with the installer's own merge code (compiled for the host) and updates
certificate-sources.json. Nothing changes when the bundle is already current.
"""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "vitals-app"
SOURCE_URL = "https://curl.se/ca/cacert.pem"


def download(url):
    with urllib.request.urlopen(url, timeout=60) as response:
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
        raise ValueError("bundle header has no Mozilla date")
    return datetime.strptime(match.group(1).decode(), "%a %b %d %H:%M:%S %Y GMT").strftime("%Y-%m-%d")


def build_merge_tool(directory):
    """The installer's certificates.c with its host CLI, as the certificate tests build it."""
    flags = subprocess.check_output(["pkg-config", "--cflags", "--libs", "libcurl", "openssl"], text=True)
    tool = directory / "certificates"
    subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-O1", str(APP / "certificates.c"),
                    str(APP / "certificates_cli.c"), *shlex.split(flags), "-o", str(tool)], check=True)
    return tool


def update(assets, mozilla):
    """Writes the new snapshot, merged bundle and manifest into assets; returns False if unchanged."""
    manifest_path = assets / "certificate-sources.json"
    manifest = json.loads(manifest_path.read_text())
    if hashlib.sha256(mozilla).hexdigest() == manifest["mozilla"]["sha256"]:
        return False
    with tempfile.TemporaryDirectory(prefix="vitals-certs-") as temporary:
        directory = Path(temporary)
        (directory / "mozilla-certs.pem").write_bytes(mozilla)
        merged = directory / "certs.cer"
        # Offline mode: merge the given bundle exactly as the installer's fallback path does
        result = subprocess.run([str(build_merge_tool(directory)), str(assets / "sony-certs.pem"),
                                 str(directory / "mozilla-certs.pem"), "offline", str(merged)],
                                capture_output=True, text=True)
        if result.returncode != 0:
            raise SystemExit("Merging failed: " + (result.stderr or result.stdout).strip())
        combined = merged.read_bytes()
    manifest["mozilla"].update(source_date=mozilla_date(mozilla),
                               fetched_date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                               **describe(mozilla))
    manifest["combined"].update(describe(combined))
    (assets / "mozilla-certs.pem").write_bytes(mozilla)
    (assets / "certs.cer").write_bytes(combined)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, help="use this cacert.pem instead of downloading it")
    parser.add_argument("--assets", type=Path, default=APP / "assets")
    args = parser.parse_args()
    if args.bundle is not None:
        mozilla = args.bundle.read_bytes()
    else:
        mozilla = download(SOURCE_URL)
        expected = download(SOURCE_URL + ".sha256").split()[0].decode()
        if hashlib.sha256(mozilla).hexdigest() != expected:
            raise SystemExit("Downloaded bundle does not match curl's published SHA-256")
    if not certificate_ders(mozilla)[1]:
        raise SystemExit("Bundle contains no certificates")
    if not update(args.assets, mozilla):
        print("Bundled Mozilla certificates are already current.")
        return
    manifest = json.loads((args.assets / "certificate-sources.json").read_text())
    print("Updated to Mozilla data of {source_date}: {unique_certificates} certificates.".format(**manifest["mozilla"]))
    print("Merged bundle: {unique_certificates} certificates.".format(**manifest["combined"]))


if __name__ == "__main__":
    sys.exit(main())
