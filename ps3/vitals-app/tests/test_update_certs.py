"""tools/update_certs.py (make update-certs), offline with --bundle on a copy of the app's assets: an
unchanged bundle changes nothing, a newer one replaces the bundle and updates the manifest, and a
bundle that isn't curl's or has too few certificates is refused with nothing changed."""
from pathlib import Path
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "update_certs.py"
ASSETS = ROOT / "vitals-app" / "assets"
CERTIFICATE = re.compile(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\n?", re.S)


class UpdateCertsTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(tempfile.mkdtemp(prefix="vitals-certs-test-"))
        for name in ("mozilla-certs.pem", "certificate-sources.json"):
            shutil.copy(ASSETS / name, self.directory / name)
        self.bundle = (ASSETS / "mozilla-certs.pem").read_bytes()

    def tearDown(self):
        shutil.rmtree(self.directory)

    def run_script(self, bundle):
        source = self.directory / "given.pem"
        source.write_bytes(bundle)
        return subprocess.run([sys.executable, "-I", str(SCRIPT), "--bundle", str(source), "--assets", str(self.directory)],
                              capture_output=True, text=True)

    def assets(self):
        return ((self.directory / "mozilla-certs.pem").read_bytes(),
                json.loads((self.directory / "certificate-sources.json").read_text()))

    def test_manifest_describes_the_bundle(self):
        bundle, manifest = self.assets()
        mozilla = manifest["mozilla"]
        self.assertEqual(mozilla["bytes"], len(bundle))
        self.assertEqual(mozilla["certificate_blocks"], len(CERTIFICATE.findall(bundle)))
        self.assertGreaterEqual(mozilla["unique_certificates"], 100)

    def test_unchanged_bundle_changes_nothing(self):
        before = self.assets()
        result = self.run_script(self.bundle)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("already current", result.stdout)
        self.assertEqual(self.assets(), before)

    def test_newer_bundle_is_taken(self):
        # A day later, one certificate fewer
        newer = re.sub(rb"(Certificate data from Mozilla as of: )[^\n]+", rb"\1Wed Jan 06 04:12:03 2100 GMT", self.bundle, count=1)
        newer = CERTIFICATE.sub(b"", newer, count=1)
        result = self.run_script(newer)
        self.assertEqual(result.returncode, 0, result.stderr)
        bundle, manifest = self.assets()
        self.assertEqual(bundle, newer)
        self.assertEqual(manifest["mozilla"]["source_date"], "2100-01-06")
        self.assertEqual(manifest["mozilla"]["bytes"], len(newer))
        self.assertEqual(manifest["mozilla"]["certificate_blocks"], len(CERTIFICATE.findall(newer)))

    def test_refused_bundles_change_nothing(self):
        before = self.assets()
        header_end = self.bundle.index(b"-----BEGIN CERTIFICATE-----")
        few = self.bundle[:header_end] + b"".join(CERTIFICATE.findall(self.bundle)[:50])
        for name, bundle in (("too few certificates", few),
                             ("no curl header", b"".join(CERTIFICATE.findall(self.bundle))),
                             ("not a bundle", b"<html>error</html>")):
            with self.subTest(name):
                result = self.run_script(bundle)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.assets(), before)


if __name__ == "__main__":
    unittest.main()
