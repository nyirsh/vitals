"""shared/tools/update_certs.py (make update-certs), offline with --bundle on a copy of the assets: a
current bundle changes nothing, a newer one updates the bundle, the Vita's store and the manifest
together, a store left behind is rebuilt, and a bundle that isn't curl's or has too few certificates
is refused with nothing changed."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "shared" / "tools" / "update_certs.py"
CERTIFICATE = re.compile(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\n?", re.S)


@unittest.skipUnless(shutil.which(os.environ.get("CC", "cc")), "requires a C compiler")
class UpdateCertsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        base = Path(self.temporary.name)
        self.shared = base / "shared"
        self.vita = base / "vita"
        self.shared.mkdir()
        self.vita.mkdir()
        for name in ("mozilla-certs.pem", "certificate-sources.json"):
            shutil.copy(ROOT / "shared" / "assets" / name, self.shared / name)
        for name in ("sony-certs.pem", "certs.cer"):
            shutil.copy(ROOT / "vita" / "vitals-app" / "assets" / name, self.vita / name)
        self.bundle = (self.shared / "mozilla-certs.pem").read_bytes()

    def tearDown(self):
        self.temporary.cleanup()

    def run_script(self, bundle):
        source = Path(self.temporary.name) / "given.pem"
        source.write_bytes(bundle)
        return subprocess.run([sys.executable, "-I", str(SCRIPT), "--bundle", str(source), "--assets", str(self.shared),
                               "--vita-assets", str(self.vita)], capture_output=True, text=True)

    def state(self):
        return ((self.shared / "mozilla-certs.pem").read_bytes(), (self.vita / "certs.cer").read_bytes(),
                json.loads((self.shared / "certificate-sources.json").read_text()))

    def test_manifest_describes_the_files(self):
        bundle, combined, manifest = self.state()
        self.assertEqual(manifest["mozilla"]["sha256"], hashlib.sha256(bundle).hexdigest())
        self.assertEqual(manifest["mozilla"]["certificate_blocks"], len(CERTIFICATE.findall(bundle)))
        self.assertGreaterEqual(manifest["mozilla"]["unique_certificates"], 100)
        self.assertEqual(manifest["combined"]["sha256"], hashlib.sha256(combined).hexdigest())

    def test_current_bundle_changes_nothing(self):
        before = self.state()
        result = self.run_script(self.bundle)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("already current", result.stdout)
        self.assertEqual(self.state(), before)

    def test_newer_bundle_updates_all_of_it(self):
        newer = re.sub(rb"(Certificate data from Mozilla as of: )[^\n]+", rb"\1Wed Jan 06 04:12:03 2100 GMT", self.bundle, count=1)
        count = len(CERTIFICATE.findall(newer))
        newer = CERTIFICATE.sub(b"", newer, count=1)
        result = self.run_script(newer)
        self.assertEqual(result.returncode, 0, result.stderr)
        bundle, combined, manifest = self.state()
        self.assertEqual(bundle, newer)
        self.assertEqual(manifest["mozilla"]["source_date"], "2100-01-06")
        self.assertEqual(manifest["mozilla"]["unique_certificates"], count - 1)
        self.assertEqual(manifest["combined"]["sha256"], hashlib.sha256(combined).hexdigest())
        self.assertEqual(manifest["combined"]["bytes"], len(combined))
        # Sony's file stays byte for byte at the start of the Vita's store
        self.assertTrue(combined.startswith((self.vita / "sony-certs.pem").read_bytes()))

    def test_store_left_behind_is_rebuilt(self):
        manifest_path = self.shared / "certificate-sources.json"
        manifest = json.loads(manifest_path.read_text())
        dates = manifest["mozilla"]["source_date"], manifest["mozilla"]["fetched_date"]
        manifest["combined"]["sha256"] = "0" * 64
        manifest_path.write_text(json.dumps(manifest))
        (self.vita / "certs.cer").write_bytes(b"old")
        result = self.run_script(self.bundle)
        self.assertEqual(result.returncode, 0, result.stderr)
        _, combined, manifest = self.state()
        self.assertTrue(combined.startswith((self.vita / "sony-certs.pem").read_bytes()))
        self.assertEqual(manifest["combined"]["sha256"], hashlib.sha256(combined).hexdigest())
        self.assertEqual((manifest["mozilla"]["source_date"], manifest["mozilla"]["fetched_date"]), dates)

    def test_refused_bundles_change_nothing(self):
        before = self.state()
        header_end = self.bundle.index(b"-----BEGIN CERTIFICATE-----")
        few = self.bundle[:header_end] + b"".join(CERTIFICATE.findall(self.bundle)[:50])
        for name, bundle in (("too few certificates", few),
                             ("no curl header", b"".join(CERTIFICATE.findall(self.bundle))),
                             ("not a bundle", b"<html>error</html>")):
            with self.subTest(name):
                result = self.run_script(bundle)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.state(), before)


if __name__ == "__main__":
    unittest.main()
