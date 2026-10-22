"""update_certs.py refreshes the bundled snapshot consistently, and leaves a current one alone."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("update_certs", ROOT / "vitals-app/tools/update_certs.py")
update_certs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(update_certs)


@unittest.skipUnless(shutil.which("pkg-config") and
                     subprocess.run(["pkg-config", "--exists", "libcurl", "openssl"]).returncode == 0,
                     "requires libcurl/OpenSSL development libraries and pkg-config")
class UpdateCertsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.assets = Path(self.temporary.name) / "assets"
        shutil.copytree(ROOT / "vitals-app/assets", self.assets)

    def tearDown(self):
        self.temporary.cleanup()

    def test_current_bundle_changes_nothing(self):
        before = {path.name: path.read_bytes() for path in self.assets.iterdir()}
        self.assertFalse(update_certs.update(self.assets, before["mozilla-certs.pem"]))
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.assets.iterdir()})

    def test_new_bundle_updates_all_three_files_consistently(self):
        original = (self.assets / "mozilla-certs.pem").read_bytes()
        # Drop the last certificate to stand in for a newer Mozilla release
        blocks = list(re.finditer(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\n?", original, re.S))
        newer = original[:blocks[-1].start()]
        self.assertTrue(update_certs.update(self.assets, newer))
        manifest = json.loads((self.assets / "certificate-sources.json").read_text())
        combined = (self.assets / "certs.cer").read_bytes()
        self.assertEqual((self.assets / "mozilla-certs.pem").read_bytes(), newer)
        self.assertEqual(manifest["mozilla"]["sha256"], hashlib.sha256(newer).hexdigest())
        self.assertEqual(manifest["mozilla"]["unique_certificates"], len(blocks) - 1)
        self.assertEqual(manifest["combined"]["sha256"], hashlib.sha256(combined).hexdigest())
        self.assertEqual(manifest["combined"]["bytes"], len(combined))
        # Sony's file stays byte for byte at the start of the merged bundle
        self.assertTrue(combined.startswith((self.assets / "sony-certs.pem").read_bytes()))


if __name__ == "__main__":
    unittest.main()
