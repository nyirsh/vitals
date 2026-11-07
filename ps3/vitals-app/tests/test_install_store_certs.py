"""tools/ps3_comms.py's Mozilla part of the store (make install), held to the same cases as the app's
own in test_store_certs.c: Mozilla's certificates without Sony's wherever their lines break, everything
else as it is, an earlier version's merged custom certificates cut off; and Sony's CAs read as the app
reads them, from the table libssl uses."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import ps3_comms  # noqa: E402


def cert(body):
    return b"-----BEGIN CERTIFICATE-----\n" + body + b"\n-----END CERTIFICATE-----\n"


MOZILLA = (b"##\n## Bundle of CA Root Certificates\n##\n\nRoot A\n======\n" + cert(b"QUFBQQ==")
           + b"\nRoot B\n======\n" + cert(b"QkJCQg=="))
SONY = b"Sony's CA_LIST.cer\r\n-----BEGIN CERTIFICATE-----\r\nQkJC\r\nQg==\r\n-----END CERTIFICATE-----\r\n"


class InstallStoreCertsTests(unittest.TestCase):
    def test_marker_matches_the_apps(self):
        header = (ROOT / "vitals-app" / "src" / "store_certs.h").read_text()
        self.assertIn('#define VITALS_EARLIER_CUSTOM_MARKER "# vitals: custom certificates"', header)
        self.assertEqual(ps3_comms.EARLIER_CUSTOM_MARKER, b"# vitals: custom certificates")

    def test_without_sonys_the_bundle_as_it_is(self):
        self.assertEqual(ps3_comms.store_mozilla(MOZILLA, None), (MOZILLA, 2, 0, False))
        self.assertEqual(ps3_comms.store_mozilla(MOZILLA, cert(b"Q0NDQw==")), (MOZILLA, 2, 0, False))

    def test_sonys_left_out_wherever_their_lines_break(self):
        self.assertEqual(ps3_comms.store_mozilla(MOZILLA, SONY),
                         (b"##\n## Bundle of CA Root Certificates\n##\n\nRoot A\n======\n" + cert(b"QUFBQQ==")
                          + b"\nRoot B\n======\n", 1, 1, False))

    def test_earlier_merge_cut_and_stays_so(self):
        earlier = MOZILLA + b"# vitals: custom certificates (/dev_hdd0/vitals/custom-certs.pem)\n" + cert(b"RERERA==")
        data, kept, _sony, cut = ps3_comms.store_mozilla(earlier, None)
        self.assertEqual((data, kept, cut), (MOZILLA, 2, True))
        self.assertEqual(ps3_comms.store_mozilla(data, None), (MOZILLA, 2, 0, False))

    def test_broken_blocks_kept_as_they_are(self):
        broken = b"-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n" + cert(b"QkJCQg==")
        self.assertEqual(ps3_comms.store_mozilla(broken, SONY),
                         (b"-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n", 0, 1, False))

    def test_files_without_their_last_newline(self):
        cut = b"Root A\n-----BEGIN CERTIFICATE-----\nQUFBQQ==\n-----END CERTIFICATE-----"
        self.assertEqual(ps3_comms.store_mozilla(cut, None)[0], cut + b"\n")

    def test_marker_only_at_a_lines_start(self):
        quoted = b"text # vitals: custom certificates\n" + cert(b"QUFBQQ==")
        self.assertEqual(ps3_comms.store_mozilla(quoted, None), (quoted, 1, 0, False))

    def test_sonys_cas_read_from_the_table(self):
        files = {"CA01.cer": b"first\n", "CA_LIST.cer": bytes(range(256)) * 200}
        text = ps3_comms.sony_text(files.get)
        cas = ps3_comms.sony_cas()
        self.assertTrue(text.startswith(b"first\n\n"))
        listed = [(offset, length) for name, offset, length in cas if name == "CA_LIST.cer"]
        self.assertTrue(listed)
        offset, length = listed[-1]
        self.assertTrue(text.endswith(files["CA_LIST.cer"][offset:offset + length] + b"\n"))
        self.assertIsNone(ps3_comms.sony_text(lambda name: None))

    def test_sonys_real_cas_left_out_of_mozillas(self):
        """With the dumps (dumps/ps3/4.93-cex/cert), the bundled Mozilla file loses exactly Sony's"""
        cert_dir = ROOT.parent / "dumps" / "ps3" / "4.93-cex" / "cert"
        if not cert_dir.is_dir():
            self.skipTest("Sony's CA files aren't here (dumps/ps3/4.93-cex/cert)")
        sony = ps3_comms.sony_text(lambda name: (cert_dir / name).read_bytes() if (cert_dir / name).exists() else None)
        mozilla = (ROOT / "vitals-app" / "assets" / "mozilla-certs.pem").read_bytes()
        data, kept, left_out, _cut = ps3_comms.store_mozilla(mozilla, sony)
        sonys = {body for whole, _s, _e, body in ps3_comms.pem_blocks(sony) if whole}
        bodies = [body for whole, _s, _e, body in ps3_comms.pem_blocks(mozilla) if whole]
        self.assertEqual(left_out, sum(body in sonys for body in bodies))
        self.assertGreater(left_out, 0)
        self.assertEqual(kept + left_out, len(bodies))
        self.assertFalse(any(body in sonys for whole, _s, _e, body in ps3_comms.pem_blocks(data) if whole))


if __name__ == "__main__":
    unittest.main()
