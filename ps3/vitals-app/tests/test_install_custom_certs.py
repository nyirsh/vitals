"""tools/ps3_comms.py's merge of custom-certs.pem (make install), held to the same cases as the app's
own in test_custom_certs.c: the user's certificates after Mozilla's under the marker, once each, broken
blocks skipped, and an earlier merge replaced rather than added to."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import ps3_comms  # noqa: E402

MARKER = b"# vitals: custom certificates (/dev_hdd0/vitals/custom-certs.pem)\n"


def cert(body):
    return b"-----BEGIN CERTIFICATE-----\n" + body + b"\n-----END CERTIFICATE-----\n"


MOZILLA = (b"##\n## Bundle of CA Root Certificates\n##\n\nRoot A\n======\n" + cert(b"QUFBQQ==")
           + b"\nRoot B\n======\n" + cert(b"QkJCQg=="))


def merge(bundle, custom):
    return ps3_comms.merge_custom_certificates(bundle, custom)


class InstallCustomCertsTests(unittest.TestCase):
    def test_marker_matches_the_apps(self):
        header = (Path(__file__).resolve().parents[1] / "src" / "custom_certs.h").read_text()
        self.assertIn('"# vitals: custom certificates (" VITALS_CUSTOM_CERTS ")\\n"', header)
        self.assertEqual(ps3_comms.CUSTOM_MARKER, MARKER)

    def test_no_file_or_nothing_in_it_leaves_the_bundle(self):
        self.assertEqual(merge(MOZILLA, None), (MOZILLA, 0, 0, 0))
        self.assertEqual(merge(MOZILLA, b"# nothing yet\n"), (MOZILLA, 0, 0, 0))

    def test_added_after_mozillas_once_and_replaced_next_time(self):
        custom = b"# my server\n" + cert(b"Q0NDQw==") + b"some words\n" + cert(b"RERE\nRA==")
        merged, added, duplicates, skipped = merge(MOZILLA, custom)
        self.assertEqual((added, duplicates, skipped), (2, 0, 0))
        self.assertEqual(merged, MOZILLA + MARKER + cert(b"Q0NDQw==") + cert(b"RERE\nRA=="))
        self.assertEqual(merge(merged, custom)[0], merged)
        self.assertEqual(merge(merged, None)[0], MOZILLA)

    def test_duplicates_wherever_their_lines_break(self):
        merged, added, duplicates, _skipped = merge(
            MOZILLA, cert(b"QUFB\nQQ==") + cert(b"Q0NDQw==") + cert(b"Q0ND\r\nQw=="))
        self.assertEqual((added, duplicates), (1, 2))
        self.assertEqual(merged.count(b"Q0NDQw=="), 1)

    def test_broken_blocks_skipped_never_in_the_way(self):
        broken = (b"-----BEGIN CERTIFICATE-----\nRUVFRQ==\n" + cert(b"not base64!") + cert(b"RkZGRg==")
                  + b"-----BEGIN CERTIFICATE-----\nR0dHRw==\n-----END CERTIFICATE----- extra\n" + cert(b""))
        merged, added, _duplicates, skipped = merge(MOZILLA, broken)
        self.assertEqual((added, skipped), (1, 4))
        self.assertIn(b"RkZGRg==", merged)
        self.assertNotIn(b"RUVFRQ==", merged)

    def test_files_without_their_last_newline(self):
        cut = b"Root A\n-----BEGIN CERTIFICATE-----\nQUFBQQ==\n-----END CERTIFICATE-----"
        merged, added, _duplicates, _skipped = merge(
            cut, b"-----BEGIN CERTIFICATE-----\nSElISQ==\n-----END CERTIFICATE-----")
        self.assertEqual(added, 1)
        self.assertEqual(merged, cut + b"\n" + MARKER + cert(b"SElISQ=="))

    def test_marker_only_at_a_lines_start(self):
        quoted = b"text # vitals: custom certificates\n" + cert(b"QUFBQQ==")
        self.assertEqual(merge(quoted, None)[0], quoted)


if __name__ == "__main__":
    unittest.main()
