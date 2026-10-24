"""tools/release.py (make version): the version numbers it accepts, and its changelog check."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("release", ROOT / "tools" / "release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class VersionNumberTests(unittest.TestCase):
    def test_accepted_as_version_cmake_does(self):
        self.assertEqual(release.parse_version("1.5"), (1, 5))
        self.assertEqual(release.parse_version("1.10"), (1, 10))
        self.assertEqual(release.parse_version("0.9\n"), (0, 9))
        for text in ["", "1", "1.", "1.0.0", "v1.5", "01.5", "1.05", "100.0", "1,5"]:
            with self.subTest(text=text):
                self.assertIsNone(release.parse_version(text))

    def test_ordered_as_numbers(self):
        self.assertLess(release.parse_version("1.9"), release.parse_version("1.10"))


class ChangelogTests(unittest.TestCase):
    CHANGELOG = "# Changelog\n\nEvery release, newest first.\n\n## 1.5\n\n- New\n\n## 1.4\n\n- Old\n"

    def test_newest_entry_is_the_version(self):
        release.check_changelog(self.CHANGELOG, (1, 5))
        release.check_changelog("## 1.5\r\n- New\r\n", (1, 5))

    def test_anything_else_is_refused(self):
        for version in [(1, 6), (1, 4)]:
            with self.subTest(version=version):
                with self.assertRaises(release.ReleaseError):
                    release.check_changelog(self.CHANGELOG, version)
        for text in ["# Changelog\n", "## Next\n- New\n", "## 1.5 (2026-11-02)\n- New\n"]:
            with self.subTest(text=text):
                with self.assertRaises(release.ReleaseError):
                    release.check_changelog(text, (1, 5))


if __name__ == "__main__":
    unittest.main()
