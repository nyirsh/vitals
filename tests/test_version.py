"""VERSION holds a well-formed release number, and the build turns it into the Vita's version formats."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def read_version(text):
    """Runs version.cmake on a VERSION file holding text; returns its variables, or None if it is rejected."""
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        shutil.copy(ROOT / "version.cmake", directory)
        (directory / "VERSION").write_text(text)
        (directory / "print.cmake").write_text(
            "include(${CMAKE_CURRENT_LIST_DIR}/version.cmake)\n"
            'message("${VITALS_VERSION};${VITALS_APP_VERSION};'
            '${VITALS_MODULE_VERSION_MAJOR};${VITALS_MODULE_VERSION_MINOR}")\n')
        result = subprocess.run(["cmake", "-P", str(directory / "print.cmake")],
                                capture_output=True, text=True)
    if result.returncode != 0:
        return None
    return tuple(result.stderr.strip().split(";"))


@unittest.skipUnless(shutil.which("cmake"), "cmake is required")
class VersionTests(unittest.TestCase):
    def test_version_file_is_well_formed(self):
        text = (ROOT / "VERSION").read_text()
        self.assertIsNotNone(read_version(text), f"VERSION holds {text!r}; expected major.minor such as 1.0")
        self.assertEqual(len(text.splitlines()), 1, "VERSION should hold a single line")

    def test_formats(self):
        cases = {
            "1.0": ("1.0", "01.00", "1", "0"),
            "1.5": ("1.5", "01.05", "1", "5"),
            "1.10": ("1.10", "01.10", "1", "10"),
            "0.9": ("0.9", "00.09", "0", "9"),
            "12.34": ("12.34", "12.34", "12", "34"),
            "99.99": ("99.99", "99.99", "99", "99"),
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(read_version(text + "\n"), expected)

    def test_surrounding_whitespace_is_ignored(self):
        self.assertEqual(read_version("  1.0\r\n\n"), ("1.0", "01.00", "1", "0"))

    def test_malformed_versions_are_rejected(self):
        for text in ["", "1", "1.", ".1", "1.0.0", "v1.0", "1.0-beta", "01.0", "1.01",
                     "100.0", "1.100", "1,0", "1 .0", "1.0\n2.0", "-1.0"]:
            with self.subTest(text=text):
                self.assertIsNone(read_version(text))


if __name__ == "__main__":
    unittest.main()
