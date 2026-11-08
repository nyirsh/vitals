"""The browser provider's Makefile always passes its full configuration, so a stale CMake cache cannot change a build,
and the root Makefile's options reach it."""
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
# Every component builds into build/ at the repository root
BUILD = ROOT / "build"


def dry_run(directory, *arguments):
    return subprocess.run(["make", "-n", "-C", str(directory), *arguments],
                          check=True, capture_output=True, text=True).stdout


@unittest.skipUnless(shutil.which("make"), "make is required")
class BrowserMakefileTests(unittest.TestCase):
    def test_providers_pass_release_defaults(self):
        output = dry_run(ROOT / "vitals-browser")
        self.assertIn(f"cmake -S . -B {BUILD}/vitals-browser", output)
        self.assertIn("-DVITALS_DEBUG=0", output)
        self.assertIn("--target vitals.suprx-self", output)

    def test_root_options_reach_the_providers(self):
        output = dry_run(ROOT, "vitals-browser", "DEBUG=2")
        self.assertIn("-DVITALS_DEBUG=2", output)

    def test_each_debug_level_builds_apart(self):
        # The app carries every level, so they must not overwrite each other
        for level, folder in (("0", "vitals-browser "), ("1", "vitals-browser-debug1 "), ("2", "vitals-browser-debug2 ")):
            output = dry_run(ROOT / "vitals-browser", f"DEBUG={level}")
            self.assertIn(f"-B {BUILD}/{folder}", output)
            self.assertIn(f"-DVITALS_DEBUG={level}", output)

    def test_the_app_builds_every_debug_level(self):
        output = dry_run(ROOT / "vitals-app", "modules")
        for level in ("0", "1", "2"):
            self.assertIn(f"-C ../vitals-browser DEBUG={level}", output)
            self.assertIn(f"-C ../vitals-boot DEBUG={level}", output)


if __name__ == "__main__":
    unittest.main()
