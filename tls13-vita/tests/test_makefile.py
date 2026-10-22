"""The providers' Makefile always passes its full configuration, so a stale CMake cache cannot change a build,
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
class ProviderMakefileTests(unittest.TestCase):
    def test_providers_pass_release_defaults(self):
        output = dry_run(ROOT / "tls13-vita")
        self.assertIn(f"cmake -Wno-deprecated -S . -B {BUILD}/tls13-vita", output)
        self.assertIn("-DVITALS_DEBUG=0", output)
        self.assertIn("-DVITALS_HTTP_HEAP_KIB=128", output)
        self.assertIn("--target vitals.suprx-self", output)

    def test_root_options_reach_the_providers(self):
        output = dry_run(ROOT, "tls13-vita", "DEBUG=2", "HTTP_HEAP_KIB=256")
        self.assertIn("-DVITALS_DEBUG=2", output)
        self.assertIn("-DVITALS_HTTP_HEAP_KIB=256", output)


if __name__ == "__main__":
    unittest.main()
