"""The plugin's Makefile always passes its full configuration, so a stale CMake cache cannot change a build."""
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
class PluginMakefileTests(unittest.TestCase):
    def test_kernel_passes_provider_path(self):
        output = dry_run(ROOT / "vitals-plugin")
        self.assertIn(f"cmake -S . -B {BUILD}/vitals-plugin", output)
        self.assertIn("-DVITALS_HTTP_PROVIDER_PATH=vs0:/data/external/vitals/native/vitals_http.suprx", output)
        self.assertIn("-DVITALS_DEBUG=0", output)

    def test_debug_levels_build_apart(self):
        output = dry_run(ROOT / "vitals-plugin", "DEBUG=2")
        self.assertIn(f"cmake -S . -B {BUILD}/vitals-plugin-debug2", output)
        self.assertIn("-DVITALS_DEBUG=2", output)


if __name__ == "__main__":
    unittest.main()
