"""The root Makefile: which console's Makefile each command reaches, dry-run."""
from pathlib import Path
import re
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]


def run(*arguments):
    return subprocess.run(["make", "-n", "-C", str(ROOT), *arguments], capture_output=True, text=True)


def consoles(output, command=""):
    """Which consoles' Makefiles are started, in order"""
    tail = rf"\s+{re.escape(command)}\b" if command else r"\s*(?:&&|$)"
    return re.findall(rf"-C (ps3|psv){tail}", output, re.M)


@unittest.skipUnless(shutil.which("make"), "make is required")
class RootMakefileTests(unittest.TestCase):
    def test_make_builds_both_in_order(self):
        self.assertEqual(consoles(run().stdout), ["ps3", "psv"])

    def test_a_console_alone_is_built(self):
        self.assertEqual(consoles(run("ps3").stdout), ["ps3"])
        self.assertEqual(consoles(run("psv").stdout), ["psv"])

    def test_a_command_reaches_both(self):
        self.assertEqual(consoles(run("clean").stdout, "clean"), ["ps3", "psv"])

    def test_a_command_reaches_the_console_named(self):
        output = run("ps3", "clean").stdout
        self.assertEqual(consoles(output, "clean"), ["ps3"])
        self.assertEqual(consoles(output), [])
        self.assertEqual(consoles(run("psv", "test").stdout, "test"), ["psv"])

    def test_several_commands(self):
        output = run("psv", "clean", "test").stdout
        self.assertEqual(consoles(output, "clean"), ["psv"])
        self.assertEqual(consoles(output, "test"), ["psv"])

    def test_both_named(self):
        self.assertEqual(consoles(run("ps3", "psv").stdout), ["ps3", "psv"])

    def test_what_is_the_same_for_both_runs_once(self):
        self.assertEqual(consoles(run("update-certs").stdout, "update-certs"), ["ps3"])
        self.assertEqual(consoles(run("preview").stdout, "preview"), ["ps3"])
        self.assertEqual(consoles(run("psv", "update-certs").stdout, "update-certs"), ["psv"])

    def test_one_consoles_command_needs_it_named(self):
        result = run("install")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("make ps3 install or make psv install", result.stderr)
        self.assertEqual(consoles(run("ps3", "install").stdout, "install"), ["ps3"])

    def test_art_runs_once_at_the_top(self):
        output = run("art").stdout
        self.assertIn("shared/tools/make_app_art.py", output)
        self.assertEqual(consoles(output, "art"), [])

    def test_options_reach_the_console(self):
        self.assertIn("DEBUG=1", run("psv", "ssl", "DEBUG=1").stdout)


if __name__ == "__main__":
    unittest.main()
