"""CHANGELOG.md, which the app shows, has an entry for every release, the newest being VERSION's."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
# The date is left out until a release is out
HEADING = re.compile(r"^## (\d+)\.(\d+)(?: \((\d{4}-\d{2}-\d{2})\))?$")


def releases():
    """Each "## major.minor" or "## major.minor (date)" heading, in the file's order (the date None when it is
    left out); other "## " lines are reported as None."""
    found = []
    for line in (ROOT / "CHANGELOG.md").read_text().splitlines():
        if line.startswith("## "):
            match = HEADING.match(line)
            found.append(None if match is None else ((int(match[1]), int(match[2])), match[3], line))
    return found


class ChangelogTests(unittest.TestCase):
    def test_headings_are_well_formed(self):
        for release in releases():
            self.assertIsNotNone(release, 'every "## " heading should read "## major.minor", with " (YYYY-MM-DD)" '
                                          "once released")

    def test_newest_entry_is_this_version(self):
        version = (ROOT / "VERSION").read_text().strip()
        found = releases()
        self.assertTrue(found, "CHANGELOG.md has no releases")
        newest = found[0]
        self.assertEqual("%d.%d" % newest[0], version,
                         f"the newest changelog entry is {newest[2]!r}; add one for {version}")

    def test_newest_first_once_each(self):
        found = [release for release in releases() if release is not None]
        versions = [release[0] for release in found]
        self.assertEqual(versions, sorted(versions, reverse=True), "releases should be listed newest first")
        self.assertEqual(len(versions), len(set(versions)), "each release should be listed once")
        dates = [release[1] for release in found if release[1] is not None]
        self.assertEqual(dates, sorted(dates, reverse=True), "newer releases can't have older dates")

    def test_every_release_lists_a_change(self):
        lines = (ROOT / "CHANGELOG.md").read_text().splitlines()
        headings = [i for i, line in enumerate(lines) if line.startswith("## ")]
        for start, end in zip(headings, headings[1:] + [len(lines)]):
            with self.subTest(release=lines[start]):
                self.assertTrue(any(line.startswith("- ") for line in lines[start + 1:end]),
                                "each release should list at least one change")


if __name__ == "__main__":
    unittest.main()
