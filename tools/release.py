#!/usr/bin/env python3
"""Releases a version of vitals: `make version 1.5` runs `release.py 1.5`.

It checks the number (major.minor, not lower than VERSION, no such tag yet), the working tree
(clean) and the changelog (its newest entry is that version), then writes VERSION and runs
`make test`. Then it commits VERSION, tags the commit with the version, and pushes the branch and
the tag to origin. Nothing is written before the checks pass, and VERSION is put back if the tests
fail.
"""
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
# As version.cmake accepts it: each part 0 to 99, without leading zeros
VERSION = re.compile(r"^([0-9]|[1-9][0-9])\.([0-9]|[1-9][0-9])$")
HEADING = re.compile(r"^## (\d+)\.(\d+)\s*$")


class ReleaseError(Exception):
    """A reason not to release, worded for the person releasing."""


def parse_version(text):
    """(major, minor) for "major.minor", or None."""
    match = VERSION.match(text.strip())
    return None if match is None else (int(match[1]), int(match[2]))


def check_changelog(text, version):
    """Raises ReleaseError unless the changelog's newest entry is version."""
    for line in text.splitlines():
        if not line.startswith("## "):
            continue
        match = HEADING.match(line)
        if match is None or (int(match[1]), int(match[2])) != version:
            raise ReleaseError(f"the newest changelog entry is {line.strip()!r}; add a \"## {version[0]}.{version[1]}\" "
                               "entry listing what changed first")
        return
    raise ReleaseError(f"CHANGELOG.md has no entries; add a \"## {version[0]}.{version[1]}\" entry first")


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, check=True, text=True, capture_output=True).stdout.strip()


def release(text):
    version = parse_version(text)
    if version is None:
        raise ReleaseError(f"{text!r} is not a version; use major.minor, such as 1.5")
    name = "%d.%d" % version
    current_text = (ROOT / "VERSION").read_text()
    current = parse_version(current_text)
    if current is not None and version < current:
        raise ReleaseError(f"{name} is older than the current version, {'%d.%d' % current}")
    if git("status", "--porcelain"):
        raise ReleaseError("the working tree has changes; commit or stash them first, so the release holds only "
                           "the release")
    branch = git("branch", "--show-current")
    if not branch:
        raise ReleaseError("not on a branch; check out the branch to release from first")
    if git("tag", "--list", name):
        raise ReleaseError(f"tag {name} exists already")
    try:
        remote = git("ls-remote", "--tags", "origin", f"refs/tags/{name}")
    except subprocess.CalledProcessError as error:
        raise ReleaseError(f"couldn't reach origin to check for tag {name}: {error.stderr.strip()}") from None
    if remote:
        raise ReleaseError(f"origin has a tag {name} already")
    check_changelog((ROOT / "CHANGELOG.md").read_text(), version)

    # The checks passed: write, test, and put VERSION back if the tests fail
    (ROOT / "VERSION").write_text(name + "\n")
    print(f"Testing vitals {name}...", flush=True)
    if subprocess.run(["make", "test"], cwd=ROOT).returncode != 0:
        (ROOT / "VERSION").write_text(current_text)
        raise ReleaseError("the tests failed; VERSION is as it was, and nothing was committed")

    git("add", "VERSION")
    if git("diff", "--cached", "--name-only"):
        git("commit", "-m", f"Release {name}")
    git("tag", name)
    print(f"Tagged {name}; pushing {branch} and {name} to origin...", flush=True)
    for ref in (branch, name):
        if subprocess.run(["git", "push", "origin", ref], cwd=ROOT).returncode != 0:
            raise ReleaseError(f"pushing {ref} failed; the release is committed and tagged here, so run "
                               f"\"git push origin {branch} {name}\" once origin can be reached")
    print(f"Released vitals {name}.")


def main(argv):
    if len(argv) != 2:
        print("usage: make version <major.minor>, such as make version 1.5", file=sys.stderr)
        return 2
    try:
        release(argv[1])
    except ReleaseError as error:
        print(f"Not released: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
