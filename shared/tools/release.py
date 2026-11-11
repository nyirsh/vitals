#!/usr/bin/env python3
"""Publishes the release VERSION names, from CI on main once everything built and passed: when there's
no tag for it yet, a tag on this commit and a release named after it, with the changelog's section for
it as its notes and the apps attached. A version that already has its release is left alone, so every
later push to main does nothing until VERSION changes; a tag left without its release by a run that
stopped halfway gets its release.

    shared/tools/release.py github|gitlab FILE... [--dry-run]

GitHub: GITHUB_TOKEN (contents: write), GITHUB_REPOSITORY, GITHUB_SHA, GITHUB_API_URL. GitLab:
CI_JOB_TOKEN, CI_PROJECT_ID, CI_COMMIT_SHA, CI_API_V4_URL; the files go to the project's generic
package registry, linked from the release. Only the standard library is used."""
import argparse
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

REPOSITORY = Path(__file__).resolve().parents[2]


def version():
    return (REPOSITORY / "VERSION").read_text(encoding="utf-8").strip()


def notes(changelog, release):
    """The changelog's section for release: what's under "## <release>" up to the next "## ", trimmed"""
    lines = changelog.splitlines()
    heading = f"## {release}"
    try:
        start = next(i for i, line in enumerate(lines) if line.strip() == heading)
    except StopIteration:
        raise SystemExit(f"CHANGELOG.md has no '{heading}' section: write it before releasing {release}")
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    text = "\n".join(lines[start + 1:end]).strip()
    if not text:
        raise SystemExit(f"CHANGELOG.md's '{heading}' section is empty")
    return text + "\n"


def call(method, url, headers, body=None, content_type="application/json"):
    """The response's JSON (or None), and its status; 404 is an answer, any other error stops"""
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        headers = {**headers, "Content-Type": content_type}
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            text = response.read()
            return (json.loads(text) if text else None), response.status
    except urllib.error.HTTPError as error:
        if error.code == 404:
            error.close()
            return None, 404
        raise SystemExit(f"{method} {url}: {error.code} {error.read().decode(errors='replace')[:500]}")


class GitHub:
    def __init__(self):
        self.api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
        self.repository = os.environ["GITHUB_REPOSITORY"]
        self.commit = os.environ["GITHUB_SHA"]
        self.headers = {"Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}",
                        "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}

    def released(self, release):
        _, status = call("GET", f"{self.api}/repos/{self.repository}/releases/tags/{urllib.parse.quote(release)}",
                         self.headers)
        return status != 404

    def publish(self, release, text, files):
        _, status = call("GET", f"{self.api}/repos/{self.repository}/git/ref/tags/{urllib.parse.quote(release)}",
                         self.headers)
        if status == 404:
            call("POST", f"{self.api}/repos/{self.repository}/git/refs", self.headers,
                 {"ref": f"refs/tags/{release}", "sha": self.commit})
            print(f"tag {release} -> {self.commit}")
        else:
            print(f"tag {release} is there already, without its release")
        created, _ = call("POST", f"{self.api}/repos/{self.repository}/releases", self.headers,
                          {"tag_name": release, "name": release, "body": text})
        upload = created["upload_url"].split("{", 1)[0]
        for path in files:
            call("POST", f"{upload}?name={urllib.parse.quote(path.name)}", self.headers, path.read_bytes(),
                 "application/octet-stream")
            print(f"attached {path.name}")
        print(created["html_url"])


class GitLab:
    def __init__(self):
        self.api = os.environ["CI_API_V4_URL"]
        self.project = os.environ["CI_PROJECT_ID"]
        self.commit = os.environ["CI_COMMIT_SHA"]
        self.headers = {"JOB-TOKEN": os.environ["CI_JOB_TOKEN"]}

    def released(self, release):
        _, status = call("GET", f"{self.api}/projects/{self.project}/releases/{urllib.parse.quote(release, safe='')}",
                         self.headers)
        return status != 404

    def publish(self, release, text, files):
        links = []
        for path in files:
            url = f"{self.api}/projects/{self.project}/packages/generic/vitals/{release}/{path.name}"
            call("PUT", url, self.headers, path.read_bytes(), "application/octet-stream")
            print(f"uploaded {path.name}")
            links.append({"name": path.name, "url": url, "link_type": "package"})
        # A job's token can't create a tag by itself: the release makes it, on this commit, first
        created, _ = call("POST", f"{self.api}/projects/{self.project}/releases", self.headers,
                          {"name": release, "tag_name": release, "ref": self.commit, "description": text,
                           "assets": {"links": links}})
        print(f"tag {release} -> {self.commit}")
        print(created.get("_links", {}).get("self", "released"))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("host", choices=("github", "gitlab"))
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--dry-run", action="store_true", help="say what would be published, publish nothing")
    args = parser.parse_args()
    release = version()
    text = notes((REPOSITORY / "CHANGELOG.md").read_text(encoding="utf-8"), release)
    missing = [str(path) for path in args.files if not path.is_file()]
    if missing:
        raise SystemExit(f"Not built: {', '.join(missing)}")
    if args.dry_run:
        print(f"release {release}, with {', '.join(path.name for path in args.files)}, notes:\n{text}")
        return 0
    host = GitHub() if args.host == "github" else GitLab()
    if host.released(release):
        print(f"{release} is released already: nothing to do")
        return 0
    host.publish(release, text, args.files)
    return 0


if __name__ == "__main__":
    sys.exit(main())
