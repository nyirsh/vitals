"""shared/tools/release.py: the changelog's section for a version, and both hosts' calls, against a
stand-in server: nothing when the release exists, otherwise the tag, the release and its files."""
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import release  # noqa: E402

CHANGELOG = """# Changelog

## 2.1

- one
- two

## 2.0

- old
"""


class Recorder(BaseHTTPRequestHandler):
    calls, existing = [], set()

    def log_message(self, *arguments):
        pass

    def answer(self, status, body=None):
        data = json.dumps(body).encode() if body is not None else b""
        self.send_response(status)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def handle_any(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        Recorder.calls.append((self.command, self.path, body, dict(self.headers)))
        if self.command == "GET":
            self.answer(200, {}) if self.path in Recorder.existing else self.answer(404, {"message": "Not Found"})
        elif self.path.endswith("/releases") and "projects" not in self.path:
            port = self.server.server_address[1]
            self.answer(201, {"upload_url": f"http://127.0.0.1:{port}/upload/1/assets{{?name,label}}",
                              "html_url": "https://example/release"})
        else:
            self.answer(201, {})

    do_GET = do_POST = do_PUT = handle_any


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        Recorder.calls, Recorder.existing = [], set()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Recorder)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.directory = tempfile.TemporaryDirectory()
        self.files = []
        for name in ("vitals-app.vpk", "vitals-app.pkg"):
            path = Path(self.directory.name) / name
            path.write_bytes(name.encode())
            self.files.append(path)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.directory.cleanup()

    def test_notes_are_the_version_section(self):
        self.assertEqual(release.notes(CHANGELOG, "2.1"), "- one\n- two\n")
        self.assertEqual(release.notes(CHANGELOG, "2.0"), "- old\n")

    def test_a_version_without_notes_stops(self):
        with self.assertRaises(SystemExit):
            release.notes(CHANGELOG, "9.9")
        with self.assertRaises(SystemExit):
            release.notes("## 3.0\n\n## 2.0\n- x\n", "3.0")

    def test_the_real_changelog_has_this_version(self):
        self.assertTrue(release.notes((release.REPOSITORY / "CHANGELOG.md").read_text(), release.version()).strip())

    def github(self):
        return mock.patch.dict(os.environ, {"GITHUB_API_URL": self.base, "GITHUB_REPOSITORY": "o/r", "GITHUB_SHA": "abc",
                                            "GITHUB_TOKEN": "t"})

    def gitlab(self):
        return mock.patch.dict(os.environ, {"CI_API_V4_URL": self.base + "/api/v4", "CI_PROJECT_ID": "7",
                                            "CI_COMMIT_SHA": "abc", "CI_JOB_TOKEN": "t"})

    def test_github_releases_with_tag_and_files(self):
        with self.github(), redirect_stdout(io.StringIO()):
            host = release.GitHub()
            self.assertFalse(host.released("2.1"))
            host.publish("2.1", "- one\n", self.files)
        posts = [(method, path, body) for method, path, body, _ in Recorder.calls if method == "POST"]
        self.assertEqual(posts[0][1], "/repos/o/r/git/refs")
        self.assertEqual(json.loads(posts[0][2]), {"ref": "refs/tags/2.1", "sha": "abc"})
        self.assertEqual(json.loads(posts[1][2]), {"tag_name": "2.1", "name": "2.1", "body": "- one\n"})
        self.assertEqual([p[1] for p in posts[2:]], ["/upload/1/assets?name=vitals-app.vpk", "/upload/1/assets?name=vitals-app.pkg"])
        self.assertTrue(all(h.get("Authorization") == "Bearer t" for _, _, _, h in Recorder.calls))

    def test_github_finishes_a_tag_left_without_its_release(self):
        Recorder.existing = {"/repos/o/r/git/ref/tags/2.1"}
        with self.github(), redirect_stdout(io.StringIO()):
            release.GitHub().publish("2.1", "- one\n", self.files)
        self.assertNotIn("/repos/o/r/git/refs", [path for method, path, _, _ in Recorder.calls if method == "POST"])

    def test_gitlab_uploads_then_releases(self):
        with self.gitlab(), redirect_stdout(io.StringIO()):
            host = release.GitLab()
            self.assertFalse(host.released("2.1"))
            host.publish("2.1", "- one\n", self.files)
        puts = [path for method, path, _, _ in Recorder.calls if method == "PUT"]
        self.assertEqual(puts, ["/api/v4/projects/7/packages/generic/vitals/2.1/vitals-app.vpk",
                                "/api/v4/projects/7/packages/generic/vitals/2.1/vitals-app.pkg"])
        body = json.loads([b for method, path, b, _ in Recorder.calls if method == "POST"][0])
        self.assertEqual((body["tag_name"], body["ref"], body["name"]), ("2.1", "abc", "2.1"))
        self.assertEqual([link["name"] for link in body["assets"]["links"]], ["vitals-app.vpk", "vitals-app.pkg"])
        self.assertTrue(all({k.lower(): v for k, v in h.items()}.get("job-token") == "t" for _, _, _, h in Recorder.calls))

    def test_an_existing_release_is_left_alone(self):
        Recorder.existing = {"/repos/o/r/releases/tags/2.1"}
        with self.github(), mock.patch.object(release, "version", return_value="2.1"), \
                mock.patch.object(sys, "argv", ["release.py", "github", *map(str, self.files)]), redirect_stdout(io.StringIO()) as out:
            release.main()
        self.assertIn("released already", out.getvalue())
        self.assertEqual([method for method, _, _, _ in Recorder.calls], ["GET"])


if __name__ == "__main__":
    unittest.main()
