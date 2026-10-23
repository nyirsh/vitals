"""The new-version check against local HTTPS servers: the release number comes from the first site
that gives one, and nothing untrusted, redirected, oversized or malformed is believed."""
import contextlib
import http.server
import os
from pathlib import Path
import shlex
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[2]


class VersionCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="vitals-version-tests-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        environment = dict(os.environ)
        # As in the certificate tests: link the OpenSSL that Homebrew's curl uses
        paths = [str(path) for path in (Path('/opt/homebrew/opt/curl/lib/pkgconfig'),
                                        Path('/opt/homebrew/opt/openssl/lib/pkgconfig')) if path.exists()]
        if paths:
            environment['PKG_CONFIG_PATH'] = os.pathsep.join(paths + [environment.get('PKG_CONFIG_PATH', '')])
        try:
            flags = subprocess.check_output(['pkg-config', '--cflags', '--libs', 'libcurl', 'openssl'],
                                            env=environment, text=True, stderr=subprocess.PIPE)
        except (OSError, subprocess.CalledProcessError):
            cls.temporary.cleanup()
            raise unittest.SkipTest('Native version check tests require libcurl development libraries and pkg-config')
        cls.executable = cls.directory / 'version-check'
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror', '-O1', '-g',
                        '-I', str(ROOT / 'vitals-app'),
                        str(ROOT / 'vitals-app/version_check.c'), str(ROOT / 'vitals-app/release_version.c'),
                        str(ROOT / 'vitals-app/version_check_cli.c'), *shlex.split(flags),
                        '-o', str(cls.executable)], check=True, capture_output=True, timeout=60)
        for name in ('root', 'other'):
            cls.openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '1',
                        '-keyout', cls.directory / (name + '.key'), '-out', cls.directory / (name + '.pem'),
                        '-subj', '/CN=' + name, '-addext', 'basicConstraints=critical,CA:TRUE',
                        '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
        cls.servers = {}
        for name, issuer in (('good', 'root'), ('untrusted', 'other')):
            key, csr, certificate = [cls.directory / ('server-' + name + suffix) for suffix in ('.key', '.csr', '.crt')]
            cls.openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', csr,
                        '-subj', '/CN=localhost')
            extensions = cls.directory / (name + '.ext')
            extensions.write_text('subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\n')
            cls.openssl('x509', '-req', '-in', csr, '-CA', cls.directory / (issuer + '.pem'),
                        '-CAkey', cls.directory / (issuer + '.key'), '-CAcreateserial', '-out', certificate,
                        '-days', '1', '-sha256', '-extfile', extensions)
            cls.servers[name] = (certificate, key)

    @classmethod
    def openssl(cls, *arguments):
        subprocess.run(['openssl', *map(str, arguments)], check=True, capture_output=True, timeout=30)

    @contextlib.contextmanager
    def endpoint(self, body, identity='good', code=200):
        requests = []

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def handle(self):
                try:
                    super().handle()
                except (OSError, ssl.SSLError):
                    pass

            def log_message(self, *args):
                pass

            def do_GET(self):
                requests.append(dict(self.headers))
                self.send_response(code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                if code == 302:
                    self.send_header('Location', '/elsewhere')
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (OSError, ssl.SSLError):
                    pass

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(*map(str, self.servers[identity]))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f'https://localhost:{server.server_port}/releases', requests
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def latest(self, *urls):
        result = subprocess.run([str(self.executable), str(self.directory / 'root.pem'), *urls],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout.strip().split('=', 1)[1]

    @staticmethod
    def closed_url():
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            return f'https://localhost:{listener.getsockname()[1]}/releases'

    def test_github_and_gitlab_responses(self):
        with self.endpoint(b'{"url":"x","tag_name":"1.3","name":"vitals 1.3"}') as (url, requests):
            self.assertEqual(self.latest(url), '1.3')
        # The request names itself and asks for JSON
        self.assertEqual(requests[0].get('User-Agent'), 'vitals-test')
        self.assertEqual(requests[0].get('Accept'), 'application/json')
        with self.endpoint(b'[{"name":"vitals 1.4","tag_name":"1.4"},{"tag_name":"1.3"}]') as (url, _):
            self.assertEqual(self.latest(url), '1.4')

    def test_the_second_site_answers_when_the_first_cannot(self):
        gitlab = b'[{"tag_name":"1.4"}]'
        for first in ('closed', 404, b'{"tag_name":"v1.5"}', b'<html>busy</html>'):
            with self.subTest(first=first), self.endpoint(gitlab) as (second, _):
                if first == 'closed':
                    self.assertEqual(self.latest(self.closed_url(), second), '1.4')
                    continue
                body, code = (b'{}', first) if isinstance(first, int) else (first, 200)
                with self.endpoint(body, code=code) as (url, _):
                    self.assertEqual(self.latest(url, second), '1.4')
        # The first answer that works is used, the second site is not asked
        with self.endpoint(b'{"tag_name":"1.3"}') as (first, _), self.endpoint(gitlab) as (second, asked):
            self.assertEqual(self.latest(first, second), '1.3')
            self.assertEqual(asked, [])

    def test_nothing_doubtful_is_believed(self):
        cases = [
            ('untrusted certificate', b'{"tag_name":"9.9"}', 'untrusted', 200),
            ('redirect', b'{"tag_name":"9.9"}', 'good', 302),
            ('server error', b'{"tag_name":"9.9"}', 'good', 500),
            ('not a release number', b'{"tag_name":"9.9-beta"}', 'good', 200),
            ('no release', b'{"message":"Not Found"}', 'good', 200),
            ('oversized', b'{"tag_name":"9.9","pad":"' + b'x' * (300 * 1024) + b'"}', 'good', 200),
        ]
        for name, body, identity, code in cases:
            with self.subTest(case=name), self.endpoint(body, identity, code) as (url, _):
                self.assertEqual(self.latest(url), 'none')
        self.assertEqual(self.latest(self.closed_url()), 'none')


if __name__ == '__main__':
    unittest.main()
