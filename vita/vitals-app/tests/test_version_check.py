"""The new-version check against local HTTPS servers, on the Vita's curl backend (OpenSSL): the tests
are both consoles' (../../../shared/app/tests/release_fetch_tests.py)"""
import os
from pathlib import Path
import shlex
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT.parent / 'shared/app/tests'))
from release_fetch_tests import ReleaseFetchTests, SHARED_APP  # noqa: E402


class VersionCheckTests(ReleaseFetchTests, unittest.TestCase):
    @classmethod
    def build_executable(cls, directory):
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
        executable = directory / 'version-check'
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror', '-O1', '-g',
                        '-I', str(SHARED_APP),
                        *(str(SHARED_APP / name) for name in
                          ('download.c', 'release_fetch.c', 'release_version.c', 'tests/release_fetch_cli.c')),
                        *shlex.split(flags),
                        '-o', str(executable)], check=True, capture_output=True, timeout=60)
        return executable


if __name__ == '__main__':
    unittest.main()
