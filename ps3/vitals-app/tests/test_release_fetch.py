"""The new-release check's fetch, and so the shared download, against local HTTPS servers on the PS3's
curl backend, Mbed TLS (../curl, ../crypto): the tests are both consoles'
(../../../shared/app/tests/release_fetch_tests.py), and the program is built by this folder's CMake
(vitals_app_release_fetch_mbedtls), which `make test` runs first"""
import os
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / 'shared/app/tests'))
from release_fetch_tests import ReleaseFetchTests  # noqa: E402

# Where `make test` builds it (../../Makefile's test target), or VITALS_RELEASE_FETCH_MBEDTLS
BUILT = HERE.parents[1] / 'build/vitals-app-tests/vitals_app_release_fetch_mbedtls'


class ReleaseFetchMbedTlsTests(ReleaseFetchTests, unittest.TestCase):
    @classmethod
    def build_executable(cls, directory):
        executable = Path(os.environ.get('VITALS_RELEASE_FETCH_MBEDTLS', BUILT))
        if not executable.is_file():
            cls.temporary.cleanup()
            raise unittest.SkipTest(f'{executable} is missing: run make test, which builds it first')
        return executable


if __name__ == '__main__':
    unittest.main()
