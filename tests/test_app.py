import subprocess
import subprocess
import sys
from typing import AnyStr, Tuple
from unittest import TestCase

from tests import SAMPLES_PATH, \
    TESTS_PATH


class TestApp(TestCase):

    @staticmethod
    def _m_credsweeper(args) -> Tuple[str, str]:
        print(TESTS_PATH.parent, flush=True)
        print(TESTS_PATH.parent, flush=True)
        print(TESTS_PATH.parent, flush=True)
        proc = subprocess.Popen(
            [sys.executable, "-m", "credsweeper", *args],  #
            cwd=TESTS_PATH.parent,  #
            stdout=subprocess.PIPE,  #
            stderr=subprocess.PIPE)  #
        _stdout, _stderr = proc.communicate()

        def transform(x: AnyStr) -> str:
            if isinstance(x, bytes):
                return x.decode(errors='replace')
            elif isinstance(x, str):
                return x
            else:
                raise ValueError(f"Unknown type: {type(x)}")

        return transform(_stdout), transform(_stderr)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_severity_p(self) -> None:
        _stdout, _stderr = self._m_credsweeper([  #
            "--log", "DEBUG", "--path", str(SAMPLES_PATH)
        ])
        self.assertIn("Detected Credentials: 106", _stdout, _stdout)
        self.assertNotIn("CRITICAL", _stdout, _stdout)
        self.assertNotIn("CRITICAL", _stderr, _stderr)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

