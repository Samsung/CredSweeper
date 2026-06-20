import logging
import logging.config
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import AnyStr, Tuple
from unittest import TestCase

from credsweeper import CredSweeper
from credsweeper.app import APP_PATH
from credsweeper.file_handler.files_provider import FilesProvider
from credsweeper.utils.util import Util
from tests import SAMPLES_PATH, TESTS_PATH

CHECK_WORKFLOW_PATH = TESTS_PATH.parent / ".github" / "workflows" / "check.yml"


class TestLog(TestCase):

    def setUp(self):
        self.maxDiff = None

    @staticmethod
    def _script(args) -> Tuple[str, str]:
        with subprocess.Popen(
                args=["python", __file__, *args],  #
                cwd=APP_PATH.parent,  #
                stdout=subprocess.PIPE,  #
                stderr=subprocess.PIPE) as proc:
            _stdout, _stderr = proc.communicate()

        def transform(x: AnyStr) -> str:
            if isinstance(x, bytes):
                return x.decode(errors='replace')
            elif isinstance(x, str):
                return x
            else:
                raise ValueError(f"Unknown type: {type(x)}")

        return transform(_stdout), transform(_stderr)

    def test_log_n(self) -> None:
        # custom log config
        _stdout, _stderr = self._script([str((Path(__file__).parent / "test_log.yaml"))])
        self.assertIn(" WARNING " , _stderr ,( _stdout,_stderr))
        self.assertNotIn(" | WARNING | ", _stderr,( _stdout,_stderr))
        print(_stderr)

    def test_log_p(self) -> None:
        # default log config requires log dir at start
        log_dir = APP_PATH.parent / "log"
        log_dir.mkdir(exist_ok=True)
        _stdout, _stderr = self._script([str((APP_PATH / "secret" / "log.yaml"))])
        self.assertIn(" | WARNING | " , _stderr , ( _stdout,_stderr))
        print(_stderr)


if __name__ == "__main__":
    print(sys.argv, flush=True)
    if log_cfg := sys.argv[1] if 1 < len(sys.argv) else None:
        logging_config = Util.yaml_load(log_cfg)
        logging.config.dictConfig(logging_config)

    cs = CredSweeper(pool_count=2)
    cs.run(FilesProvider([SAMPLES_PATH]))
