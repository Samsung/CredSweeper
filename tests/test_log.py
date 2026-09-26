import shutil
import tempfile
from pathlib import Path
from unittest import TestCase

from credsweeper.app import APP_PATH
from credsweeper.common.constants import ASCII, UTF_8
from tests import SAMPLES_PATH, TESTS_PATH
from tests.test_int import TestInt


class TestLog(TestCase):

    def setUp(self):
        self.maxDiff = None

    def test_log_p(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_log_cfg = Path(tmp_dir) / "log.yaml"
            with open(TESTS_PATH / "log.yaml", 'r', encoding=ASCII) as fi:
                t = fi.read()
            test_log_dir = Path(tmp_dir) / "log"
            with open(test_log_cfg, 'w', encoding=ASCII) as fo:
                # enable all handlers and add for the root
                fo.write(t.replace("filename: ./log/", f"filename: {test_log_dir}/"))
            _stdout, _stderr = TestInt._m_credsweeper([
                "--path",
                str(SAMPLES_PATH), "--log_config",
                str(test_log_cfg), "--jobs", "2", "--log", "INFO", "--no-stdout"
            ])
            self.assertNotIn("| TRACE |", _stdout)
            self.assertNotIn("| DEBUG |", _stdout)
            self.assertIn("| INFO |", _stdout)
            self.assertIn("| WARNING |", _stdout)
            self.assertTrue(test_log_dir.exists())
            with open(test_log_dir / "debug.log", 'r', encoding=UTF_8) as debug_f:
                debug_text = debug_f.read()
                self.assertIn("| TRACE |", debug_text)
                self.assertIn("| DEBUG |", debug_text)
                self.assertIn("| INFO |", debug_text)
                self.assertIn("| WARNING |", debug_text)
                for line in debug_text.splitlines():
                    if " | " not in line:
                        # multiline debug
                        continue
                    self.assertTrue(any(x in line for x in ["| TRACE |", "| DEBUG |", "| INFO |", "| WARNING |"]), line)

            with open(test_log_dir / "warning.log", 'r', encoding=UTF_8) as warning_f:
                warning_text = warning_f.read()
                self.assertNotIn("| TRACE |", warning_text)
                self.assertNotIn("| DEBUG |", warning_text)
                self.assertNotIn("| INFO |", warning_text)
                self.assertIn("| WARNING |", warning_text)
                for line in warning_f.readlines():
                    self.assertIn(" | WARNING | ", line)
