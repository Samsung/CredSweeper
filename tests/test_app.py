import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import AnyStr, Tuple
from unittest import TestCase

import pytest

from credsweeper import CREDSWEEPER_DIR
from credsweeper.utils import Util
from tests import AZ_STRING, SAMPLES_FILTERED_BY_POST_COUNT, SAMPLES_POST_CRED_COUNT, SAMPLES_IN_DEEP_1, \
    SAMPLES_IN_DEEP_3, SAMPLES_DIR, TESTS_DIR, PROJECT_DIR


class TestApp(TestCase):

    @staticmethod
    def _m_credsweeper(args) -> Tuple[AnyStr, AnyStr]:
        proc = subprocess.Popen(
            [sys.executable, "-m", "credsweeper", *args],  #
            cwd=PROJECT_DIR,  #
            stdout=subprocess.PIPE,  #
            stderr=subprocess.PIPE)  #
        return proc.communicate()

    def test_it_works_p(self) -> None:
        target_path = str(SAMPLES_DIR / "password")
        _stdout, _stderr = self._m_credsweeper(["--path", target_path, "--log", "silence"])
        output = " ".join(_stdout.decode("UTF-8").split()[:-1])

        expected = f"""
                    rule: Password
                    / severity: medium
                    / line_data_list:
                        [line: 'password = \"cackle!\"'
                        / line_num: 1
                        / path: {target_path}
                        / value: 'cackle!'
                        / entropy_validation: False]
                    / api_validation: NOT_AVAILABLE
                    / ml_validation: VALIDATED_KEY\n
                    Detected Credentials: 1\n
                    Time Elapsed:
                    """
        expected = " ".join(expected.split())
        assert output == expected

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_huge_diff_p(self) -> None:
        # verifies issue when huge patch is parsed very slow
        # https://github.com/Samsung/CredSweeper/issues/242
        text = """diff --git a/huge.file b/huge.file
                index 0000000..1111111 100644
                --- a/huge.file
                +++ a/huge.file
                @@ -3,13 +3,1000007 @@
                 00000000
                 11111111
                 22222222
                -33333333
                -44444444
                +55555555
                +66666666
                """
        for n in range(0, 1000000):
            text += "+" + hex(n) + "\n"
        with tempfile.TemporaryDirectory() as tmp_dir:
            target_path = os.path.join(tmp_dir, f"{__name__}.diff")
            start_time = time.time()
            _stdout, _stderr = self._m_credsweeper(["--path", target_path, "--ml_threshold", "0", "--log", "silence"])
            self.assertGreater(100, time.time() - start_time)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_it_works_without_ml_p(self) -> None:
        target_path = str(SAMPLES_DIR / "password")
        _stdout, _stderr = self._m_credsweeper(["--path", target_path, "--ml_threshold", "0", "--log", "silence"])
        output = " ".join(_stdout.decode("UTF-8").split()[:-1])

        expected = f"""
                    rule: Password
                    / severity: medium
                    / line_data_list:
                        [line: 'password = \"cackle!\"'
                        / line_num: 1
                        / path: {target_path}
                        / value: 'cackle!'
                        / entropy_validation: False]
                    / api_validation: NOT_AVAILABLE
                    / ml_validation: NOT_AVAILABLE\n
                    Detected Credentials: 1\n
                    Time Elapsed:
                    """
        expected = " ".join(expected.split())
        assert output == expected

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_it_works_with_patch_p(self) -> None:
        target_path = str(SAMPLES_DIR / "password.patch")
        _stdout, _stderr = self._m_credsweeper(["--diff_path", target_path, "--log", "silence"])
        output = " ".join(_stdout.decode("UTF-8").split()[:-1])

        expected = """
                    rule: Password
                    / severity: medium
                    / line_data_list:
                    [line: '  "password": "dkajco1"'
                        / line_num: 3
                        / path: .changes/1.16.98.json
                        / value: 'dkajco1'
                        / entropy_validation: False]
                    / api_validation: NOT_AVAILABLE
                    / ml_validation: VALIDATED_KEY\n
                    Added File Credentials: 1\n
                    Deleted File Credentials: 0\n
                    Time Elapsed:
                    """
        expected = " ".join(expected.split())
        assert output == expected

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_it_works_with_multiline_in_patch_p(self) -> None:
        target_path = str(SAMPLES_DIR / "multiline.patch")
        _stdout, _stderr = self._m_credsweeper(["--diff_path", target_path, "--log", "silence"])
        output = " ".join(_stdout.decode("UTF-8").split()[:-1])

        expected = """
                    rule: AWS Client ID
                        / severity: high
                        / line_data_list:
                            [line: ' clid = "AKIAQWADE5R42RDZ4JEM"'
                            / line_num: 4
                            / path: creds.py
                            / value: 'AKIAQWADE5R42RDZ4JEM'
                            / entropy_validation: False]
                        / api_validation: NOT_AVAILABLE
                        / ml_validation: VALIDATED_KEY
                    rule: AWS Multi
                        / severity: high
                        / line_data_list:
                            [line: ' clid = "AKIAQWADE5R42RDZ4JEM"'
                            / line_num: 4
                            / path: creds.py
                            / value: 'AKIAQWADE5R42RDZ4JEM'
                            / entropy_validation: False, line: ' token = "V84C7sDU001tFFodKU95USNy97TkqXymnvsFmYhQ"'
                            / line_num: 5
                            / path: creds.py
                            / value: 'V84C7sDU001tFFodKU95USNy97TkqXymnvsFmYhQ'
                            / entropy_validation: True]
                        / api_validation: NOT_AVAILABLE
                        / ml_validation: VALIDATED_KEY
                    rule: Token
                        / severity: medium
                        / line_data_list:
                            [line: ' token = "V84C7sDU001tFFodKU95USNy97TkqXymnvsFmYhQ"'
                            / line_num: 5
                            / path: creds.py
                            / value: 'V84C7sDU001tFFodKU95USNy97TkqXymnvsFmYhQ'
                            / entropy_validation: True]
                        / api_validation: NOT_AVAILABLE
                        / ml_validation: VALIDATED_KEY\n
                    Added File Credentials: 3\n
                    Deleted File Credentials: 0\n
                    Time Elapsed:
                    """
        expected = " ".join(expected.split())
        assert output == expected

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @pytest.mark.skipif(0 != subprocess.call(["curl", "https://maps.googleapis.com/"]),
                        reason="network is not available")
    def test_it_works_with_api_p(self) -> None:
        target_path = str(SAMPLES_DIR / "google_api_key")
        _stdout, _stderr = self._m_credsweeper(
            ["--path", target_path, "--ml_threshold", "0", "--api_validation", "--log", "silence"], )
        output = " ".join(_stdout.decode("UTF-8").split()[:-1])

        expected = f"""
                    rule: Google API Key
                    / severity: high
                    / line_data_list:
                    [line: 'AIzaGiReoGiCrackleCrackle12315618112315'
                        / line_num: 1
                        / path: {target_path}
                        / value: 'AIzaGiReoGiCrackleCrackle12315618112315'
                        / entropy_validation: True]
                    / api_validation: INVALID_KEY
                    / ml_validation: NOT_AVAILABLE\n
                    Detected Credentials: 1\n
                    Time Elapsed:
                    """
        expected = " ".join(expected.split())
        assert output == expected

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_it_works_n(self) -> None:
        _stdout, _stderr = self._m_credsweeper([])

        # Merge more than two whitespaces into one because _stdout and _stderr are changed based on the terminal size
        output = " ".join(_stderr.decode("UTF-8").split())

        expected = "usage: python -m credsweeper [-h]" \
                   " (--path PATH [PATH ...]" \
                   " | --diff_path PATH [PATH ...]" \
                   " | --export_config [PATH]" \
                   " | --export_log_config [PATH]" \
                   ")" \
                   " [--rules [PATH]]" \
                   " [--config [PATH]]" \
                   " [--log_config [PATH]]" \
                   " [--denylist PATH]" \
                   " [--find-by-ext]" \
                   " [--depth POSITIVE_INT]" \
                   " [--ml_threshold FLOAT_OR_STR]" \
                   " [--ml_batch_size POSITIVE_INT]" \
                   " [--api_validation]" \
                   " [--jobs POSITIVE_INT]" \
                   " [--skip_ignored]" \
                   " [--save-json [PATH]]" \
                   " [--save-xlsx [PATH]]" \
                   " [--log LOG_LEVEL]" \
                   " [--size_limit SIZE_LIMIT]" \
                   " [--banner] " \
                   " [--version] " \
                   "python -m credsweeper: error: one of the arguments" \
                   " --path" \
                   " --diff_path" \
                   " --export_config" \
                   " --export_log_config" \
                   " is required "
        expected = " ".join(expected.split())
        assert output == expected

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_log_p(self) -> None:
        apk_path = str(SAMPLES_DIR / "pem_key.apk")
        _stdout, _stderr = self._m_credsweeper(
            ["--log", "Debug", "--depth", "7", "--ml_threshold", "0", "--path", apk_path, "not_existed_path"])
        assert len(_stderr) == 0
        output = _stdout.decode()

        assert "DEBUG" in output, output
        assert "INFO" in output, output
        assert "WARNING" in output, output
        assert "ERROR" in output, output
        assert not ("CRITICAL" in output), output

        for line in output.splitlines():
            if 5 <= len(line) and "rule:" == line[0:5]:
                assert re.match(r"rule: \.*", line), line
            elif 21 <= len(line) and "Detected Credentials:" == line[0:21]:
                assert re.match(r"Detected Credentials: \d+", line), line
            elif 13 <= len(line) and "Time Elapsed:" == line[0:13]:
                assert re.match(r"Time Elapsed: \d+\.\d+", line), line
            else:
                self.assertRegex(line,
                                 r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d+ \| (DEBUG|INFO|WARNING|ERROR) \| \w+:\d+ \| .*",
                                 line)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_log_n(self) -> None:
        _stdout, _stderr = self._m_credsweeper(["--log", "CriTicaL", "--rule", "NOT_EXISTED_PATH", "--path", "."])
        assert len(_stderr) == 0
        output = _stdout.decode()

        assert not ("DEBUG" in output), output
        assert not ("INFO" in output), output
        assert not ("WARNING" in output), output
        assert not ("ERROR" in output), output
        assert "CRITICAL" in output, output

        assert any(
            re.match(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d+ \| (CRITICAL) \| \w+:\d+ \| .*", line)
            for line in output.splitlines()), output

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_help_p(self) -> None:
        _stdout, _stderr = self._m_credsweeper(["--help"])
        output = " ".join(_stdout.decode("UTF-8").split())
        help_path = os.path.join(TESTS_DIR, "..", "docs", "source", "guide.rst")
        with open(help_path, "r") as f:
            text = ""
            started = False
            for line in f.read().splitlines():
                if ".. note::" == line:
                    break
                if ".. code-block:: text" == line:
                    started = True
                    continue
                if started:
                    # There is argparse change on python3.10 to display just "options:"
                    if sys.version_info.minor >= 10 and line.strip() == "optional arguments:":
                        text += line.replace("optional arguments:", "options:")
                    else:
                        text += line
            expected = " ".join(text.split())
            assert output == expected

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_version_p(self) -> None:
        _stdout, _stderr = self._m_credsweeper(["--version"])
        # Merge more than two whitespaces into one because _stdout and _stderr are changed based on the terminal size
        output = " ".join(_stdout.decode("UTF-8").split())
        self.assertRegex(output, r"CredSweeper \d+\.\d+\.\d+")

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_banner_p(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            _stdout, _stderr = self._m_credsweeper(["--banner", "--export_config", json_filename])
            output = " ".join(_stdout.decode().split())
            self.assertRegex(output, r"CredSweeper \d+\.\d+\.\d+ crc32:[0-9a-f]{8}")

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_patch_save_json_p(self) -> None:
        target_path = str(SAMPLES_DIR / "password.patch")
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            _stdout, _stderr = self._m_credsweeper(
                ["--diff_path", target_path, "--save-json", json_filename, "--log", "silence"])
            assert os.path.exists(os.path.join(tmp_dir, f"{__name__}_added.json"))
            assert os.path.exists(os.path.join(tmp_dir, f"{__name__}_deleted.json"))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_patch_save_json_n(self) -> None:
        start_time = time.time()
        target_path = str(SAMPLES_DIR / "password.patch")
        _stdout, _stderr = self._m_credsweeper(["--diff_path", target_path, "--log", "silence"])
        for root, dirs, files in os.walk(PROJECT_DIR):
            self.assertIn("credsweeper", dirs)
            for file in files:
                # check whether the report was created AFTER test launch to avoid failures during development
                self.assertFalse(file.endswith(".json") and os.stat(os.path.join(root, file)).st_mtime > start_time)
            dirs.clear()

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_export_config_p(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            _stdout, _stderr = self._m_credsweeper(["--export_config", json_filename, "--log", "silence"])
            assert os.path.exists(json_filename)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_import_config_p(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            custom_config = os.path.join(tmp_dir, f"{__name__}.json")
            shutil.copyfile(CREDSWEEPER_DIR / "secret" / "config.json", custom_config)
            args = ["--config", custom_config, "--path", str(CREDSWEEPER_DIR), "--find-by-ext", "--log", "CRITICAL"]
            _stdout, _stderr = self._m_credsweeper(args)
            self.assertEqual("", _stderr.decode())
            output = _stdout.decode()
            self.assertNotIn("CRITICAL", output)
            self.assertIn("Time Elapsed:", output)
            self.assertIn("Detected Credentials: 0", output)
            self.assertEqual(2, len(output.splitlines()))
            # add .py to find by extension
            modified_config = Util.json_load(custom_config)
            self.assertIn("find_by_ext_list", modified_config.keys())
            self.assertIsInstance(modified_config["find_by_ext_list"], list)
            modified_config["find_by_ext_list"].append(".py")
            Util.json_dump(modified_config, custom_config)
            _stdout, _stderr = self._m_credsweeper(args)
            output = _stdout.decode()
            self.assertEqual("", _stderr.decode())
            self.assertNotIn("CRITICAL", output)
            self.assertIn("Time Elapsed:", output)
            self.assertNotIn("Detected Credentials: 0", output)
            self.assertLess(42, len(output.splitlines()))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_import_config_n(self) -> None:
        # not existed file
        _stdout, _stderr = self._m_credsweeper(
            ["--config", "not_existed_file", "--path",
             str(CREDSWEEPER_DIR), "--log", "CRITICAL"])
        self.assertEqual(0, len(_stderr))
        self.assertIn("CRITICAL", _stdout.decode())
        # wrong config
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            with open(json_filename, "w") as f:
                f.write('{}')
            _stdout, _stderr = self._m_credsweeper(
                ["--config", json_filename, "--path",
                 str(CREDSWEEPER_DIR), "--log", "CRITICAL"])
            self.assertEqual(0, len(_stderr))
            self.assertIn("CRITICAL", _stdout.decode())

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_export_log_config_p(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_filename = os.path.join(tmp_dir, f"{__name__}.yaml")
            _stdout, _stderr = self._m_credsweeper(["--export_log_config", test_filename, "--log", "silence"])
            assert os.path.exists(test_filename)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_import_log_config_p(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_filename = os.path.join(tmp_dir, f"{__name__}.yaml")
            _o, _e = self._m_credsweeper(["--export_log_config", test_filename, "--log", "silence"])
            self.assertFalse(os.path.exists(os.path.join(tmp_dir, "log")))
            with open(test_filename, 'r') as f:
                text = f.read().replace("filename: ./log", f"filename: {tmp_dir}/log")
            with open(test_filename, 'w') as f:
                f.write(text)
            _stdout, _stderr = self._m_credsweeper(["--log_config", test_filename, "--log", "silence", "--path", "X3"])
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "log")))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "log", "error.log")))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_find_by_ext_p(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            # .deR will be found also!
            for f in [".pem", ".cer", ".csr", ".deR"]:
                file_path = os.path.join(tmp_dir, f"dummy{f}")
                assert not os.path.exists(file_path)
                open(file_path, "w").write(AZ_STRING)

            # not of all will be found due they are empty
            for f in [".jks", ".KeY"]:
                file_path = os.path.join(tmp_dir, f"dummy{f}")
                assert not os.path.exists(file_path)
                open(file_path, "w").close()

            # the directory hides all files
            ignored_dir = os.path.join(tmp_dir, "target")
            os.mkdir(ignored_dir)
            for f in [".pfx", ".p12"]:
                file_path = os.path.join(ignored_dir, f"dummy{f}")
                assert not os.path.exists(file_path)
                open(file_path, "w").write(AZ_STRING)

            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            _stdout, _stderr = self._m_credsweeper(
                ["--path", tmp_dir, "--find-by-ext", "--save-json", json_filename, "--log", "silence"])
            assert os.path.exists(json_filename)
            with open(json_filename, "r") as json_file:
                report = json.load(json_file)
                assert len(report) == 4, f"{report}"
                for t in report:
                    assert t["line_data_list"][0]["line_num"] == -1
                    assert str(t["line_data_list"][0]["path"][-4:]) in [".pem", ".cer", ".csr", ".deR"]

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_find_by_ext_n(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            for f in [".pem", ".cer", ".csr", ".der", ".pfx", ".p12", ".key", ".jks"]:
                file_path = os.path.join(tmp_dir, f"dummy{f}")
                assert not os.path.exists(file_path)
                open(file_path, "w").write(AZ_STRING)
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            _stdout, _stderr = self._m_credsweeper(
                ["--path", tmp_dir, "--save-json", json_filename, "--log", "silence"])
            assert os.path.exists(json_filename)
            with open(json_filename, "r") as json_file:
                report = json.load(json_file)
                assert len(report) == 0

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_depth_p(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            # depth = 3
            _stdout, _stderr = self._m_credsweeper(
                ["--log", "silence", "--path",
                 str(SAMPLES_DIR), "--save-json", json_filename, "--depth", "3"])
            assert os.path.exists(json_filename)
            with open(json_filename, "r") as json_file:
                report = json.load(json_file)
                assert len(report) == SAMPLES_POST_CRED_COUNT + SAMPLES_IN_DEEP_3 - SAMPLES_FILTERED_BY_POST_COUNT

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_depth_n(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            # depth is not set
            _stdout, _stderr = self._m_credsweeper(
                ["--log", "silence", "--path",
                 str(SAMPLES_DIR), "--save-json", json_filename])
            assert os.path.exists(json_filename)
            with open(json_filename, "r") as json_file:
                report = json.load(json_file)
                assert len(report) == SAMPLES_POST_CRED_COUNT

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_denylist_value_p(self) -> None:
        target_path = str(SAMPLES_DIR / "password")
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            denylist_filename = os.path.join(tmp_dir, f"list.txt")
            with open(denylist_filename, "w") as f:
                f.write("cackle!")
            _stdout, _stderr = self._m_credsweeper([
                "--path", target_path, "--denylist", denylist_filename, "--save-json", json_filename, "--log", "silence"
            ])
            with open(json_filename, "r") as json_file:
                report = json.load(json_file)
                assert len(report) == 0

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_denylist_value_n(self) -> None:
        target_path = str(SAMPLES_DIR / "password")
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            denylist_filename = os.path.join(tmp_dir, f"list.txt")
            with open(denylist_filename, "w") as f:
                f.write("abc")
            _stdout, _stderr = self._m_credsweeper([
                "--path", target_path, "--denylist", denylist_filename, "--save-json", json_filename, "--log", "silence"
            ])
            with open(json_filename, "r") as json_file:
                report = json.load(json_file)
                assert len(report) == 1

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_denylist_line_p(self) -> None:
        target_path = str(SAMPLES_DIR / "password")
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            denylist_filename = os.path.join(tmp_dir, f"list.txt")
            with open(denylist_filename, "w") as f:
                f.write('  password = "cackle!" ')
            _stdout, _stderr = self._m_credsweeper([
                "--path", target_path, "--denylist", denylist_filename, "--save-json", json_filename, "--log", "silence"
            ])
            with open(json_filename, "r") as json_file:
                report = json.load(json_file)
                assert len(report) == 0

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_denylist_line_n(self) -> None:
        target_path = str(SAMPLES_DIR / "password")
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            denylist_filename = os.path.join(tmp_dir, f"list.txt")
            with open(denylist_filename, "w") as f:
                f.write("abc")
            _stdout, _stderr = self._m_credsweeper([
                "--path", target_path, "--denylist", denylist_filename, "--save-json", json_filename, "--log", "silence"
            ])
            with open(json_filename, "r") as json_file:
                report = json.load(json_file)
                assert len(report) == 1

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_rules_p(self) -> None:
        _stdout, _stderr = self._m_credsweeper(["--log", "silence", "--ml_threshold", "0", "--path", str(SAMPLES_DIR)])
        assert len(_stderr) == 0
        output = _stdout.decode(errors='replace')
        rules = Util.yaml_load(PROJECT_DIR / "credsweeper" / "rules" / "config.yaml")
        for rule in rules:
            rule_name = rule["name"]
            if rule_name in ["Nonce", "Salt", "Certificate"]:
                continue
            self.assertIn(f"rule: {rule_name}", output)
