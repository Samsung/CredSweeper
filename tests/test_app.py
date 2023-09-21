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

import deepdiff
import pytest

from credsweeper.app import APP_PATH
from credsweeper.utils import Util
from tests import AZ_STRING, SAMPLES_POST_CRED_COUNT, SAMPLES_IN_DEEP_3, SAMPLES_PATH, \
    TESTS_PATH, SAMPLES_CRED_COUNT, SAMPLES_IN_DOC


class TestApp(TestCase):

    @staticmethod
    def _m_credsweeper(args) -> Tuple[str, str]:
        proc = subprocess.Popen(
            [sys.executable, "-m", "credsweeper", *args],  #
            cwd=APP_PATH.parent,  #
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

    def test_it_works_p(self) -> None:
        target_path = str(SAMPLES_PATH / "password.gradle")
        _stdout, _stderr = self._m_credsweeper(["--path", target_path, "--log", "silence"])
        output = " ".join(_stdout.split()[:-1])

        expected = f"""
                    rule: Password
                    / severity: medium
                    / line_data_list:
                        [line: 'password = \"cackle!\"'
                        / line_num: 1
                        / path: {target_path}
                        / value: 'cackle!'
                        / entropy_validation: BASE64_CHARS 2.120590 False]
                    / api_validation: NOT_AVAILABLE
                    / ml_validation: VALIDATED_KEY\n
                    Detected Credentials: 1\n
                    Time Elapsed:
                    """
        expected = " ".join(expected.split())
        self.assertEqual(expected, output)

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

    def test_it_works_with_patch_p(self) -> None:
        target_path = str(SAMPLES_PATH / "password.patch")
        _stdout, _stderr = self._m_credsweeper(["--diff_path", target_path, "--log", "silence"])
        output = " ".join(_stdout.split()[:-1])

        expected = """
                    rule: Password
                    / severity: medium
                    / line_data_list:
                    [line: '  "password": "dkajco1"'
                        / line_num: 3
                        / path: .changes/1.16.98.json
                        / value: 'dkajco1'
                        / entropy_validation: BASE64_CHARS 2.807355 False]
                    / api_validation: NOT_AVAILABLE
                    / ml_validation: VALIDATED_KEY\n
                    Added File Credentials: 1\n
                    Deleted File Credentials: 0\n
                    Time Elapsed:
                    """
        expected = " ".join(expected.split())
        self.assertEqual(expected, output)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_it_works_with_multiline_in_patch_p(self) -> None:
        target_path = str(SAMPLES_PATH / "multiline.patch")
        _stdout, _stderr = self._m_credsweeper(["--diff_path", target_path, "--log", "silence"])
        output = " ".join(_stdout.split()[:-1])

        expected = """
                    rule: AWS Client ID
                        / severity: high
                        / line_data_list:
                            [line: ' clid = "AKIAQWADE5R42RDZ4JEM"'
                            / line_num: 4
                            / path: creds.py
                            / value: 'AKIAQWADE5R42RDZ4JEM'
                            / entropy_validation: BASE64_CHARS 3.684184 False]
                        / api_validation: NOT_AVAILABLE
                        / ml_validation: VALIDATED_KEY
                    rule: AWS Multi
                        / severity: high
                        / line_data_list:
                            [line: ' clid = "AKIAQWADE5R42RDZ4JEM"'
                            / line_num: 4
                            / path: creds.py
                            / value: 'AKIAQWADE5R42RDZ4JEM'
                            / entropy_validation: BASE64_CHARS 3.684184 False,
                            line: ' token = "V84C7sDU001tFFodKU95USNy97TkqXymnvsFmYhQ"'
                            / line_num: 5
                            / path: creds.py
                            / value: 'V84C7sDU001tFFodKU95USNy97TkqXymnvsFmYhQ'
                            / entropy_validation: BASE64_CHARS 4.784184 True]
                        / api_validation: NOT_AVAILABLE
                        / ml_validation: VALIDATED_KEY
                    rule: Token
                        / severity: medium
                        / line_data_list:
                            [line: ' token = "V84C7sDU001tFFodKU95USNy97TkqXymnvsFmYhQ"'
                            / line_num: 5
                            / path: creds.py
                            / value: 'V84C7sDU001tFFodKU95USNy97TkqXymnvsFmYhQ'
                            / entropy_validation: BASE64_CHARS 4.784184 True]
                        / api_validation: NOT_AVAILABLE
                        / ml_validation: VALIDATED_KEY\n
                    Added File Credentials: 3\n
                    Deleted File Credentials: 0\n
                    Time Elapsed:
                    """
        expected = " ".join(expected.split())
        self.assertEqual(expected, output)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @pytest.mark.skipif(0 != subprocess.call(["curl", "https://maps.googleapis.com/"]),
                        reason="network is not available")
    def test_it_works_with_api_p(self) -> None:
        target_path = str(SAMPLES_PATH / "google_api_key.toml")
        _stdout, _stderr = self._m_credsweeper(
            ["--path", target_path, "--ml_threshold", "0", "--api_validation", "--log", "silence"], )
        output = " ".join(_stdout.split()[:-1])

        expected = f"""
                    rule: Google API Key
                    / severity: high
                    / line_data_list:
                    [line: 'AIzaGiReoG-CrackleCrackle12315618_12315'
                        / line_num: 1
                        / path: {target_path}
                        / value: 'AIzaGiReoG-CrackleCrackle12315618_12315'
                        / entropy_validation: BASE36_CHARS 3.165196 True]
                    / api_validation: INVALID_KEY
                    / ml_validation: NOT_AVAILABLE\n
                    Detected Credentials: 1\n
                    Time Elapsed:
                    """
        expected = " ".join(expected.split())
        self.assertEqual(expected, output)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_it_works_n(self) -> None:
        _stdout, _stderr = self._m_credsweeper([])

        # Merge more than two whitespaces into one because _stdout and _stderr are changed based on the terminal size
        output = " ".join(_stderr.split())

        expected = "usage: python -m credsweeper [-h]" \
                   " (--path PATH [PATH ...]" \
                   " | --diff_path PATH [PATH ...]" \
                   " | --export_config [PATH]" \
                   " | --export_log_config [PATH]" \
                   ")" \
                   " [--rules [PATH]]" \
                   " [--severity SEVERITY]" \
                   " [--config [PATH]]" \
                   " [--log_config [PATH]]" \
                   " [--denylist PATH]" \
                   " [--find-by-ext]" \
                   " [--depth POSITIVE_INT]" \
                   " [--no-filters]" \
                   " [--doc]" \
                   " [--ml_threshold FLOAT_OR_STR]" \
                   " [--ml_batch_size POSITIVE_INT]" \
                   " [--azure | --cuda] " \
                   " [--api_validation]" \
                   " [--jobs POSITIVE_INT]" \
                   " [--skip_ignored]" \
                   " [--save-json [PATH]]" \
                   " [--save-xlsx [PATH]]" \
                   " [--sort]" \
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
        self.assertEqual(expected, output)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_log_p(self) -> None:
        apk_path = str(SAMPLES_PATH / "pem_key.apk")
        _stdout, _stderr = self._m_credsweeper(
            ["--log", "Debug", "--depth", "7", "--ml_threshold", "0", "--path", apk_path, "not_existed_path"])
        self.assertEqual(0, len(_stderr))

        self.assertIn("DEBUG", _stdout)
        self.assertIn("INFO", _stdout)
        self.assertIn("WARNING", _stdout)
        self.assertIn("ERROR", _stdout)
        self.assertNotIn("CRITICAL", _stdout)

        for line in _stdout.splitlines():
            if 5 <= len(line) and "rule:" == line[0:5]:
                self.assertRegex(line, r"rule: \.*")
            elif 21 <= len(line) and "Detected Credentials:" == line[0:21]:
                self.assertRegex(line, r"Detected Credentials: \d+")
            elif 13 <= len(line) and "Time Elapsed:" == line[0:13]:
                self.assertRegex(line, r"Time Elapsed: \d+\.\d+")
            else:
                self.assertRegex(
                    line,
                    r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d+ \| (DEBUG|INFO|WARNING|ERROR) \| \w+:\d+ \| .*",
                )

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_log_n(self) -> None:
        _stdout, _stderr = self._m_credsweeper(["--log", "CriTicaL", "--rule", "NOT_EXISTED_PATH", "--path", "."])
        self.assertEqual(0, len(_stderr))

        self.assertNotIn("DEBUG", _stdout)
        self.assertNotIn("INFO", _stdout)
        self.assertNotIn("WARNING", _stdout)
        self.assertNotIn("ERROR", _stdout)
        self.assertIn("CRITICAL", _stdout)

        self.assertTrue(
            any(
                re.match(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d+ \| (CRITICAL) \| \w+:\d+ \| .*", line)
                for line in _stdout.splitlines()), _stdout)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_help_p(self) -> None:
        _stdout, _stderr = self._m_credsweeper(["--help"])
        output = " ".join(_stdout.split())
        if 10 > sys.version_info.minor and output.find("options:"):
            # Legacy support python3.8 - 3.9 to display "optional arguments:" like in python 3.10
            output = output.replace("options:", "optional arguments:")
        help_path = os.path.join(TESTS_PATH, "..", "docs", "source", "guide.rst")
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
                    if 10 > sys.version_info.minor and line.strip() == "options:":
                        # Legacy support python3.8 - 3.9 to display "optional arguments:"
                        text = ' '.join([text, line.replace("options:", "optional arguments:")])
                    else:
                        text = ' '.join([text, line])
            expected = " ".join(text.split())
            self.maxDiff = 65536
            self.assertEqual(expected, output)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_version_p(self) -> None:
        _stdout, _stderr = self._m_credsweeper(["--version"])
        # Merge more than two whitespaces into one because _stdout and _stderr are changed based on the terminal size
        output = " ".join(_stdout.split())
        self.assertRegex(output, r"CredSweeper \d+\.\d+\.\d+")

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_banner_p(self) -> None:
        _stdout, _stderr = self._m_credsweeper(["--banner"])
        output = " ".join(_stdout.split())
        self.assertRegex(output, r"CredSweeper \d+\.\d+\.\d+ crc32:[0-9a-f]{8}", _stderr or _stdout)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_patch_save_json_p(self) -> None:
        target_path = str(SAMPLES_PATH / "password.patch")
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            _stdout, _stderr = self._m_credsweeper(
                ["--diff_path", target_path, "--save-json", json_filename, "--log", "silence"])
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, f"{__name__}_added.json")))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, f"{__name__}_deleted.json")))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_patch_save_json_n(self) -> None:
        start_time = time.time()
        target_path = str(SAMPLES_PATH / "password.patch")
        _stdout, _stderr = self._m_credsweeper(["--diff_path", target_path, "--log", "silence"])
        for root, dirs, files in os.walk(APP_PATH.parent):
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
            self.assertTrue(os.path.exists(json_filename))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_import_config_p(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            custom_config = os.path.join(tmp_dir, f"{__name__}.json")
            shutil.copyfile(APP_PATH / "secret" / "config.json", custom_config)
            args = ["--config", custom_config, "--path", str(APP_PATH), "--find-by-ext", "--log", "CRITICAL"]
            _stdout, _stderr = self._m_credsweeper(args)
            self.assertEqual("", _stderr)
            self.assertNotIn("CRITICAL", _stdout)
            self.assertIn("Time Elapsed:", _stdout)
            self.assertIn("Detected Credentials: 0", _stdout)
            self.assertEqual(2, len(_stdout.splitlines()))
            # add .py to find by extension
            modified_config = Util.json_load(custom_config)
            self.assertIn("find_by_ext_list", modified_config.keys())
            self.assertIsInstance(modified_config["find_by_ext_list"], list)
            modified_config["find_by_ext_list"].append(".py")
            Util.json_dump(modified_config, custom_config)
            _stdout, _stderr = self._m_credsweeper(args)
            self.assertEqual("", _stderr)
            self.assertNotIn("CRITICAL", _stdout)
            self.assertIn("Time Elapsed:", _stdout)
            self.assertNotIn("Detected Credentials: 0", _stdout)
            self.assertLess(5, len(_stdout.splitlines()))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_import_config_n(self) -> None:
        # not existed file
        _stdout, _stderr = self._m_credsweeper(
            ["--config", "not_existed_file", "--path",
             str(APP_PATH), "--log", "CRITICAL"])
        self.assertEqual(0, len(_stderr))
        self.assertIn("CRITICAL", _stdout)
        # wrong config
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            with open(json_filename, "w") as f:
                f.write('{}')
            _stdout, _stderr = self._m_credsweeper(
                ["--config", json_filename, "--path",
                 str(APP_PATH), "--log", "CRITICAL"])
            self.assertEqual(0, len(_stderr))
            self.assertIn("CRITICAL", _stdout)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_export_log_config_p(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_filename = os.path.join(tmp_dir, f"{__name__}.yaml")
            _stdout, _stderr = self._m_credsweeper(["--export_log_config", test_filename, "--log", "silence"])
            self.assertTrue(os.path.exists(test_filename))

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
                self.assertFalse(os.path.exists(file_path))
                open(file_path, "w").write(AZ_STRING)

            # not of all will be found due they are empty
            for f in [".jks", ".KeY"]:
                file_path = os.path.join(tmp_dir, f"dummy{f}")
                self.assertFalse(os.path.exists(file_path))
                open(file_path, "w").close()

            # the directory hides all files
            ignored_dir = os.path.join(tmp_dir, "target")
            os.mkdir(ignored_dir)
            for f in [".pfx", ".p12"]:
                file_path = os.path.join(ignored_dir, f"dummy{f}")
                self.assertFalse(os.path.exists(file_path))
                open(file_path, "w").write(AZ_STRING)

            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            _stdout, _stderr = self._m_credsweeper(
                ["--path", tmp_dir, "--find-by-ext", "--save-json", json_filename, "--log", "silence"])
            self.assertTrue(os.path.exists(json_filename))
            with open(json_filename, "r") as json_file:
                report = json.load(json_file)
                self.assertEqual(4, len(report), report)
                for t in report:
                    self.assertEqual(0, t["line_data_list"][0]["line_num"])
                    self.assertIn(str(t["line_data_list"][0]["path"][-4:]), [".pem", ".cer", ".csr", ".deR"])

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_find_by_ext_n(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            for f in [".pem", ".cer", ".csr", ".der", ".pfx", ".p12", ".key", ".jks"]:
                file_path = os.path.join(tmp_dir, f"dummy{f}")
                self.assertFalse(os.path.exists(file_path))
                open(file_path, "w").write(AZ_STRING)
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            _stdout, _stderr = self._m_credsweeper(
                ["--path", tmp_dir, "--save-json", json_filename, "--log", "silence"])
            self.assertTrue(os.path.exists(json_filename))
            with open(json_filename, "r") as json_file:
                report = json.load(json_file)
                self.assertEqual(0, len(report))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_depth_p(self) -> None:
        normal_report = []
        sorted_report = []
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            # depth = 3
            _stdout, _stderr = self._m_credsweeper(
                ["--log", "silence", "--path",
                 str(SAMPLES_PATH), "--save-json", json_filename, "--depth", "3"])
            self.assertTrue(os.path.exists(json_filename))
            with open(json_filename, "r") as json_file:
                normal_report.extend(json.load(json_file))
                self.assertEqual(SAMPLES_IN_DEEP_3, len(normal_report))
            sorted_json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            _stdout, _stderr = self._m_credsweeper([
                "--log", "silence", "--path",
                str(SAMPLES_PATH), "--sort", "--save-json", sorted_json_filename, "--depth", "3"
            ])
            self.assertTrue(os.path.exists(sorted_json_filename))
            with open(sorted_json_filename, "r") as json_file:
                sorted_report.extend(json.load(json_file))
                self.assertEqual(SAMPLES_IN_DEEP_3, len(sorted_report))
        self.assertTrue(deepdiff.DeepDiff(sorted_report, normal_report))
        # exclude equal items of dict instead custom __lt__ realization
        for n in range(len(normal_report) - 1, -1, -1):
            for i in sorted_report:
                if i == normal_report[n]:
                    del normal_report[n]
                    break
        # 0 - means all items were matched
        self.assertEqual(0, len(normal_report))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_depth_n(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            # depth is not set
            _stdout, _stderr = self._m_credsweeper(
                ["--log", "silence", "--path",
                 str(SAMPLES_PATH), "--save-json", json_filename])
            self.assertTrue(os.path.exists(json_filename))
            with open(json_filename, "r") as json_file:
                report = json.load(json_file)
                self.assertEqual(SAMPLES_POST_CRED_COUNT, len(report))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_denylist_value_p(self) -> None:
        target_path = str(SAMPLES_PATH / "password.gradle")
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            denylist_filename = os.path.join(tmp_dir, "list.txt")
            with open(denylist_filename, "w") as f:
                f.write("cackle!")
            _stdout, _stderr = self._m_credsweeper([
                "--path", target_path, "--denylist", denylist_filename, "--save-json", json_filename, "--log", "silence"
            ])
            with open(json_filename, "r") as json_file:
                report = json.load(json_file)
                self.assertEqual(0, len(report))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_denylist_value_n(self) -> None:
        target_path = str(SAMPLES_PATH / "password.gradle")
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            denylist_filename = os.path.join(tmp_dir, "list.txt")
            with open(denylist_filename, "w") as f:
                f.write("abc")
            _stdout, _stderr = self._m_credsweeper([
                "--path", target_path, "--denylist", denylist_filename, "--save-json", json_filename, "--log", "silence"
            ])
            with open(json_filename, "r") as json_file:
                report = json.load(json_file)
                self.assertEqual(1, len(report))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_denylist_line_p(self) -> None:
        target_path = str(SAMPLES_PATH / "password.gradle")
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            denylist_filename = os.path.join(tmp_dir, "list.txt")
            with open(denylist_filename, "w") as f:
                f.write('  password = "cackle!" ')
            _stdout, _stderr = self._m_credsweeper([
                "--path", target_path, "--denylist", denylist_filename, "--save-json", json_filename, "--log", "silence"
            ])
            with open(json_filename, "r") as json_file:
                report = json.load(json_file)
                self.assertEqual(0, len(report))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_denylist_line_n(self) -> None:
        target_path = str(SAMPLES_PATH / "password.gradle")
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            denylist_filename = os.path.join(tmp_dir, "list.txt")
            with open(denylist_filename, "w") as f:
                f.write("abc")
            _stdout, _stderr = self._m_credsweeper([
                "--path", target_path, "--denylist", denylist_filename, "--save-json", json_filename, "--log", "silence"
            ])
            with open(json_filename, "r") as json_file:
                report = json.load(json_file)
                self.assertEqual(1, len(report))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_rules_ml_p(self) -> None:
        # checks whether all rules have positive test samples with almost the same arguments during benchmark
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            _stdout, _stderr = self._m_credsweeper([
                "--path",
                str(SAMPLES_PATH),
                "--save-json",
                json_filename,
            ])
            self.assertEqual(0, len(_stderr))
            report = Util.json_load(json_filename)
            report_set = set([i["rule"] for i in report])
            rules = Util.yaml_load(APP_PATH / "rules" / "config.yaml")
            rules_set = set([i["name"] for i in rules])
            missed = {  #
            }
            self.assertSetEqual(rules_set.difference(missed), report_set, f"\n{_stdout}")
            self.assertEqual(SAMPLES_POST_CRED_COUNT, len(report))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_rules_ml_n(self) -> None:
        # checks whether all rules have test samples which detected without ML
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            _stdout, _stderr = self._m_credsweeper([
                "--path",
                str(SAMPLES_PATH),
                "--ml_threshold",
                "0",
                "--save-json",
                json_filename,
            ])
            self.assertEqual(0, len(_stderr))
            report = Util.json_load(json_filename)
            report_set = set([i["rule"] for i in report])
            rules = Util.yaml_load(APP_PATH / "rules" / "config.yaml")
            rules_set = set([i["name"] for i in rules])
            self.assertSetEqual(rules_set, report_set, f"\n{_stdout}")
            self.assertEqual(SAMPLES_CRED_COUNT, len(report))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_no_filters_p(self) -> None:
        # checks with disabled ML and filtering
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            _stdout, _stderr = self._m_credsweeper([
                "--path",
                str(SAMPLES_PATH),
                "--ml_threshold",
                "0",
                "--no-filters",
                "--save-json",
                json_filename,
            ])
            self.assertEqual(0, len(_stderr))
            report = Util.json_load(json_filename)
            # the number of reported items should increase
            self.assertLess(SAMPLES_CRED_COUNT, len(report))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_severity_p(self) -> None:
        _stdout, _stderr = self._m_credsweeper([  #
            "--log", "silence", "--ml_threshold", "0", "--severity", "medium", "--path",
            str(SAMPLES_PATH)
        ])
        self.assertIn("severity: medium", _stdout)
        self.assertNotIn("severity: info", _stdout)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_severity_n(self) -> None:
        _stdout, _stderr = self._m_credsweeper([  #
            "--log", "silence", "--ml_threshold", "0", "--severity", "critical", "--path",
            str(SAMPLES_PATH)
        ])
        self.assertNotIn("severity: medium", _stdout)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_doc_n(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            _stdout, _stderr = self._m_credsweeper(["--doc", "--path", str(SAMPLES_PATH), "--save-json", json_filename])
            report = Util.json_load(json_filename)
            self.assertEqual(SAMPLES_IN_DOC, len(report))
