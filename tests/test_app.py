import json
import os
import re
import subprocess
import sys
import tempfile

import pytest

from tests import AZ_STRING, SAMPLES_POST_CRED_COUNT, SAMPLES_IN_DEEP_1, SAMPLES_IN_DEEP_3


class TestApp:

    def test_it_works_p(self) -> None:
        dir_path = os.path.dirname(os.path.realpath(__file__))
        target_path = os.path.join(dir_path, "samples", "password")
        proc = subprocess.Popen(
            [sys.executable, "-m", "credsweeper", "--path", target_path, "--log", "silence"],  #
            stdout=subprocess.PIPE,  #
            stderr=subprocess.PIPE)  #
        stdout, _stderr = proc.communicate()
        output = " ".join(stdout.decode("UTF-8").split()[:-1])

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

    def test_it_works_without_ml_p(self) -> None:
        dir_path = os.path.dirname(os.path.realpath(__file__))
        target_path = os.path.join(dir_path, "samples", "password")
        proc = subprocess.Popen(
            [sys.executable, "-m", "credsweeper", "--path", target_path, "--ml_threshold", "0", "--log", "silence"],  #
            stdout=subprocess.PIPE,  #
            stderr=subprocess.PIPE)  #
        stdout, _stderr = proc.communicate()
        output = " ".join(stdout.decode("UTF-8").split()[:-1])

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
        dir_path = os.path.dirname(os.path.realpath(__file__))
        target_path = os.path.join(dir_path, "samples", "password.patch")
        proc = subprocess.Popen(
            [sys.executable, "-m", "credsweeper", "--diff_path", target_path, "--log", "silence"],
            #
            stdout=subprocess.PIPE,  #
            stderr=subprocess.PIPE)  #
        stdout, _stderr = proc.communicate()
        output = " ".join(stdout.decode("UTF-8").split()[:-1])

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
        dir_path = os.path.dirname(os.path.realpath(__file__))
        target_path = os.path.join(dir_path, "samples", "multiline.patch")
        proc = subprocess.Popen(
            [sys.executable, "-m", "credsweeper", "--diff_path", target_path, "--log", "silence"],
            #
            stdout=subprocess.PIPE,  #
            stderr=subprocess.PIPE)  #
        stdout, _stderr = proc.communicate()
        output = " ".join(stdout.decode("UTF-8").split()[:-1])

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

    @pytest.mark.api_validation
    def test_it_works_with_api_p(self) -> None:
        dir_path = os.path.dirname(os.path.realpath(__file__))
        target_path = os.path.join(dir_path, "samples", "google_api_key")
        proc = subprocess.Popen(
            [
                sys.executable, "-m", "credsweeper", "--path", target_path, "--ml_threshold", "0", "--api_validation",
                "--log", "silence"
            ],  #
            stdout=subprocess.PIPE,  #
            stderr=subprocess.PIPE)  #
        stdout, _stderr = proc.communicate()
        output = " ".join(stdout.decode("UTF-8").split()[:-1])

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
        proc = subprocess.Popen([sys.executable, "-m", "credsweeper"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        _stdout, stderr = proc.communicate()

        # Merge more than two whitespaces into one because stdout and stderr are changed based on the terminal size
        output = " ".join(stderr.decode("UTF-8").split())

        expected = "usage: python -m credsweeper [-h]" \
                   " (--path PATH [PATH ...]" \
                   " | --diff_path PATH [PATH ...]" \
                   ")" \
                   " [--rules [PATH]]" \
                   " [--find-by-ext]" \
                   " [--depth POSITIVE_INT]" \
                   " [--ml_threshold FLOAT_OR_STR]" \
                   " [-b POSITIVE_INT]" \
                   " [--api_validation]" \
                   " [-j POSITIVE_INT]" \
                   " [--skip_ignored]" \
                   " [--save-json [PATH]]" \
                   " [--save-xlsx [PATH]]" \
                   " [-l LOG_LEVEL]" \
                   " [--size_limit SIZE_LIMIT]" \
                   " [--version] " \
                   "python -m credsweeper: error: one of the arguments" \
                   " --path" \
                   " --diff_path" \
                   " is required "
        expected = " ".join(expected.split())
        assert output == expected

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_help_p(self) -> None:
        proc = subprocess.Popen(
            [sys.executable, "-m", "credsweeper", "--help"],  #
            stdout=subprocess.PIPE,  #
            stderr=subprocess.PIPE)  #
        _stdout, _stderr = proc.communicate()
        output = " ".join(_stdout.decode("UTF-8").split())
        dir_path = os.path.dirname(os.path.realpath(__file__))
        help_path = os.path.join(dir_path, "..", "docs", "source", "guide.rst")
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
                    text += line
            expected = " ".join(text.split())
            assert output == expected

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_version_p(self) -> None:
        proc = subprocess.Popen(
            [sys.executable, "-m", "credsweeper", "--version"],  #
            stdout=subprocess.PIPE,  #
            stderr=subprocess.PIPE)  #
        _stdout, stderr = proc.communicate()

        # Merge more than two whitespaces into one because stdout and stderr are changed based on the terminal size
        output = " ".join(_stdout.decode("UTF-8").split())

        assert re.match(r"CredSweeper \d+\.\d+\.\d+", output)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_patch_save_json_p(self) -> None:
        dir_path = os.path.dirname(os.path.realpath(__file__))
        target_path = os.path.join(dir_path, "samples", "password.patch")
        json_filename = "unittest_output.json"
        proc = subprocess.Popen(
            [
                sys.executable, "-m", "credsweeper", "--diff_path", target_path, "--save-json", json_filename, "--log",
                "silence"
            ],  #
            stdout=subprocess.PIPE,  #
            stderr=subprocess.PIPE)  #
        _stdout, _stderr = proc.communicate()

        assert os.path.exists("unittest_output_added.json") and os.path.exists("unittest_output_deleted.json")
        os.remove("unittest_output_added.json")
        os.remove("unittest_output_deleted.json")

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_find_tests_p(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, 'test_find_tests_p.json')
            tests_path = os.path.join(os.path.dirname(__file__), "samples")
            assert os.path.exists(tests_path)
            assert os.path.isdir(tests_path)
            proc = subprocess.Popen(
                [
                    sys.executable, "-m", "credsweeper", "--path", tests_path, "--save-json", json_filename, "--log",
                    "silence", "--jobs", "3"
                ],  #
                stdout=subprocess.PIPE,  #
                stderr=subprocess.PIPE)  #
            _stdout, _stderr = proc.communicate()
            assert os.path.exists(json_filename)
            with open(json_filename, "r") as json_file:
                report = json.load(json_file)
                # Fixed credentials number are found in samples
                assert len(report) == SAMPLES_POST_CRED_COUNT

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_patch_save_json_n(self) -> None:
        dir_path = os.path.dirname(os.path.realpath(__file__))
        target_path = os.path.join(dir_path, "samples", "password.patch")
        proc = subprocess.Popen(
            [sys.executable, "-m", "credsweeper", "--diff_path", target_path, "--log", "silence"],  #
            stdout=subprocess.PIPE,  #
            stderr=subprocess.PIPE)  #
        _stdout, _stderr = proc.communicate()

        assert not os.path.exists("unittest_output_added.json") and not os.path.exists("unittest_output_deleted.json")

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_find_by_ext_p(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            # .deR will be not found, only 4 of them
            for f in [".pem", ".crt", ".cer", ".csr", ".deR"]:
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

            json_filename = os.path.join(tmp_dir, "dummy.json")
            proc = subprocess.Popen(
                [
                    sys.executable, "-m", "credsweeper", "--path", tmp_dir, "--find-by-ext", "--save-json",
                    json_filename, "--log", "silence"
                ],  #
                stdout=subprocess.PIPE,  #
                stderr=subprocess.PIPE)  #
            _stdout, _stderr = proc.communicate()
            assert os.path.exists(json_filename)
            with open(json_filename, "r") as json_file:
                report = json.load(json_file)
                assert len(report) == 4, f"{report}"
                for t in report:
                    assert t["line_data_list"][0]["line_num"] == -1
                    assert str(t["line_data_list"][0]["path"][-4:]) in [".pem", ".crt", ".cer", ".csr"]

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_find_by_ext_n(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            for f in [".pem", ".crt", ".cer", ".csr", ".der", ".pfx", ".p12", ".key", ".jks"]:
                file_path = os.path.join(tmp_dir, f"dummy{f}")
                assert not os.path.exists(file_path)
                open(file_path, "w").write(AZ_STRING)
            json_filename = os.path.join(tmp_dir, "dummy.json")
            proc = subprocess.Popen(
                [
                    sys.executable, "-m", "credsweeper", "--path", tmp_dir, "--save-json", json_filename, "--log",
                    "silence"
                ],  #
                stdout=subprocess.PIPE,  #
                stderr=subprocess.PIPE)  #
            _stdout, _stderr = proc.communicate()
            assert os.path.exists(json_filename)
            with open(json_filename, "r") as json_file:
                report = json.load(json_file)
                assert len(report) == 0

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_zip_p(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            samples_dir_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "samples")
            json_filename = os.path.join(tmp_dir, "dummy.json")
            # depth = 3
            proc = subprocess.Popen(
                [
                    sys.executable, "-m", "credsweeper", "--log", "silence", "--path", samples_dir_path, "--save-json",
                    json_filename, "--depth", "3"
                ],  #
                stdout=subprocess.PIPE,  #
                stderr=subprocess.PIPE)  #
            _stdout, _stderr = proc.communicate()
            assert os.path.exists(json_filename)
            with open(json_filename, "r") as json_file:
                report = json.load(json_file)
                assert len(report) == SAMPLES_POST_CRED_COUNT + SAMPLES_IN_DEEP_3
            # depth = 1
            proc = subprocess.Popen(
                [
                    sys.executable, "-m", "credsweeper", "--log", "silence", "--path", samples_dir_path, "--save-json",
                    json_filename, "--depth", "1"
                ],  #
                stdout=subprocess.PIPE,  #
                stderr=subprocess.PIPE)  #
            _stdout, _stderr = proc.communicate()
            assert os.path.exists(json_filename)
            with open(json_filename, "r") as json_file:
                report = json.load(json_file)
                assert len(report) == SAMPLES_POST_CRED_COUNT + SAMPLES_IN_DEEP_1

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
