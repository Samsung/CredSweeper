import json
import os
import re
import subprocess
import sys
import tempfile

import pytest


class TestApp:

    def test_it_works_p(self) -> None:
        dir_path = os.path.dirname(os.path.realpath(__file__))
        target_path = os.path.join(dir_path, "samples", "password")
        proc = subprocess.Popen([sys.executable, "-m", "credsweeper", "--path", target_path, "--log", "silence"],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        stdout, _stderr = proc.communicate()
        output = " ".join(stdout.decode("UTF-8").split())

        expected = f"""
                    rule: Password / severity: medium / line_data_list: [line: 'password = \"cackle!\"' / line_num: 1
                    / path: {target_path} / value: 'cackle!' / entropy_validation: False]
                    / api_validation: NOT_AVAILABLE / ml_validation: NOT_AVAILABLE\n
                    """
        expected = " ".join(expected.split())
        assert output == expected

    def test_it_works_with_ml_p(self) -> None:
        dir_path = os.path.dirname(os.path.realpath(__file__))
        target_path = os.path.join(dir_path, "samples", "password")
        proc = subprocess.Popen(
            [sys.executable, "-m", "credsweeper", "--path", target_path, "--ml_validation", "--log", "silence"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        stdout, _stderr = proc.communicate()
        output = " ".join(stdout.decode("UTF-8").split())

        expected = f"""
                    rule: Password / severity: medium / line_data_list: [line: 'password = \"cackle!\"' / line_num: 1
                    / path: {target_path} / value: 'cackle!' / entropy_validation: False]
                    / api_validation: NOT_AVAILABLE / ml_validation: VALIDATED_KEY\n
                    """
        expected = " ".join(expected.split())
        assert output == expected

    def test_it_works_with_patch_p(self) -> None:
        dir_path = os.path.dirname(os.path.realpath(__file__))
        target_path = os.path.join(dir_path, "samples", "password.patch")
        proc = subprocess.Popen([sys.executable, "-m", "credsweeper", "--diff_path", target_path, "--log", "silence"],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        stdout, _stderr = proc.communicate()
        output = " ".join(stdout.decode("UTF-8").split())

        expected = """
                    rule: Password / severity: medium / line_data_list: [line: '  "password": "dkajco1"' / line_num: 3
                    / path: .changes/1.16.98.json / value: 'dkajco1' / entropy_validation: False]
                    / api_validation: NOT_AVAILABLE / ml_validation: NOT_AVAILABLE\n
                    """
        expected = " ".join(expected.split())
        assert output == expected

    def test_it_works_with_multiline_in_patch_p(self) -> None:
        dir_path = os.path.dirname(os.path.realpath(__file__))
        target_path = os.path.join(dir_path, "samples", "multiline.patch")
        proc = subprocess.Popen([sys.executable, "-m", "credsweeper", "--diff_path", target_path, "--log", "silence"],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        stdout, _stderr = proc.communicate()
        output = " ".join(stdout.decode("UTF-8").split())

        expected = """
                    rule: AWS Client ID / severity: high / line_data_list: [line: ' clid = "AKIAQWADE5R42RDZ4JEM"'
                    / line_num: 4 / path: creds.py / value: 'AKIAQWADE5R42RDZ4JEM' / entropy_validation: False]
                    / api_validation: NOT_AVAILABLE / ml_validation: NOT_AVAILABLE rule: AWS Multi / severity: high
                    / line_data_list: [line: ' clid = "AKIAQWADE5R42RDZ4JEM"' / line_num: 4 / path: creds.py
                    / value: 'AKIAQWADE5R42RDZ4JEM'
                    / entropy_validation: False, line: ' token = "V84C7sDU001tFFodKU95USNy97TkqXymnvsFmYhQ"'
                    / line_num: 5 / path: creds.py / value: 'V84C7sDU001tFFodKU95USNy97TkqXymnvsFmYhQ'
                    / entropy_validation: True] / api_validation: NOT_AVAILABLE / ml_validation: NOT_AVAILABLE
                    rule: Token / severity: medium / line_data_list: [line: ' token = "V84C7sDU001tFFodKU95USNy97TkqXymnvsFmYhQ"'
                    / line_num: 5 / path: creds.py / value: 'V84C7sDU001tFFodKU95USNy97TkqXymnvsFmYhQ'
                    / entropy_validation: True] / api_validation: NOT_AVAILABLE / ml_validation: NOT_AVAILABLE\n
                    """
        expected = " ".join(expected.split())
        assert output == expected

    @pytest.mark.api_validation
    def test_it_works_with_api_p(self) -> None:
        dir_path = os.path.dirname(os.path.realpath(__file__))
        target_path = os.path.join(dir_path, "samples", "google_api_key")
        proc = subprocess.Popen(
            [sys.executable, "-m", "credsweeper", "--path", target_path, "--api_validation", "--log", "silence"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        stdout, _stderr = proc.communicate()
        output = " ".join(stdout.decode("UTF-8").split())

        expected = f"""
                    rule: Google API Key / severity: high / line_data_list: [line: 'AIzaGiReoGiCrackleCrackle12315618112315' / line_num: 1
                    / path: {target_path} / value: 'AIzaGiReoGiCrackleCrackle12315618112315' / entropy_validation: True]
                    / api_validation: INVALID_KEY / ml_validation: NOT_AVAILABLE\n
                    """
        expected = " ".join(expected.split())
        assert output == expected

    def test_it_works_n(self) -> None:
        proc = subprocess.Popen([sys.executable, "-m", "credsweeper"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        _stdout, stderr = proc.communicate()

        # Merge more than two whitespaces into one because stdout and stderr are changed based on the terminal size
        output = " ".join(stderr.decode("UTF-8").split())

        expected = """
                   usage: python -m credsweeper [-h] (--path PATH [PATH ...] | --diff_path PATH [PATH ...]) [--rules [PATH]] [--find-by-ext] [--ml_validation] [--ml_threshold FLOAT_OR_STR] [-b POSITIVE_INT]
                                                [--api_validation] [-j POSITIVE_INT] [--skip_ignored] [--save-json [PATH]] [-l LOG_LEVEL] [--version]
                   python -m credsweeper: error: one of the arguments --path --diff_path is required
                   """
        expected = " ".join(expected.split())
        assert output == expected

    def test_version_p(self) -> None:
        proc = subprocess.Popen([sys.executable, "-m", "credsweeper", "--version"],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        _stdout, stderr = proc.communicate()

        # Merge more than two whitespaces into one because stdout and stderr are changed based on the terminal size
        output = " ".join(_stdout.decode("UTF-8").split())

        assert re.match(r"CredSweeper \d+\.\d+\.\d+", output)

    def test_patch_save_json_p(self) -> None:
        dir_path = os.path.dirname(os.path.realpath(__file__))
        target_path = os.path.join(dir_path, "samples", "password.patch")
        json_filename = "unittest_output.json"
        proc = subprocess.Popen([
            sys.executable, "-m", "credsweeper", "--diff_path", target_path, "--save-json", json_filename, "--log",
            "silence"
        ],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        _stdout, _stderr = proc.communicate()

        assert os.path.exists("unittest_output_added.json") and os.path.exists("unittest_output_deleted.json")
        os.remove("unittest_output_added.json")
        os.remove("unittest_output_deleted.json")

    def test_find_tests_p(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, 'test_find_tests_p.json')
            tests_path = os.path.dirname(__file__)
            assert os.path.exists(tests_path)
            assert os.path.isdir(tests_path)
            proc = subprocess.Popen([
                sys.executable, "-m", "credsweeper", "--path", tests_path, "--save-json", json_filename, "--log",
                "silence"
            ],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            _stdout, _stderr = proc.communicate()
            assert os.path.exists(json_filename)
            with open(json_filename, "r") as json_file:
                report = json.load(json_file)
                assert len(report) > 111

    def test_patch_save_json_n(self) -> None:
        dir_path = os.path.dirname(os.path.realpath(__file__))
        target_path = os.path.join(dir_path, "samples", "password.patch")
        proc = subprocess.Popen([sys.executable, "-m", "credsweeper", "--diff_path", target_path, "--log", "silence"],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        _stdout, _stderr = proc.communicate()

        assert not os.path.exists("unittest_output_added.json") and not os.path.exists("unittest_output_deleted.json")

    def test_find_by_ext_p(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            # .deR will be not found, only 4 of them
            for f in [".pem", ".crt", ".cer", ".csr", ".deR"]:
                file_path = os.path.join(tmp_dir, f"dummy{f}")
                assert not os.path.exists(file_path)
                open(file_path, "w").write("The quick brown fox jumps over the lazy dog")

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
                open(file_path, "w").write("The quick brown fox jumps over the lazy dog")

            json_filename = os.path.join(tmp_dir, "dummy.json")
            proc = subprocess.Popen([
                sys.executable, "-m", "credsweeper", "--path", tmp_dir, "--find-by-ext", "--save-json", json_filename,
                "--log", "silence"
            ],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            _stdout, _stderr = proc.communicate()
            assert os.path.exists(json_filename)
            with open(json_filename, "r") as json_file:
                report = json.load(json_file)
                assert len(report) == 4, f"{report}"
                for t in report:
                    assert t["line_data_list"][0]["line_num"] == -1
                    assert str(t["line_data_list"][0]["path"][-4:]) in [".pem", ".crt", ".cer", ".csr"]

    def test_find_by_ext_n(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            for f in [".pem", ".crt", ".cer", ".csr", ".der", ".pfx", ".p12", ".key", ".jks"]:
                file_path = os.path.join(tmp_dir, f"dummy{f}")
                assert not os.path.exists(file_path)
                open(file_path, "w").write("The quick brown fox jumps over the lazy dog")
            json_filename = os.path.join(tmp_dir, "dummy.json")
            proc = subprocess.Popen([
                sys.executable, "-m", "credsweeper", "--path", tmp_dir, "--save-json", json_filename, "--log", "silence"
            ],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            _stdout, _stderr = proc.communicate()
            assert os.path.exists(json_filename)
            with open(json_filename, "r") as json_file:
                report = json.load(json_file)
                assert len(report) == 0
