import os
import subprocess
import sys
from unittest import mock

import pytest

from credsweeper.app import CredSweeper
from credsweeper.file_handler.text_content_provider import TextContentProvider


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
                   usage: python -m credsweeper [-h] (--path PATH [PATH ...] | --diff_path PATH [PATH ...]) [--rules [PATH]] [--ml_validation] [-b POSITIVE_INT] [--api_validation] [-j POSITIVE_INT] [--skip_ignored] [--save-json [PATH]] [-l LOG_LEVEL]
                   python -m credsweeper: error: one of the arguments --path --diff_path is required
                   """
        expected = " ".join(expected.split())
        assert output == expected

    def test_ml_validation_p(self) -> None:
        cred_sweeper = CredSweeper(ml_validation=True)
        assert cred_sweeper.config.ml_validation

    def test_ml_validation_n(self) -> None:
        cred_sweeper = CredSweeper(ml_validation=False)
        assert not cred_sweeper.config.ml_validation

    def test_api_validation_p(self) -> None:
        cred_sweeper = CredSweeper(api_validation=True)
        assert cred_sweeper.config.api_validation

    def test_api_validation_n(self) -> None:
        cred_sweeper = CredSweeper(api_validation=False)
        assert not cred_sweeper.config.api_validation

    def test_use_filters_p(self) -> None:
        cred_sweeper = CredSweeper(use_filters=True)
        dir_path = os.path.dirname(os.path.realpath(__file__))
        files = [os.path.join(dir_path, "samples", "password_short")]
        files_provider = [TextContentProvider(file_path) for file_path in files]
        cred_sweeper.scan(files_provider)
        assert len(cred_sweeper.credential_manager.get_credentials()) == 0

    def test_use_filters_n(self) -> None:
        cred_sweeper = CredSweeper(use_filters=False)
        dir_path = os.path.dirname(os.path.realpath(__file__))
        files = [os.path.join(dir_path, "samples", "password_short")]
        files_provider = [TextContentProvider(file_path) for file_path in files]
        cred_sweeper.scan(files_provider)
        assert len(cred_sweeper.credential_manager.get_credentials()) == 1

    @mock.patch("json.dump")
    def test_save_json_p(self, mock_json_dump: mock) -> None:
        cred_sweeper = CredSweeper(json_filename="unittest_output.json")
        cred_sweeper.run([])
        mock_json_dump.assert_called()
        os.remove("unittest_output.json")

    @mock.patch("json.dump")
    def test_save_json_n(self, mock_json_dump: mock) -> None:
        cred_sweeper = CredSweeper()
        cred_sweeper.run([])
        mock_json_dump.assert_not_called()
