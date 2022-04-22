import json
import os
import random
from argparse import ArgumentTypeError
from unittest import mock
from unittest.mock import Mock

import pytest

from credsweeper import __main__, ByteContentProvider, StringContentProvider
from credsweeper.app import CredSweeper
from credsweeper.common.constants import DEFAULT_ENCODING
from credsweeper.file_handler.text_content_provider import TextContentProvider


class TestMain:
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
        assert os.path.exists("unittest_output.json")
        os.remove("unittest_output.json")

    @mock.patch("json.dump")
    def test_save_json_n(self, mock_json_dump: mock) -> None:
        cred_sweeper = CredSweeper()
        cred_sweeper.run([])
        mock_json_dump.assert_not_called()

    @mock.patch("credsweeper.__main__.scan")
    @mock.patch("credsweeper.__main__.get_arguments")
    def test_main_n(self, mock_get_arguments: Mock(), mock_scan: Mock(return_value=None)) -> None:
        args_mock = Mock(log='silence', path=None, diff_path=None, json_filename=None, rule_path=None, jobs=1)
        mock_get_arguments.return_value = args_mock
        __main__.main()
        assert not mock_scan.called

    @mock.patch("credsweeper.__main__.scan")
    @mock.patch("credsweeper.__main__.get_arguments")
    def test_main_path_n(self, mock_get_arguments: Mock(), mock_scan: Mock(return_value=None)) -> None:
        dir_path = os.path.dirname(os.path.realpath(__file__))
        path = os.path.join(dir_path, "samples", "password.patch")
        args_mock = Mock(log='silence', path=path, diff_path=path, json_filename=None, rule_path=None, jobs=1)
        mock_get_arguments.return_value = args_mock
        __main__.main()
        assert mock_scan.called

    @mock.patch("argparse.ArgumentParser.parse_args")
    def test_parse_args_n(self, mock_parse: Mock()) -> None:
        assert __main__.get_arguments()
        assert mock_parse.called

    def test_positive_int_p(self):
        i: int = random.randint(1, 100)
        assert i == __main__.positive_int(i)

    def test_positive_int_n(self):
        i: int = random.randint(-100, 0)
        with pytest.raises(ArgumentTypeError):
            __main__.positive_int(i)

    def test_threshold_or_float_p(self):
        f: float = random.random()
        assert f == __main__.threshold_or_float(str(f))

    def test_threshold_or_float_n(self):
        with pytest.raises(ArgumentTypeError):
            __main__.threshold_or_float("DUMMY STRING")

    def test_scan_bytes_p(self) -> None:
        to_scan = b"line one\npassword='in_line_2'"
        cred_sweeper = CredSweeper()
        provider = ByteContentProvider(to_scan)
        results = cred_sweeper.file_scan(provider)
        assert len(results) == 1
        assert results[0].rule_name == "Password"
        assert results[0].line_data_list[0].variable == "password"
        assert results[0].line_data_list[0].value == "in_line_2"

    def test_scan_lines_p(self) -> None:
        to_scan = ["line one", "password='in_line_2'"]
        cred_sweeper = CredSweeper()
        provider = StringContentProvider(to_scan)
        results = cred_sweeper.file_scan(provider)
        assert len(results) == 1
        assert results[0].rule_name == "Password"
        assert results[0].line_data_list[0].variable == "password"
        assert results[0].line_data_list[0].value == "in_line_2"

    def test_find_by_ext_and_not_ignore_p(self) -> None:
        # checks only exactly match - may be wrong for windows
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(f"{dir_path}/../credsweeper/secret/config.json", "r", encoding=DEFAULT_ENCODING) as conf_file:
            config_dict = json.load(conf_file)
            extensions = config_dict["find_by_ext_list"]
            assert isinstance(extensions, list)
            assert len(extensions) > 0
            ignores = config_dict["exclude"]["extension"]
            assert isinstance(ignores, list)
            extension_conflict = set(extensions).intersection(ignores)
            assert len(extension_conflict) == 0, f"{extension_conflict}"
