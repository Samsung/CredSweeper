import json
import os
import random
import tempfile
from argparse import ArgumentTypeError
from typing import List, Set
from unittest import mock
from unittest.mock import Mock, patch

import pandas as pd
import pytest

from credsweeper import ByteContentProvider, StringContentProvider
from credsweeper import __main__ as app_main
from credsweeper.app import CredSweeper
from credsweeper.common.constants import DEFAULT_ENCODING, ThresholdPreset
from credsweeper.credentials import Candidate
from credsweeper.file_handler.files_provider import FilesProvider
from credsweeper.file_handler.text_content_provider import TextContentProvider
from credsweeper.file_handler.text_provider import TextProvider
from credsweeper.utils import Util
from tests import SAMPLES_CRED_COUNT, SAMPLES_CRED_LINE_COUNT, SAMPLES_FILES_COUNT, SAMPLES_FILTERED_BY_POST_COUNT, \
    SAMPLES_POST_CRED_COUNT, SAMPLES_IN_DEEP_1, SAMPLES_IN_DEEP_2, SAMPLES_IN_DEEP_3, SAMPLES_DIR, CREDSWEEPER_DIR


class TestMain:

    def test_ml_validation_p(self) -> None:
        cred_sweeper = CredSweeper()
        assert cred_sweeper.ml_threshold == ThresholdPreset.medium

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_ml_validation_n(self) -> None:
        cred_sweeper = CredSweeper(ml_threshold=0)
        assert cred_sweeper.ml_threshold == 0

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_api_validation_p(self) -> None:
        cred_sweeper = CredSweeper(api_validation=True)
        assert cred_sweeper.config.api_validation

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_api_validation_n(self) -> None:
        cred_sweeper = CredSweeper(api_validation=False)
        assert not cred_sweeper.config.api_validation

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_api_validators_p(self) -> None:
        cred_sweeper = CredSweeper(api_validation=True)
        content_provider: FilesProvider = TextProvider([SAMPLES_DIR])
        file_extractors = content_provider.get_scannable_files(cred_sweeper.config)
        candidates: List[Candidate] = []
        for file in file_extractors:
            candidates += cred_sweeper.file_scan(file)
        known_validators: Set[str] = {  #
            "GithubTokenValidation",  #
            "GoogleApiKeyValidation",  #
            "GoogleMultiValidation",  #
            "MailChimpKeyValidation",  #
            "SlackTokenValidation",  #
            "SquareAccessTokenValidation",  #
            "SquareClientIdValidation",  #
            "StripeApiKeyValidation"
        }
        found_validators: Set[str] = set()
        for candidate in candidates:
            for validator in candidate.validations:
                found_validators.add(type(validator).__name__)
        assert found_validators == known_validators

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_use_filters_p(self) -> None:
        cred_sweeper = CredSweeper(use_filters=True)
        files = [SAMPLES_DIR / "password_short"]
        files_provider = [TextContentProvider(file_path) for file_path in files]
        cred_sweeper.scan(files_provider)
        assert len(cred_sweeper.credential_manager.get_credentials()) == 0

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_use_filters_n(self) -> None:
        cred_sweeper = CredSweeper(use_filters=False)
        files = [SAMPLES_DIR / "password_short"]
        files_provider = [TextContentProvider(file_path) for file_path in files]
        cred_sweeper.scan(files_provider)
        assert len(cred_sweeper.credential_manager.get_credentials()) == 1

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @mock.patch("json.dump")
    def test_save_json_p(self, mock_json_dump: Mock()) -> None:
        cred_sweeper = CredSweeper(json_filename="unittest_output.json")
        cred_sweeper.run([])
        mock_json_dump.assert_called()
        assert os.path.exists("unittest_output.json")
        os.remove("unittest_output.json")

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @mock.patch("json.dump")
    def test_save_json_n(self, mock_json_dump: Mock()) -> None:
        cred_sweeper = CredSweeper()
        cred_sweeper.run([])
        mock_json_dump.assert_not_called()

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @mock.patch("pandas.DataFrame", return_value=pd.DataFrame(data=[]))
    def test_save_xlsx_p(self, mock_xlsx_to_excel: Mock()) -> None:
        cred_sweeper = CredSweeper(xlsx_filename="unittest_output.xlsx")
        cred_sweeper.run([])
        mock_xlsx_to_excel.assert_called()
        assert os.path.exists("unittest_output.xlsx")
        os.remove("unittest_output.xlsx")

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @mock.patch("pandas.DataFrame", return_value=pd.DataFrame(data=[]))
    def test_save_xlsx_n(self, mock_xlsx_to_excel: Mock()) -> None:
        cred_sweeper = CredSweeper()
        cred_sweeper.run([])
        mock_xlsx_to_excel.assert_not_called()

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @mock.patch("credsweeper.__main__.scan")
    @mock.patch("credsweeper.__main__.get_arguments")
    def test_main_n(self, mock_get_arguments: Mock(), mock_scan: Mock(return_value=None)) -> None:
        args_mock = Mock(log='silence', path=None, diff_path=None, json_filename=None, rule_path=None, jobs=1)
        mock_get_arguments.return_value = args_mock
        app_main.main()
        assert not mock_scan.called

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @mock.patch("credsweeper.__main__.get_arguments")
    def test_main_path_n(self, mock_get_arguments: Mock()) -> None:
        path = SAMPLES_DIR / "password.patch"
        args_mock = Mock(log='silence', path=path, diff_path=path, json_filename=None, rule_path=None, jobs=1)
        mock_get_arguments.return_value = args_mock
        with patch.object(app_main, app_main.scan.__name__, return_value=0) as mock_scan:
            app_main.main()
            mock_scan.assert_called()

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @mock.patch("credsweeper.__main__.get_arguments")
    def test_binary_patch_n(self, mock_get_arguments: Mock()) -> None:
        # test verifies case when binary diff cannot be scanned
        target_path = SAMPLES_DIR / "multifile.patch"
        args_mock = Mock(log='warning',
                         path=None,
                         config_path=None,
                         diff_path=[str(target_path)],
                         json_filename=None,
                         xlsx_filename=None,
                         rule_path=None,
                         jobs=1,
                         ml_threshold=0.0,
                         depth=1,
                         size_limit="1G",
                         api_validation=False,
                         denylist_path=None)
        mock_get_arguments.return_value = args_mock
        with patch('logging.Logger.warning') as mocked_logger:
            app_main.main()
            # two times when analysis passed "added data" + two in "deleted data" case
            mocked_logger.assert_called()
            assert mocked_logger.call_count == 4

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @mock.patch("credsweeper.__main__.get_arguments")
    def test_report_p(self, mock_get_arguments: Mock()) -> None:
        # verifies reports creations
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, "report.json")
            xlsx_filename = os.path.join(tmp_dir, "report.xlsx")
            args_mock = Mock(log='warning',
                             config_path=None,
                             path=[str(SAMPLES_DIR)],
                             diff_path=None,
                             json_filename=json_filename,
                             xlsx_filename=xlsx_filename,
                             rule_path=None,
                             jobs=1,
                             ml_threshold=0.0,
                             depth=0,
                             size_limit="1G",
                             find_by_ext=False,
                             api_validation=False,
                             denylist_path=None)
            mock_get_arguments.return_value = args_mock
            app_main.main()
            assert os.path.exists(xlsx_filename)
            assert os.path.exists(json_filename)
            with open(json_filename, "r") as json_file:
                report = json.load(json_file)
                assert len(report) == SAMPLES_CRED_COUNT
            df = pd.read_excel(xlsx_filename)
            assert len(df) == SAMPLES_CRED_LINE_COUNT

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @mock.patch("argparse.ArgumentParser.parse_args")
    def test_parse_args_n(self, mock_parse: Mock()) -> None:
        assert app_main.get_arguments()
        assert mock_parse.called

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_positive_int_p(self):
        i: int = random.randint(1, 100)
        assert i == app_main.positive_int(i)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_positive_int_n(self):
        i: int = random.randint(-100, 0)
        with pytest.raises(ArgumentTypeError):
            app_main.positive_int(i)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_threshold_or_float_p(self):
        f: float = random.random()
        assert f == app_main.threshold_or_float(str(f))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_threshold_or_float_n(self):
        with pytest.raises(ArgumentTypeError):
            app_main.threshold_or_float("DUMMY STRING")

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_scan_bytes_p(self) -> None:
        to_scan = b"line one\npassword='in_line_2'"
        cred_sweeper = CredSweeper()
        provider = ByteContentProvider(to_scan)
        results = cred_sweeper.file_scan(provider)
        assert len(results) == 1
        assert results[0].rule_name == "Password"
        assert results[0].line_data_list[0].variable == "password"
        assert results[0].line_data_list[0].value == "in_line_2"

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_scan_lines_p(self) -> None:
        to_scan = ["line one", "password='in_line_2'"]
        cred_sweeper = CredSweeper()
        provider = StringContentProvider(to_scan)
        results = cred_sweeper.file_scan(provider)
        assert len(results) == 1
        assert results[0].rule_name == "Password"
        assert results[0].line_data_list[0].variable == "password"
        assert results[0].line_data_list[0].value == "in_line_2"

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_find_by_ext_and_not_ignore_p(self) -> None:
        # checks only exactly match - may be wrong for windows
        with open(str(CREDSWEEPER_DIR / "secret" / "config.json"), "r", encoding=DEFAULT_ENCODING) as conf_file:
            config_dict = json.load(conf_file)
            extensions = config_dict["find_by_ext_list"]
            assert isinstance(extensions, list)
            assert len(extensions) > 0
            ignores = config_dict["exclude"]["extension"]
            assert isinstance(ignores, list)
            extension_conflict = set(extensions).intersection(ignores)
            assert len(extension_conflict) == 0, f"{extension_conflict}"

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_multiple_invocation_p(self) -> None:
        # test whether ml_validator is created once
        files_counter = 0
        candidates_number = 0
        post_credentials_number = 0
        cred_sweeper = CredSweeper()
        validator_id = None
        for dir_path, _, filenames in os.walk(SAMPLES_DIR):
            filenames.sort()
            for filename in filenames:
                files_counter += 1
                to_scan = bytearray()
                for b_line in Util.read_file(os.path.join(dir_path, filename)):
                    to_scan += bytearray(f"{b_line}\n".encode('utf-8'))
                provider = ByteContentProvider(to_scan)
                candidates = cred_sweeper.file_scan(provider)
                candidates_number += len(candidates)
                cred_sweeper.credential_manager.set_credentials(candidates)
                cred_sweeper.post_processing()
                cred_sweeper_validator = cred_sweeper.ml_validator
                assert cred_sweeper_validator is not None
                if validator_id is None:
                    validator_id = id(cred_sweeper.ml_validator)
                assert id(cred_sweeper.ml_validator) == validator_id
                post_credentials = cred_sweeper.credential_manager.get_credentials()
                post_credentials_number += len(post_credentials)

        assert files_counter == SAMPLES_FILES_COUNT
        assert candidates_number == SAMPLES_CRED_COUNT - 2
        assert post_credentials_number == SAMPLES_POST_CRED_COUNT - 1

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_multi_jobs_p(self) -> None:
        # real result might be shown in code coverage
        content_provider: FilesProvider = TextProvider([SAMPLES_DIR])
        cred_sweeper = CredSweeper(pool_count=3)
        cred_sweeper.run(content_provider=content_provider)
        assert len(cred_sweeper.credential_manager.get_credentials()) == SAMPLES_POST_CRED_COUNT

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_find_by_ext_p(self) -> None:
        # test for finding files by extension
        content_provider: FilesProvider = TextProvider([SAMPLES_DIR])
        cred_sweeper = CredSweeper(find_by_ext=True)
        cred_sweeper.run(content_provider=content_provider)
        assert len(cred_sweeper.credential_manager.get_credentials()) == SAMPLES_POST_CRED_COUNT + 1

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_zip_p(self) -> None:
        # test for finding files by extension
        content_provider: FilesProvider = TextProvider([SAMPLES_DIR])
        # depth must be set in constructor to remove .zip as ignored extension
        cred_sweeper = CredSweeper(depth=1)
        cred_sweeper.run(content_provider=content_provider)
        assert len(cred_sweeper.credential_manager.get_credentials()
                   ) == SAMPLES_POST_CRED_COUNT + SAMPLES_IN_DEEP_1 - SAMPLES_FILTERED_BY_POST_COUNT
        cred_sweeper.config.depth = 3
        cred_sweeper.run(content_provider=content_provider)
        assert len(cred_sweeper.credential_manager.get_credentials()
                   ) == SAMPLES_POST_CRED_COUNT + SAMPLES_IN_DEEP_3 - SAMPLES_FILTERED_BY_POST_COUNT
        cred_sweeper.config.depth = 2
        cred_sweeper.run(content_provider=content_provider)
        assert len(cred_sweeper.credential_manager.get_credentials()
                   ) == SAMPLES_POST_CRED_COUNT + SAMPLES_IN_DEEP_2 - SAMPLES_FILTERED_BY_POST_COUNT
        # disable zip explore
        cred_sweeper.config.depth = 0
        cred_sweeper.run(content_provider=content_provider)
        assert len(cred_sweeper.credential_manager.get_credentials()) == SAMPLES_POST_CRED_COUNT

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_exclude_value_p(self) -> None:
        cred_sweeper = CredSweeper(use_filters=True, exclude_values=["cackle!"])
        files = [SAMPLES_DIR / "password"]
        files_provider = [TextContentProvider(file_path) for file_path in files]
        cred_sweeper.scan(files_provider)
        assert len(cred_sweeper.credential_manager.get_credentials()) == 0

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_exclude_value_n(self) -> None:
        cred_sweeper = CredSweeper(use_filters=True, exclude_values=["abc"])
        files = [SAMPLES_DIR / "password"]
        files_provider = [TextContentProvider(file_path) for file_path in files]
        cred_sweeper.scan(files_provider)
        assert len(cred_sweeper.credential_manager.get_credentials()) == 1

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @pytest.mark.parametrize("line", ['  password = "cackle!" ', 'password = "cackle!"'])
    def test_exclude_line_p(self, line: str) -> None:
        cred_sweeper = CredSweeper(use_filters=True, exclude_lines=[line])
        files = [SAMPLES_DIR / "password"]
        files_provider = [TextContentProvider(file_path) for file_path in files]
        cred_sweeper.scan(files_provider)
        assert len(cred_sweeper.credential_manager.get_credentials()) == 0

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_exclude_line_n(self) -> None:
        cred_sweeper = CredSweeper(use_filters=True, exclude_lines=["abc"])
        files = [SAMPLES_DIR / "password"]
        files_provider = [TextContentProvider(file_path) for file_path in files]
        cred_sweeper.scan(files_provider)
        assert len(cred_sweeper.credential_manager.get_credentials()) == 1
