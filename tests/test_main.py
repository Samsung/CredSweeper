import copy
import io
import json
import os
import random
import shutil
import tempfile
import unittest
from argparse import ArgumentTypeError
from pathlib import Path
from typing import List, Set, Any, Dict
from unittest import mock
from unittest.mock import Mock, patch

import deepdiff  # type: ignore
import pandas as pd
import pytest

from credsweeper import ByteContentProvider, StringContentProvider
from credsweeper import __main__ as app_main
from credsweeper.__main__ import EXIT_FAILURE, EXIT_SUCCESS
from credsweeper.app import APP_PATH
from credsweeper.app import CredSweeper
from credsweeper.common.constants import ThresholdPreset, Severity
from credsweeper.credentials import Candidate
from credsweeper.file_handler.files_provider import FilesProvider
from credsweeper.file_handler.text_content_provider import TextContentProvider
from credsweeper.file_handler.text_provider import TextProvider
from credsweeper.utils import Util
from tests import SAMPLES_CRED_COUNT, SAMPLES_CRED_LINE_COUNT, SAMPLES_POST_CRED_COUNT, SAMPLES_PATH, AZ_STRING, \
    TESTS_PATH, SAMPLES_IN_DEEP_1, SAMPLES_IN_DEEP_3, SAMPLES_IN_DEEP_2, \
    SAMPLES_FILES_COUNT
from tests.data import DATA_TEST_CFG


class TestMain(unittest.TestCase):

    def test_ml_validation_p(self) -> None:
        cred_sweeper = CredSweeper()
        self.assertEqual(ThresholdPreset.medium, cred_sweeper.ml_threshold)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_ml_validation_n(self) -> None:
        cred_sweeper = CredSweeper(ml_threshold=0)
        self.assertEqual(0, cred_sweeper.ml_threshold)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_api_validation_p(self) -> None:
        cred_sweeper = CredSweeper(api_validation=True)
        self.assertTrue(cred_sweeper.config.api_validation)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_api_validation_n(self) -> None:
        cred_sweeper = CredSweeper(api_validation=False)
        self.assertFalse(cred_sweeper.config.api_validation)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_api_validators_p(self) -> None:
        cred_sweeper = CredSweeper(api_validation=True)
        content_provider: FilesProvider = TextProvider([SAMPLES_PATH])
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
        self.assertEqual(known_validators, found_validators)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_use_filters_p(self) -> None:
        cred_sweeper = CredSweeper(use_filters=True)
        files_provider = [TextContentProvider(SAMPLES_PATH / "password_short")]
        cred_sweeper.scan(files_provider)
        creds = cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(0, len(creds))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_use_filters_n(self) -> None:
        cred_sweeper = CredSweeper(use_filters=False)
        files_provider = [TextContentProvider(SAMPLES_PATH / "password_short")]
        cred_sweeper.scan(files_provider)
        creds = cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(1, len(creds))
        self.assertEqual('password = "abc"', creds[0].line_data_list[0].line)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @mock.patch("json.dump")
    def test_save_json_p(self, mock_json_dump) -> None:
        cred_sweeper = CredSweeper(json_filename="unittest_output.json")
        cred_sweeper.run([])
        mock_json_dump.assert_called()
        self.assertTrue(os.path.exists("unittest_output.json"))
        os.remove("unittest_output.json")

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @mock.patch("json.dump")
    def test_save_json_n(self, mock_json_dump) -> None:
        cred_sweeper = CredSweeper()
        cred_sweeper.run([])
        mock_json_dump.assert_not_called()

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_save_xlsx_p(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_filename = os.path.join(tmp_dir, "unittest_output.xlsx")
            self.assertFalse(os.path.exists(test_filename))
            cred_sweeper = CredSweeper(xlsx_filename=test_filename)
            cred_sweeper.run([])
            self.assertTrue(os.path.exists(test_filename))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @mock.patch("pandas.DataFrame", return_value=pd.DataFrame(data=[]))
    def test_save_xlsx_n(self, mock_xlsx_to_excel) -> None:
        cred_sweeper = CredSweeper()
        cred_sweeper.run([])
        mock_xlsx_to_excel.assert_not_called()

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @mock.patch("credsweeper.__main__.scan", return_value=None)
    @mock.patch("credsweeper.__main__.get_arguments")
    def test_main_n(self, mock_get_arguments, mock_scan) -> None:
        args_mock = Mock(log='silence', path=None, diff_path=None, json_filename=None, rule_path=None, jobs=1)
        mock_get_arguments.return_value = args_mock
        self.assertEqual(EXIT_FAILURE, app_main.main())
        self.assertFalse(mock_scan.called)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @mock.patch("credsweeper.__main__.get_arguments")
    def test_main_path_p(self, mock_get_arguments) -> None:
        target_path = SAMPLES_PATH / "password.patch"
        with tempfile.TemporaryDirectory() as tmp_dir:
            args_mock = Mock(log='warning',
                             path=None,
                             config_path=None,
                             diff_path=[str(target_path)],
                             json_filename=os.path.join(tmp_dir, f"{__name__}.json"),
                             xlsx_filename=None,
                             rule_path=None,
                             jobs=1,
                             ml_threshold=0.0,
                             depth=0,
                             doc=False,
                             size_limit="1G",
                             api_validation=False,
                             denylist_path=None)
            mock_get_arguments.return_value = args_mock
            self.assertEqual(EXIT_SUCCESS, app_main.main())
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, f"{__name__}_deleted.json")))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, f"{__name__}_added.json")))
            report = Util.json_load(os.path.join(tmp_dir, f"{__name__}_added.json"))
            self.assertTrue(report)
            self.assertEqual(3, report[0]["line_data_list"][0]["line_num"])
            self.assertEqual("dkajco1", report[0]["line_data_list"][0]["value"])

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @mock.patch("credsweeper.__main__.get_arguments")
    def test_binary_patch_p(self, mock_get_arguments) -> None:
        # test verifies case when binary diff might be scanned
        target_path = SAMPLES_PATH / "multifile.patch"
        with tempfile.TemporaryDirectory() as tmp_dir:
            args_mock = Mock(log='warning',
                             path=None,
                             config_path=None,
                             diff_path=[str(target_path)],
                             json_filename=os.path.join(tmp_dir, f"{__name__}.json"),
                             xlsx_filename=None,
                             sort_output=False,
                             rule_path=None,
                             jobs=1,
                             ml_threshold=0.0,
                             depth=9,
                             doc=False,
                             size_limit="1G",
                             api_validation=False,
                             denylist_path=None)
            mock_get_arguments.return_value = args_mock
            self.assertEqual(EXIT_SUCCESS, app_main.main())
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, f"{__name__}_deleted.json")))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, f"{__name__}_added.json")))
            report = Util.json_load(os.path.join(tmp_dir, f"{__name__}_added.json"))
            self.assertTrue(report)
            self.assertEqual(5, len(report))
            # zip file inside binary diff
            self.assertEqual(1, report[0]["line_data_list"][0]["line_num"])
            self.assertEqual(
                'dt0c01.ST2EY72KQINMH574WMNVI7YN.G3DFPBEJYMODIDAEX454M7YWBUVEFOWKPRVMWFASS64NFH52PX6BNDVFFM572RZM',
                report[0]["line_data_list"][0]["value"])
            # binary format
            self.assertEqual(1, report[1]["line_data_list"][0]["line_num"])
            self.assertEqual("AIzaGiReoGiCrackleCrackle12315618112315", report[1]["line_data_list"][0]["value"])
            # text format
            self.assertEqual(4, report[2]["line_data_list"][0]["line_num"])
            self.assertEqual("AKIAQWADE5R42RDZ4JEM", report[2]["line_data_list"][0]["value"])
            self.assertEqual(4, report[3]["line_data_list"][0]["line_num"])
            self.assertEqual("AKIAQWADE5R42RDZ4JEM", report[3]["line_data_list"][0]["value"])
            self.assertEqual(5, report[3]["line_data_list"][1]["line_num"])
            self.assertEqual("V84C7sDU001tFFodKU95USNy97TkqXymnvsFmYhQ", report[3]["line_data_list"][1]["value"])
            self.assertEqual(5, report[4]["line_data_list"][0]["line_num"])
            self.assertEqual("V84C7sDU001tFFodKU95USNy97TkqXymnvsFmYhQ", report[4]["line_data_list"][0]["value"])

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @mock.patch("credsweeper.__main__.get_arguments")
    def test_report_p(self, mock_get_arguments) -> None:
        # verifies reports creations
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, "report.json")
            xlsx_filename = os.path.join(tmp_dir, "report.xlsx")
            args_mock = Mock(log='warning',
                             config_path=None,
                             path=[str(SAMPLES_PATH)],
                             diff_path=None,
                             json_filename=json_filename,
                             xlsx_filename=xlsx_filename,
                             sort_output=True,
                             rule_path=None,
                             jobs=1,
                             ml_threshold=0.0,
                             depth=0,
                             doc=False,
                             size_limit="1G",
                             find_by_ext=False,
                             api_validation=False,
                             denylist_path=None,
                             severity=Severity.INFO)
            mock_get_arguments.return_value = args_mock
            self.assertEqual(EXIT_SUCCESS, app_main.main())
            self.assertTrue(os.path.exists(xlsx_filename))
            self.assertTrue(os.path.exists(json_filename))
            report = Util.json_load(json_filename)
            self.assertTrue(report)
            self.assertEqual(SAMPLES_CRED_COUNT, len(report))
            self.assertIn(str(SAMPLES_PATH), report[0]["line_data_list"][0]["path"])
            self.assertTrue("info", report[0]["line_data_list"][0].keys())
            df = pd.read_excel(xlsx_filename)
            self.assertEqual(SAMPLES_CRED_LINE_COUNT, len(df))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @mock.patch("argparse.ArgumentParser.parse_args")
    def test_parse_args_n(self, mock_parse) -> None:
        self.assertTrue(app_main.get_arguments())
        self.assertTrue(mock_parse.called)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_positive_int_p(self):
        i = random.randint(1, 100)
        self.assertEqual(app_main.positive_int(i), i)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_positive_int_n(self):
        i = random.randint(-100, 0)
        with pytest.raises(ArgumentTypeError):
            app_main.positive_int(i)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_threshold_or_float_p(self):
        f = random.random()
        self.assertEqual(app_main.threshold_or_float(str(f)), f)

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
        self.assertEqual(1, len(results))
        self.assertEqual("Password", results[0].rule_name)
        self.assertEqual("password", results[0].line_data_list[0].variable)
        self.assertEqual("in_line_2", results[0].line_data_list[0].value)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_scan_bytes_n(self) -> None:
        to_scan = "line one\npassword='in_line_2'".encode('utf-32')  # unsupported
        cred_sweeper = CredSweeper()
        provider = ByteContentProvider(to_scan)
        results = cred_sweeper.file_scan(provider)
        self.assertEqual(0, len(results))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_scan_lines_p(self) -> None:
        to_scan = ["password='in_line_2'"]
        cred_sweeper = CredSweeper()
        provider = StringContentProvider(to_scan)
        results = cred_sweeper.file_scan(provider)
        self.assertEqual(1, len(results))
        self.assertEqual("Password", results[0].rule_name)
        self.assertEqual("password", results[0].line_data_list[0].variable)
        self.assertEqual("in_line_2", results[0].line_data_list[0].value)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_scan_lines_n(self) -> None:
        to_scan = [AZ_STRING]  # not matched string
        cred_sweeper = CredSweeper()
        provider = StringContentProvider(to_scan)
        results = cred_sweeper.file_scan(provider)
        self.assertEqual(0, len(results))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_find_by_ext_and_not_ignore_p(self) -> None:
        # checks only exact match (may be wrong for windows)
        config_dict = Util.json_load(APP_PATH / "secret" / "config.json")
        self.assertTrue(config_dict)
        find_by_ext_list_items = config_dict["find_by_ext_list"]
        self.assertTrue(isinstance(find_by_ext_list_items, list))
        find_by_ext_list_set = set(find_by_ext_list_items)
        self.assertTrue(len(find_by_ext_list_items) > 0)
        # check whether ignored extension does not exist in find_by_ext_list
        exclude_extension_items = config_dict["exclude"]["extension"]
        self.assertTrue(isinstance(exclude_extension_items, list))
        extension_conflict = find_by_ext_list_set.intersection(exclude_extension_items)
        self.assertSetEqual(set(), extension_conflict)
        # check whether ignored container does not exist in find_by_ext_list
        exclude_containers_items = config_dict["exclude"]["containers"]
        self.assertTrue(isinstance(exclude_containers_items, list))
        containers_conflict = find_by_ext_list_set.intersection(exclude_containers_items)
        self.assertSetEqual(set(), containers_conflict)
        # check whether extension and containers have no duplicates
        containers_extension_conflict = set(exclude_extension_items).intersection(exclude_containers_items)
        self.assertSetEqual(set(), containers_extension_conflict)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_multi_jobs_p(self) -> None:
        # real result might be shown in code coverage
        content_provider: FilesProvider = TextProvider([SAMPLES_PATH])
        cred_sweeper = CredSweeper(pool_count=3)
        cred_sweeper.run(content_provider=content_provider)
        self.assertEqual(SAMPLES_POST_CRED_COUNT, len(cred_sweeper.credential_manager.get_credentials()))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_find_by_ext_p(self) -> None:
        # test for finding files by extension
        content_provider: FilesProvider = TextProvider([SAMPLES_PATH])
        cred_sweeper = CredSweeper(find_by_ext=True)
        cred_sweeper.run(content_provider=content_provider)
        self.assertEqual(SAMPLES_POST_CRED_COUNT + 1, len(cred_sweeper.credential_manager.get_credentials()))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_find_by_ext_n(self) -> None:
        # test for finding files by extension
        content_provider: FilesProvider = TextProvider([SAMPLES_PATH])
        cred_sweeper = CredSweeper(find_by_ext=False)
        cred_sweeper.run(content_provider=content_provider)
        self.assertEqual(SAMPLES_POST_CRED_COUNT, len(cred_sweeper.credential_manager.get_credentials()))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_tar_p(self) -> None:
        # deep scan in tar file. First level is bz2 archive to hide credentials with inflate
        content_provider: FilesProvider = TextProvider([SAMPLES_PATH / "passwords.tar.bz2"])
        cred_sweeper = CredSweeper(depth=2)
        cred_sweeper.run(content_provider=content_provider)
        self.assertEqual(3, len(cred_sweeper.credential_manager.get_credentials()))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_tar_n(self) -> None:
        # test for bad tar - throws exception
        file_path = SAMPLES_PATH / "bad.tar.bz2"
        content_provider: FilesProvider = TextProvider([file_path])
        cred_sweeper = CredSweeper(depth=2)
        with patch('logging.Logger.error') as mocked_logger:
            cred_sweeper.run(content_provider=content_provider)
            self.assertEqual(0, len(cred_sweeper.credential_manager.get_credentials()))
            mocked_logger.assert_called_with(f"{file_path}:unexpected end of data")

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_depth_p(self) -> None:
        # test for finding files with --depth
        content_provider: FilesProvider = TextProvider([SAMPLES_PATH])
        cred_sweeper = CredSweeper(depth=1)
        cred_sweeper.run(content_provider=content_provider)
        self.assertEqual(SAMPLES_IN_DEEP_1, len(cred_sweeper.credential_manager.get_credentials()))
        cred_sweeper.config.depth = 2
        cred_sweeper.run(content_provider=content_provider)
        self.assertEqual(SAMPLES_IN_DEEP_2, len(cred_sweeper.credential_manager.get_credentials()))
        cred_sweeper.config.depth = 3
        cred_sweeper.run(content_provider=content_provider)
        self.assertEqual(SAMPLES_IN_DEEP_3, len(cred_sweeper.credential_manager.get_credentials()))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_depth_n(self) -> None:
        content_provider: FilesProvider = TextProvider([SAMPLES_PATH])
        cred_sweeper = CredSweeper(depth=0)
        cred_sweeper.run(content_provider=content_provider)
        self.assertEqual(SAMPLES_POST_CRED_COUNT, len(cred_sweeper.credential_manager.get_credentials()))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_bzip2_p(self) -> None:
        # test for finding files by extension
        content_provider: FilesProvider = TextProvider([SAMPLES_PATH / "pem_key.bz2"])
        cred_sweeper = CredSweeper(depth=1)
        cred_sweeper.run(content_provider=content_provider)
        self.assertEqual(1, len(cred_sweeper.credential_manager.get_credentials()))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_bzip2_n(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_filename = os.path.join(tmp_dir, __name__)
            self.assertFalse(os.path.exists(test_filename))
            with open(test_filename, "wb") as f:
                f.write(b"\x42\x5A\x68\x35\x31\x41\x59\x26\x53\x59")
            content_provider: FilesProvider = TextProvider([test_filename])
            cred_sweeper = CredSweeper(depth=1)
            with patch('logging.Logger.error') as mocked_logger:
                cred_sweeper.run(content_provider=content_provider)
                mocked_logger.assert_called_with(
                    f"{test_filename}:Compressed data ended before the end-of-stream marker was reached")
            self.assertEqual(0, len(cred_sweeper.credential_manager.get_credentials()))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_pdf_p(self) -> None:
        # may be tested with
        # https://www.dcc.edu/documents/administration/offices/information-technology/password-examples.pdf
        content_provider: FilesProvider = TextProvider([SAMPLES_PATH / "sample.pdf"])
        cred_sweeper = CredSweeper(depth=33)
        cred_sweeper.run(content_provider=content_provider)
        found_credentials = cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(2, len(found_credentials))
        self.assertSetEqual({"AWS Client ID", "Password"}, set(i.rule_name for i in found_credentials))
        self.assertSetEqual({"Xdj@jcN834b", "AKIAGIREOGIAWSKEY123"},
                            set(i.line_data_list[0].value for i in found_credentials))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_pdf_n(self) -> None:
        content_provider: FilesProvider = TextProvider([SAMPLES_PATH / "sample.pdf"])
        cred_sweeper = CredSweeper()
        cred_sweeper.run(content_provider=content_provider)
        self.assertEqual(0, len(cred_sweeper.credential_manager.get_credentials()))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_py_p(self) -> None:
        content_provider: FilesProvider = TextProvider([SAMPLES_PATH / "sample.py"])
        cred_sweeper = CredSweeper(depth=33)
        cred_sweeper.run(content_provider=content_provider)
        found_credentials = cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(1, len(found_credentials))
        self.assertSetEqual({"Password"}, set(i.rule_name for i in found_credentials))
        self.assertSetEqual({"WeR15tr0n6"}, set(i.line_data_list[0].value for i in found_credentials))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_py_n(self) -> None:
        content_provider: FilesProvider = TextProvider([SAMPLES_PATH / "sample.py"])
        cred_sweeper = CredSweeper()
        cred_sweeper.run(content_provider=content_provider)
        self.assertEqual(0, len(cred_sweeper.credential_manager.get_credentials()))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_json_p(self) -> None:
        # test for finding credentials in JSON
        content_provider: FilesProvider = TextProvider([SAMPLES_PATH / "struct.json"])
        cred_sweeper = CredSweeper(depth=5)
        cred_sweeper.run(content_provider=content_provider)
        found_credentials = cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(1, len(found_credentials))
        self.assertSetEqual({"Password"}, set(i.rule_name for i in found_credentials))
        self.assertSetEqual({"Axt4T0eO0lm9sS=="}, set(i.line_data_list[0].value for i in found_credentials))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_json_n(self) -> None:
        # test to prove that no credentials are found without depth
        content_provider: FilesProvider = TextProvider([SAMPLES_PATH / "struct.json"])
        cred_sweeper = CredSweeper()
        cred_sweeper.run(content_provider=content_provider)
        found_credentials = cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(0, len(found_credentials))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_yaml_p(self) -> None:
        # test for finding credentials in YAML
        content_provider: FilesProvider = TextProvider([SAMPLES_PATH / "binary.yaml"])
        cred_sweeper = CredSweeper(depth=5)
        cred_sweeper.run(content_provider=content_provider)
        found_credentials = cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(2, len(found_credentials))
        self.assertSetEqual({"Secret", "PEM Private Key"}, set(i.rule_name for i in found_credentials))
        self.assertSetEqual({"we5345d0f3da48544z1t1e275y05i161x995q485\n", "-----BEGIN RSA PRIVATE KEY-----"},
                            set(i.line_data_list[0].value for i in found_credentials))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_yaml_n(self) -> None:
        # test to prove that no credentials are found without depth
        content_provider: FilesProvider = TextProvider([SAMPLES_PATH / "binary.yaml"])
        cred_sweeper = CredSweeper()
        cred_sweeper.run(content_provider=content_provider)
        found_credentials = cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(0, len(found_credentials))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_encoded_p(self) -> None:
        # test for finding credentials in ENCODED data
        content_provider: FilesProvider = TextProvider([SAMPLES_PATH / "encoded_data"])
        cred_sweeper = CredSweeper(depth=5)
        cred_sweeper.run(content_provider=content_provider)
        found_credentials = cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(2, len(found_credentials))
        self.assertSetEqual({"Token", "Github Old Token"}, set(i.rule_name for i in found_credentials))
        self.assertEqual("gireogicracklecrackle1231567190113413981", found_credentials[0].line_data_list[0].value)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_docx_p(self) -> None:
        # test for finding credentials in docx
        content_provider: FilesProvider = TextProvider([SAMPLES_PATH / "password.docx"])
        cred_sweeper = CredSweeper(depth=5)
        cred_sweeper.run(content_provider=content_provider)
        found_credentials = cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(1, len(found_credentials))
        self.assertEqual("Xdj@jcN834b.", found_credentials[0].line_data_list[0].value)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_docx_n(self) -> None:
        # test docx  - no credential should be found without 'depth'
        content_provider: FilesProvider = TextProvider([SAMPLES_PATH / "password.docx"])
        cred_sweeper = CredSweeper()
        cred_sweeper.run(content_provider=content_provider)
        found_credentials = cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(0, len(found_credentials))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_html_p(self) -> None:
        # test for finding credentials in html
        content_provider: FilesProvider = TextProvider([SAMPLES_PATH / "test.html"])
        cred_sweeper = CredSweeper(depth=5)
        cred_sweeper.run(content_provider=content_provider)
        found_credentials = cred_sweeper.credential_manager.get_credentials()
        expected_credential_lines = [
            "508627689:AAEuLPKs-EhrjrYGnz60bnYNZqakf6HJxc0",
            "secret = Ndjbwu88s22ygavsdhgt5454v3h1x",
            "password = Cr3DeHTbIal",
            "password = 0dm1nk0",
            "password = p@$$w0Rd42",
            "secret = BNbNbws73bdhss329ssakKhds120384",
            "token = H72gsdv2dswPneHduwhfd",
            "td : Password:            MU$T6Ef09#D!",
            "# 94 ya29.dshMb48ehfXwydAj34D32J",
            "# 95 dop_v1_425522a565f532bc6532d453422e50334a42f5242a3090fbe553b543b124259b",
            "# 94 ya29.dshMb48ehfXwydAj34D32J",
            "# 95 dop_v1_425522a565f532bc6532d453422e50334a42f5242a3090fbe553b543b124259b",
            "the line will be found twice # 100 EAACEdEose0cBAlGy7KeQ5Yna9Coup39tiYdoQ4jHF",
            "the line will be found twice # 100 EAACEdEose0cBAlGy7KeQ5Yna9Coup39tiYdoQ4jHF",
        ]
        self.assertEqual(len(expected_credential_lines), len(found_credentials))
        for cred in found_credentials:
            self.assertEqual(1, len(cred.line_data_list))
            self.assertIn(cred.line_data_list[0].line, expected_credential_lines)
            expected_credential_lines.remove(cred.line_data_list[0].line)
        self.assertEqual(0, len(expected_credential_lines))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_html_n(self) -> None:
        # test_html  - no credential should be found without 'depth'
        content_provider: FilesProvider = TextProvider([SAMPLES_PATH / "test.html"])
        cred_sweeper = CredSweeper()
        cred_sweeper.run(content_provider=content_provider)
        found_credentials = cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(0, len(found_credentials))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    def test_exclude_value_p(self) -> None:
        cred_sweeper = CredSweeper(use_filters=True, exclude_values=["cackle!"])
        files = [SAMPLES_PATH / "password.gradle"]
        files_provider = [TextContentProvider(file_path) for file_path in files]
        cred_sweeper.scan(files_provider)
        self.assertEqual(0, len(cred_sweeper.credential_manager.get_credentials()))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_exclude_value_n(self) -> None:
        cred_sweeper = CredSweeper(use_filters=True, exclude_values=["abc"])
        files = [SAMPLES_PATH / "password.gradle"]
        files_provider = [TextContentProvider(file_path) for file_path in files]
        cred_sweeper.scan(files_provider)
        self.assertEqual(1, len(cred_sweeper.credential_manager.get_credentials()))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_exclude_line_p(self) -> None:
        cred_sweeper = CredSweeper(use_filters=True, exclude_lines=['password = "cackle!"'])
        files = [SAMPLES_PATH / "password.gradle"]
        files_provider = [TextContentProvider(file_path) for file_path in files]
        cred_sweeper.scan(files_provider)
        self.assertEqual(0, len(cred_sweeper.credential_manager.get_credentials()))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_exclude_line_n(self) -> None:
        cred_sweeper = CredSweeper(use_filters=True, exclude_lines=["abc"])
        files = [SAMPLES_PATH / "password.gradle"]
        files_provider = [TextContentProvider(file_path) for file_path in files]
        cred_sweeper.scan(files_provider)
        self.assertEqual(1, len(cred_sweeper.credential_manager.get_credentials()))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_credit_card_number_p(self) -> None:
        content_provider: FilesProvider = TextProvider([SAMPLES_PATH / "credit_card_numbers"])
        cred_sweeper = CredSweeper()
        cred_sweeper.run(content_provider=content_provider)
        found_credentials = cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(1, len(found_credentials))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_credit_card_number_n(self) -> None:
        with tempfile.NamedTemporaryFile("w") as tmp:
            tmp.write("0000000000000000\n9999999999999999\n")  # zero and wrong sequence
            tmp.flush()
            content_provider: FilesProvider = TextProvider([tmp.name])
            cred_sweeper = CredSweeper()
            cred_sweeper.run(content_provider=content_provider)
            self.assertEqual(0, len(cred_sweeper.credential_manager.get_credentials()))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_doc_p(self) -> None:
        content_provider: FilesProvider = TextProvider([SAMPLES_PATH / "test.html"])
        cred_sweeper = CredSweeper(doc=True)
        cred_sweeper.run(content_provider=content_provider)
        found_credentials = cred_sweeper.credential_manager.get_credentials()
        expected_credential_values = {
            "508627689:AAEuLPKs-EhrjrYGnz60bnYNZqakf6HJxc0",
            "ya29.dshMb48ehfXwydAj34D32J",
            "dop_v1_425522a565f532bc6532d453422e50334a42f5242a3090fbe553b543b124259b",
            "EAACEdEose0cBAlGy7KeQ5Yna9Coup39tiYdoQ4jHF",
            "MU$T6Ef09#D!",
        }
        self.assertSetEqual(expected_credential_values, set(x.line_data_list[0].value for x in found_credentials))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_doc_n(self) -> None:
        content_provider: FilesProvider = TextProvider([SAMPLES_PATH / "test.html"])
        cred_sweeper = CredSweeper(doc=False)
        cred_sweeper.run(content_provider=content_provider)
        found_credentials = cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(0, len(found_credentials))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_data_p(self) -> None:

        def prepare(report: List[Dict[str, Any]]):
            for x in report:
                # round ml_probability for macos
                if x["ml_probability"] is not None:
                    x["ml_probability"] = round(x["ml_probability"], 5)
                for y in x["line_data_list"]:
                    # update windows style path
                    y["path"] = str(y["path"]).replace('\\', '/')
                    y["info"] = str(y["info"]).replace('\\', '/')
                x["line_data_list"].sort(key=lambda k: (
                    k["path"],
                    k["line_num"],
                    k["value"],
                    k["info"],
                    k["line"],
                ))
            report.sort(key=lambda k: (
                k["line_data_list"][0]["path"],
                k["line_data_list"][0]["line_num"],
                k["line_data_list"][0]["value"],
                k["line_data_list"][0]["info"],
                k["line_data_list"][0]["line"],
                k["rule"],
                k["severity"],
                k["ml_probability"],
            ))

        # do not use parametrised tests with unittests
        self.maxDiff = 65536
        # instead the config file is used
        with tempfile.TemporaryDirectory() as tmp_dir:
            for cfg in DATA_TEST_CFG:
                with open(TESTS_PATH / "data" / cfg["json_filename"], "r") as f:
                    expected_result = json.load(f)
                # informative parameter, relative with other tests counters. CredSweeper does not know it and fails
                cred_count = cfg.pop("__cred_count")
                prepare(expected_result)
                tmp_file = Path(tmp_dir) / cfg["json_filename"]
                # apply the current path to keep equivalence in path
                os.chdir(TESTS_PATH.parent)
                content_provider: FilesProvider = TextProvider(["tests/samples"])
                # replace output report file to place in tmp_dir
                cfg["json_filename"] = str(tmp_file)
                cred_sweeper = CredSweeper(**cfg)
                cred_sweeper.run(content_provider=content_provider)
                with open(tmp_file, "r") as f:
                    test_result = json.load(f)
                prepare(test_result)

                diff = deepdiff.DeepDiff(test_result, expected_result)
                if diff:
                    # prints produced report to compare with present data in tests/data
                    print(f"\nThe produced report for {cfg['json_filename']}:\n{json.dumps(test_result)}", flush=True)
                self.assertDictEqual(diff, {}, cfg)
                self.assertEqual(cred_count, len(expected_result), cfg["json_filename"])

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    @pytest.mark.skipif(not os.getenv("BRUTEFORCEMAXEXTENSION4ML"),
                        reason="run the test only for renaming samples with maximal ml_probability")
    def test_samples_ml_p(self) -> None:
        extensions = [
            "", ".admx", ".adoc", ".api", ".asciidoc", ".backup", ".bash", ".bat", ".bats", ".bazel", ".build",
            ".bundle", ".bzl", ".c", ".cc", ".cf", ".cfg", ".clj", ".cljc", ".cls", ".cmd", ".cnf", ".coffee", ".conf",
            ".config", ".Config", ".cpp", ".creds", ".crlf", ".crt", ".cs", ".cshtml", ".csp", ".csproj", ".css",
            ".csv", ".dart", ".deprecated", ".development", ".diff", ".dist", ".doc", ".dockerfile", ".dot", ".dwl",
            ".eex", ".ejs", ".env", ".erb", ".erl", ".ex", ".example", ".exs", ".ext", ".fsproj", ".g4", ".gd", ".gml",
            ".gni", ".go", ".golden", ".gradle", ".graphql", ".graphqls", ".groovy", ".h", ".haml", ".hbs", ".hs",
            ".idl", ".iml", ".in", ".inc", ".ini", ".init", ".ipynb", ".j", ".j2", ".java", ".Jenkinsfile", ".jinja2",
            ".js", ".jsp", ".jsx", ".jwt", ".key", ".kt", ".l", ".las", ".lasso", ".lasso9", ".ldif", ".ldiff", ".ldml",
            ".leex", ".less", ".LESSER", ".libsonnet", ".list", ".lkml", ".lock", ".log", ".lua", ".m", ".manifest",
            ".map", ".markdown", ".markerb", ".marko", ".md", ".mdx", ".MF", ".mjml", ".mjs", ".mk", ".ml", ".mlir",
            ".mod", ".moo", ".mqh", ".msg", ".mst", ".mysql", ".nb", ".ndjson", ".nix", ".nolint", ".odd", ".oracle",
            ".p8", ".pan", ".patch", ".pbxproj", ".pem", ".php", ".pl", ".PL", ".plugin", ".pm", ".po", ".pod", ".pony",
            ".postinst", ".pp", ".ppk", ".private", ".proj", ".properties", ".proto", ".ps1", ".ps1xml", ".psm1",
            ".pug", ".purs", ".pxd", ".pyi", ".pyp", ".python", ".pyx", ".R", ".rake", ".rb", ".re", ".red", ".release",
            ".response", ".resx", ".rexx", ".rnh", ".rno", ".rrc", ".rs", ".rsc", ".rsp", ".rst", ".rules", ".sample",
            ".sbt", ".scala", ".scss", ".secrets", ".service", ".sh", ".slim", ".smali", ".snap", ".spec", ".spin",
            ".sql", ".sqlite3", ".srt", ".storyboard", ".strings", ".stub", ".sublime - keymap", ".sum", ".svg",
            ".swift", ".t", ".td", ".test", ".testsettings", ".tf", ".tfstate", ".tfvars", ".tl", ".tmpl", ".token",
            ".toml", ".tpl", ".travis", ".ts", ".tsx", ".ttar", ".txt", ".user", ".utf8", ".vsixmanifest", ".vsmdi",
            ".vue", ".xaml", ".xcscheme", ".xib", ".xsl", ".yara", ".yml", ".zsh", ".zsh - theme", ".1"
            # , ".template"
        ]
        cred_sweeper = CredSweeper()
        for __, _, filenames in os.walk(SAMPLES_PATH):
            self.assertEqual(SAMPLES_FILES_COUNT, len(filenames))
            for filename in filenames:
                file_path = SAMPLES_PATH / filename
                if file_path.suffix in [
                        ".patch", ".xml", ".bz2", ".docx", ".apk", ".zip", ".gz", ".pdf", ".py", ".json", ".html",
                        ".yaml", ".jks", ".template"
                ]:
                    continue
                data = file_path.read_bytes()
                stat: Dict[str, List[Candidate]] = {}
                for extension in extensions:
                    cred_sweeper.credential_manager.candidates.clear()
                    provider = TextContentProvider(file_path=(f"dummy{extension}", io.BytesIO(data)))
                    candidates = cred_sweeper.file_scan(provider)
                    cred_sweeper.credential_manager.set_credentials(candidates)
                    cred_sweeper.post_processing()
                    post_credentials = cred_sweeper.credential_manager.get_credentials()
                    if post_credentials:
                        stat[extension] = copy.deepcopy(post_credentials)
                max_ml = 0
                max_ext = ""
                for ext_key, creds in stat.items():
                    for cred in creds:
                        if cred.ml_probability and max_ml < cred.ml_probability:
                            max_ml = cred.ml_probability
                            max_ext = ext_key
                if max_ml:
                    print(max_ext, max_ml)
                    shutil.move(file_path, SAMPLES_PATH / f"{file_path.stem}{max_ext}")
                else:
                    shutil.move(file_path, SAMPLES_PATH / f"{file_path.stem}")
                del stat

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_param_p(self) -> None:
        # internal parametrized tests to keep
        items = [("    STP_PASSWORD=qbgomdtpqch \\", "qbgomdtpqch")]
        for i in items:
            content_provider: FilesProvider = TextProvider(["test.template", io.BytesIO(i[0].encode())])
            cred_sweeper = CredSweeper(ml_threshold=0)
            cred_sweeper.run(content_provider=content_provider)
            creds = cred_sweeper.credential_manager.get_credentials()
            self.assertLessEqual(1, len(creds))
            self.assertEqual(i[1], creds[0].line_data_list[0].value)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
