import io
import os
import random
import shutil
import string
import tempfile
import unittest
import uuid
from argparse import ArgumentTypeError
from pathlib import Path
from typing import List, Any, Dict
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
from credsweeper.file_handler.abstract_provider import AbstractProvider
from credsweeper.file_handler.files_provider import FilesProvider
from credsweeper.file_handler.text_content_provider import TextContentProvider
from credsweeper.utils import Util
from tests import SAMPLES_CRED_COUNT, SAMPLES_CRED_LINE_COUNT, SAMPLES_POST_CRED_COUNT, SAMPLES_PATH, TESTS_PATH, \
    SAMPLES_IN_DEEP_1, SAMPLES_IN_DEEP_3, SAMPLES_IN_DEEP_2, NEGLIGIBLE_ML_THRESHOLD
from tests.data import DATA_TEST_CFG


class TestMain(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

    def tearDown(self):
        pass

    def test_ml_validation_p(self) -> None:
        cred_sweeper = CredSweeper()
        self.assertEqual(ThresholdPreset.medium, cred_sweeper.ml_threshold)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_ml_validation_n(self) -> None:
        cred_sweeper = CredSweeper(ml_threshold=0)
        self.assertEqual(0, cred_sweeper.ml_threshold)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_use_filters_p(self) -> None:
        cred_sweeper = CredSweeper(use_filters=True)
        files_provider = [TextContentProvider(SAMPLES_PATH / "password_FALSE")]
        cred_sweeper.scan(files_provider)
        creds = cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(0, len(creds))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_use_filters_n(self) -> None:
        cred_sweeper = CredSweeper(use_filters=False)
        files_provider = [TextContentProvider(SAMPLES_PATH / "password_FALSE")]
        cred_sweeper.scan(files_provider)
        creds = cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(2, len(creds))

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
                             json_filename=Path(os.path.join(tmp_dir, f"{__name__}.json")),
                             xlsx_filename=Path(os.path.join(tmp_dir, f"{__name__}.xlsx")),
                             color=False,
                             subtext=False,
                             hashed=False,
                             rule_path=None,
                             jobs=1,
                             ml_threshold=0.0,
                             ml_batch_size=1,
                             depth=0,
                             doc=False,
                             severity="info",
                             size_limit="1G",
                             denylist_path=None)
            mock_get_arguments.return_value = args_mock
            self.assertEqual(EXIT_SUCCESS, app_main.main())
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, f"{__name__}.xlsx")))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, f"{__name__}.deleted.json")))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, f"{__name__}.added.json")))
            report = Util.json_load(os.path.join(tmp_dir, f"{__name__}.added.json"))
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
                             subtext=False,
                             hashed=False,
                             sort_output=False,
                             rule_path=None,
                             jobs=1,
                             ml_threshold=0.0,
                             ml_batch_size=1,
                             depth=9,
                             doc=False,
                             severity="info",
                             size_limit="1G",
                             denylist_path=None)
            mock_get_arguments.return_value = args_mock
            self.assertEqual(EXIT_SUCCESS, app_main.main())
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, f"{__name__}.deleted.json")))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, f"{__name__}.added.json")))
            report = Util.json_load(os.path.join(tmp_dir, f"{__name__}.added.json"))
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
                             subtext=False,
                             hashed=False,
                             sort_output=True,
                             rule_path=None,
                             jobs=1,
                             ml_threshold=NEGLIGIBLE_ML_THRESHOLD,
                             ml_batch_size=16,
                             ml_config=None,
                             ml_model=None,
                             ml_providers=None,
                             depth=0,
                             doc=False,
                             size_limit="1G",
                             find_by_ext=False,
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
            for cred in report:
                for line_data in cred["line_data_list"]:
                    # check correctness start-end position
                    line = line_data["line"]
                    value = line_data["value"]
                    value_start = line_data["value_start"]
                    value_end = line_data["value_end"]
                    if 0 <= value_start and 0 <= value_end:
                        self.assertEqual(value, line[line_data["value_start"]:line_data["value_end"]], cred)
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

    def test_wrong_severity_n(self) -> None:
        with self.assertRaises(RuntimeError):
            CredSweeper(severity="wrong")

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

    def test_colored_line_p(self) -> None:
        cred_sweeper = CredSweeper()
        for to_scan in [
                "토큰MTAwMDoxVKvgS4Y7K7UIXHqBmV50aWFs5sb2heWGb3dy사용".encode(),
                b'\x1b[93mMTAwMDoxVKvgS4Y7K7UIXHqBmV50aWFs5sb2heWGb3dy\x1b[0m',
                b'\r\nMTAwMDoxVKvgS4Y7K7UIXHqBmV50aWFs5sb2heWGb3dy\r\n',
                b'\tMTAwMDoxVKvgS4Y7K7UIXHqBmV50aWFs5sb2heWGb3dy\n',
                b'%3DMTAwMDoxVKvgS4Y7K7UIXHqBmV50aWFs5sb2heWGb3dy%3B',
        ]:
            provider = ByteContentProvider(to_scan)
            results = cred_sweeper.file_scan(provider)
            self.assertEqual(1, len(results), to_scan)
            self.assertEqual("Jira / Confluence PAT token", results[0].rule_name)
            self.assertEqual("MTAwMDoxVKvgS4Y7K7UIXHqBmV50aWFs5sb2heWGb3dy", results[0].line_data_list[0].value)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_string_content_provider_n(self) -> None:
        random.seed(42)
        ascii_chars = string.digits + string.ascii_letters + string.punctuation + ' '
        text = ''.join(random.choice(ascii_chars) for _ in range(1 << 20))  # 1Mb dummy text
        cred_sweeper = CredSweeper()
        provider = StringContentProvider([text])
        results = cred_sweeper.file_scan(provider)
        self.assertAlmostEqual(73, len(results), delta=37)  # various lines may look like tokens

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
        content_provider: AbstractProvider = FilesProvider([SAMPLES_PATH])
        cred_sweeper = CredSweeper(pool_count=3)
        cred_sweeper.run(content_provider=content_provider)
        self.assertEqual(SAMPLES_POST_CRED_COUNT, len(cred_sweeper.credential_manager.get_credentials()))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_find_by_ext_p(self) -> None:
        # test for finding files by extension
        content_provider: AbstractProvider = FilesProvider([SAMPLES_PATH])
        cred_sweeper = CredSweeper(find_by_ext=True)
        cred_sweeper.run(content_provider=content_provider)
        self.assertEqual(SAMPLES_POST_CRED_COUNT + 3, len(cred_sweeper.credential_manager.get_credentials()))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_find_by_ext_n(self) -> None:
        # test for finding files by extension
        content_provider: AbstractProvider = FilesProvider([SAMPLES_PATH])
        cred_sweeper = CredSweeper(find_by_ext=False)
        cred_sweeper.run(content_provider=content_provider)
        self.assertEqual(SAMPLES_POST_CRED_COUNT, len(cred_sweeper.credential_manager.get_credentials()))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_tar_p(self) -> None:
        # deep scan in tar file. First level is bz2 archive to hide credentials with inflate
        content_provider: AbstractProvider = FilesProvider([SAMPLES_PATH / "passwords.tar.bz2"])
        cred_sweeper = CredSweeper(depth=2, ml_threshold=0)
        cred_sweeper.run(content_provider=content_provider)
        self.assertEqual(3, len(cred_sweeper.credential_manager.get_credentials()))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_tar_n(self) -> None:
        # test for bad tar - throws exception
        file_path = SAMPLES_PATH / "bad.tar.bz2"
        content_provider: AbstractProvider = FilesProvider([file_path])
        cred_sweeper = CredSweeper(depth=2)
        with patch('logging.Logger.error') as mocked_logger:
            cred_sweeper.run(content_provider=content_provider)
            self.assertEqual(0, len(cred_sweeper.credential_manager.get_credentials()))
            mocked_logger.assert_called_with(f"{file_path.as_posix()[:-4]}:unexpected end of data")

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_aws_multi_p(self) -> None:
        content_provider: AbstractProvider = FilesProvider([SAMPLES_PATH / "aws_multi.md"])
        cred_sweeper = CredSweeper(ml_threshold=0, color=True, hashed=True)
        cred_sweeper.run(content_provider=content_provider)
        for i in cred_sweeper.credential_manager.get_credentials():
            if "AWS Multi" == i.rule_name:
                self.assertEqual(7, i.line_data_list[0].line_num)
                self.assertEqual(8, i.line_data_list[1].line_num)
                break
        else:
            self.fail("AWS Multi was not found")

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_depth_p(self) -> None:
        # test for finding files with --depth
        content_provider: AbstractProvider = FilesProvider([SAMPLES_PATH])
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
        content_provider: AbstractProvider = FilesProvider([SAMPLES_PATH])
        cred_sweeper = CredSweeper(depth=0)
        cred_sweeper.run(content_provider=content_provider)
        self.assertEqual(SAMPLES_POST_CRED_COUNT, len(cred_sweeper.credential_manager.get_credentials()))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_bzip2_p(self) -> None:
        # test for finding files by extension
        content_provider: AbstractProvider = FilesProvider([SAMPLES_PATH / "pem_key.bz2"])
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
            content_provider: AbstractProvider = FilesProvider([test_filename])
            cred_sweeper = CredSweeper(depth=1)
            with patch('logging.Logger.error') as mocked_logger:
                cred_sweeper.run(content_provider=content_provider)
                mocked_logger.assert_called_with(
                    f"{test_filename}:Compressed data ended before the end-of-stream marker was reached")
            self.assertEqual(0, len(cred_sweeper.credential_manager.get_credentials()))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_eml_p(self) -> None:
        content_provider: AbstractProvider = FilesProvider([SAMPLES_PATH / "test.eml"])
        cred_sweeper = CredSweeper(doc=True)
        cred_sweeper.run(content_provider=content_provider)
        found_credentials = cred_sweeper.credential_manager.get_credentials()
        self.assertLessEqual(1, len(found_credentials), found_credentials)
        self.assertEqual("PW: H1ddEn#ema1l", found_credentials[0].line_data_list[0].line)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_pdf_p(self) -> None:
        # may be tested with
        # https://www.dcc.edu/documents/administration/offices/information-technology/password-examples.pdf
        content_provider: AbstractProvider = FilesProvider([SAMPLES_PATH / "sample.pdf"])
        cred_sweeper = CredSweeper(depth=7)
        cred_sweeper.run(content_provider=content_provider)
        found_credentials = cred_sweeper.credential_manager.get_credentials()
        self.assertSetEqual({"AWS Client ID", "Password", "Github Classic Token"},
                            set(i.rule_name for i in found_credentials))
        self.assertSetEqual({"Xdj@jcN834b", "AKIAGIREOGIAWSKEY123", "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"},
                            set(i.line_data_list[0].value for i in found_credentials))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_pdf_n(self) -> None:
        content_provider: AbstractProvider = FilesProvider([SAMPLES_PATH / "sample.pdf"])
        cred_sweeper = CredSweeper()
        cred_sweeper.run(content_provider=content_provider)
        self.assertEqual(0, len(cred_sweeper.credential_manager.get_credentials()))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_py_p(self) -> None:
        content_provider: AbstractProvider = FilesProvider([SAMPLES_PATH / "sample.py"])
        cred_sweeper = CredSweeper(depth=3, ml_threshold=ThresholdPreset.lowest)
        cred_sweeper.run(content_provider=content_provider)
        found_credentials = cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(1, len(found_credentials))
        self.assertSetEqual({"Password"}, set(i.rule_name for i in found_credentials))
        self.assertSetEqual({"WeR15tr0n6"}, set(i.line_data_list[0].value for i in found_credentials))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_py_n(self) -> None:
        content_provider: AbstractProvider = FilesProvider([SAMPLES_PATH / "sample.py"])
        cred_sweeper = CredSweeper()
        cred_sweeper.run(content_provider=content_provider)
        self.assertEqual(0, len(cred_sweeper.credential_manager.get_credentials()))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_json_p(self) -> None:
        # test for finding credentials in JSON
        content_provider: AbstractProvider = FilesProvider([SAMPLES_PATH / "struct.json"])
        cred_sweeper = CredSweeper(depth=5)
        cred_sweeper.run(content_provider=content_provider)
        found_credentials = cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(1, len(found_credentials))
        self.assertSetEqual({"Password"}, set(i.rule_name for i in found_credentials))
        self.assertSetEqual({"Axt4T0eO0lm9sS=="}, set(i.line_data_list[0].value for i in found_credentials))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_json_n(self) -> None:
        # test to prove that no credentials are found without depth
        content_provider: AbstractProvider = FilesProvider([SAMPLES_PATH / "struct.json"])
        cred_sweeper = CredSweeper()
        cred_sweeper.run(content_provider=content_provider)
        found_credentials = cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(0, len(found_credentials))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_yaml_p(self) -> None:
        # test for finding credentials in YAML
        content_provider: AbstractProvider = FilesProvider([SAMPLES_PATH / "binary.yaml"])
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
        content_provider: AbstractProvider = FilesProvider([SAMPLES_PATH / "binary.yaml"])
        cred_sweeper = CredSweeper()
        cred_sweeper.run(content_provider=content_provider)
        found_credentials = cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(0, len(found_credentials))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_encoded_p(self) -> None:
        # test for finding credentials in ENCODED data
        content_provider: AbstractProvider = FilesProvider([SAMPLES_PATH / "encoded_data"])
        cred_sweeper = CredSweeper(depth=5, ml_threshold=0, color=True, subtext=True)
        cred_sweeper.run(content_provider=content_provider)
        found_credentials = cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(2, len(found_credentials))
        self.assertSetEqual({"Token", "Github Old Token"}, set(i.rule_name for i in found_credentials))
        self.assertEqual("gireogicracklecrackle1231567190113413981", found_credentials[0].line_data_list[0].value)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_docx_p(self) -> None:
        # test for finding credentials in docx
        content_provider: AbstractProvider = FilesProvider([SAMPLES_PATH / "sample.docx"])
        cred_sweeper = CredSweeper(doc=True)
        cred_sweeper.run(content_provider=content_provider)
        found_credentials = cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(3, len(found_credentials))
        self.assertEqual("ghs_00000000000000000000000000000004WZ4EQ", found_credentials[0].line_data_list[0].value)
        self.assertEqual("WeR15tr0n6", found_credentials[1].line_data_list[0].value)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_docx_n(self) -> None:
        # test docx  - no credential should be found without 'doc'
        content_provider: AbstractProvider = FilesProvider([SAMPLES_PATH / "sample.docx"])
        cred_sweeper = CredSweeper(doc=False)
        cred_sweeper.run(content_provider=content_provider)
        found_credentials = cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(0, len(found_credentials))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_html_p(self) -> None:
        # test for finding credentials in html
        content_provider: AbstractProvider = FilesProvider([SAMPLES_PATH / "test.html"])
        cred_sweeper = CredSweeper(depth=5, ml_threshold=0)
        cred_sweeper.run(content_provider=content_provider)
        found_credentials = cred_sweeper.credential_manager.get_credentials()
        expected_credential_lines = [
            "508627689:AAEuLPKs-EhrjrYGnz60bnYNZqakf6HJxc0",
            "secret : Ndjbwu88s22ygavsdhgt5454v3h1x",
            "password : Cr3DeHTbIal",
            "password : 0dm1nk0",
            "password : p@$$w0Rd42",
            "secret : BNbNbws73bdhss329ssakKhds120384",
            "token : H72gsdv2dswPneHduwhfd",
            "td : Password:            MU$T6Ef09#D!",
            "# 94 ya29.dshMb48ehfXwydAj34D32J",
            "# 95 dop_v1_425522a565f532bc6532d453422e50334a42f5242a3090fbe553b543b124259b",
            "# 94 ya29.dshMb48ehfXwydAj34D32J",
            "# 95 dop_v1_425522a565f532bc6532d453422e50334a42f5242a3090fbe553b543b124259b",
            "the line will be found twice # 100"
            " EAACEb00Kse0BAlGy7KeQ5YnaCEd09Eose0cBAlGy7KeQ5Yna9CoDsup39tiYdoQ4jH9Coup39tiYdWoQ4jHFZD",
            "the line will be found twice # 100"
            " EAACEb00Kse0BAlGy7KeQ5YnaCEd09Eose0cBAlGy7KeQ5Yna9CoDsup39tiYdoQ4jH9Coup39tiYdWoQ4jHFZD",
        ]
        self.assertEqual(len(expected_credential_lines), len(found_credentials))
        for cred in found_credentials:
            self.assertEqual(1, len(cred.line_data_list))
            self.assertIn(cred.line_data_list[0].line, expected_credential_lines)
            expected_credential_lines.remove(cred.line_data_list[0].line)
        self.assertEqual(0, len(expected_credential_lines), expected_credential_lines)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_html_n(self) -> None:
        # test_html  - no credential should be found without 'depth'
        content_provider: AbstractProvider = FilesProvider([SAMPLES_PATH / "test.html"])
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

    def test_doc_p(self) -> None:
        content_provider: AbstractProvider = FilesProvider([SAMPLES_PATH / "test.html"])
        cred_sweeper = CredSweeper(doc=True)
        cred_sweeper.run(content_provider=content_provider)
        found_credentials = cred_sweeper.credential_manager.get_credentials()
        expected_credential_values = {
            "508627689:AAEuLPKs-EhrjrYGnz60bnYNZqakf6HJxc0",
            "ya29.dshMb48ehfXwydAj34D32J",
            "dop_v1_425522a565f532bc6532d453422e50334a42f5242a3090fbe553b543b124259b",
            "EAACEb00Kse0BAlGy7KeQ5YnaCEd09Eose0cBAlGy7KeQ5Yna9CoDsup39tiYdoQ4jH9Coup39tiYdWoQ4jHFZD",
            "MU$T6Ef09#D!",
        }
        self.assertSetEqual(expected_credential_values, set(x.line_data_list[0].value for x in found_credentials))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_doc_n(self) -> None:
        content_provider: AbstractProvider = FilesProvider([SAMPLES_PATH / "test.html"])
        cred_sweeper = CredSweeper(doc=False)
        cred_sweeper.run(content_provider=content_provider)
        found_credentials = cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(0, len(found_credentials))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_data_p(self) -> None:
        # the test modifies data/xxx.json with actual result - it discloses impact of changes obviously
        # use git diff to review the changes

        def prepare(report: List[Dict[str, Any]]):
            for x in report:
                # round ml_probability for macos
                ml_probability = x["ml_probability"]
                if isinstance(ml_probability, float):
                    x["ml_probability"] = round(ml_probability, 3)
                for y in x["line_data_list"]:
                    # update windows style path
                    y["path"] = str(y["path"]).replace('\\', '/')
                    y["info"] = str(y["info"]).replace('\\', '/')
                    # use relative path to project
                    y["path"] = str(y["path"]).replace(TESTS_PATH.as_posix(), './tests')
                    y["info"] = str(y["info"]).replace(TESTS_PATH.as_posix(), './tests')
                x["line_data_list"].sort(key=lambda k: (
                    k["path"],
                    k["line_num"],
                    k["value"],
                    k["info"],
                    k["line"],
                    k["value_start"],
                    k["value_end"],
                ))
            report.sort(key=lambda k: (
                k["line_data_list"][0]["path"],
                k["line_data_list"][0]["line_num"],
                k["line_data_list"][0]["value"],
                k["line_data_list"][0]["info"],
                k["line_data_list"][0]["value_start"],
                k["line_data_list"][0]["value_end"],
                k["severity"],
                k["rule"],
                k["ml_probability"],
            ))

        # instead the config file is used
        for cfg in DATA_TEST_CFG:
            with tempfile.TemporaryDirectory() as tmp_dir:
                expected_report = TESTS_PATH / "data" / cfg["json_filename"]
                expected_result = Util.json_load(expected_report)
                # informative parameter, relative with other tests counters. CredSweeper does not know it and fails
                cred_count = cfg.pop("__cred_count")
                prepare(expected_result)
                tmp_file = Path(tmp_dir) / cfg["json_filename"]
                # apply the current path to keep equivalence in path
                content_provider: AbstractProvider = FilesProvider([SAMPLES_PATH])
                # replace output report file to place in tmp_dir
                cfg["json_filename"] = str(tmp_file)
                cred_sweeper = CredSweeper(**cfg)
                cred_sweeper.run(content_provider=content_provider)
                test_result = Util.json_load(tmp_file)
                prepare(test_result)
                # use the same dump as in output
                Util.json_dump(test_result, tmp_file)

                diff = deepdiff.DeepDiff(test_result, expected_result)
                if diff:
                    # prints produced report to compare with present data in tests/data
                    print(f"Review updated {cfg['json_filename']} with git.", flush=True)
                    shutil.copy(tmp_file, expected_report)
                # first run fails with the diff but next run will pass
                self.assertDictEqual(diff, {}, cfg)
                # only count of items must be corrected manually
                self.assertEqual(cred_count, len(expected_result), cfg["json_filename"])

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_param_n(self) -> None:
        # internal parametrized tests for quick debug - no itms should be found
        items = [  #
            ('test.m', b's password=$$getTextValue^%dmzAPI("pass",sessid)'),
            ('test.yaml', b'password: Fd[q#pX+@4*r`1]Io'),
            ('enc.yaml', b'password: ENC[qGOpXrr1Iog1W+fjOiIDOT0C/dBjHyhy]'),
            ('enc.yaml', b'password: "ENC[qGOpXrr1Iog1W+fjOiIDOT0C/dBjHyhy]"'),
            ('enc.yml', b'password: ENC(qGOpXrr1Iog1W+fjOiIDOT0C/dBjHyhy)'),
            ('enc.yml', b'password: "ENC(qGOpXrr1Iog1W+fjOiIDOT0C/dBjHyhy)"'),
            ('x3.txt', b'passwd = values[token_id]'),
            ('t.py', b'new_params = {"dsn": new_params["dsn"], "password": new_params["password"]}'),
            ('t.m', b'@"otpauth://host/port?set=VNMXQKAZFVOYOJCDNBIYXYIWX2&algorithm=F4KE",'),
            ("test.c", b" *keylen = X448_KEYLEN;"),
            ("test.php", b"$yourls_user_passwords = $copy;"),
            ("", b"passwords = List<secret>"),
            ("test.template", b" API_KEY_ID=00209332 "),  #
            ("test.template", b" AUTH_API_KEY_NAME='temporally_secret_api' "),  #
            ("pager.ts", b"pagerLimitKey: 'size',"),  #
            ("pager.rs", b'    this_circleci_pass_secret_id="buratino-circle-pass"'),  #
            ("pager.rs", b'      secret_type: "odobo".to_string(),'),  #
            ("pager.rs", b"   secret_key: impl AsRef<str>,   "),  #
            ("pager.rs", b"token: impl AsRef<str>,"),  #
            ("pager.rs", b"    let tokens = quote::quote! {"),  #
            ("pager.rs", b"  let cert_chain = x509_rx"),  #
            ("my.kt", b'val password: String? = null'),  #
        ]
        content_provider: AbstractProvider = FilesProvider([(file_name, io.BytesIO(data_line))
                                                            for file_name, data_line in items])
        cred_sweeper = CredSweeper()
        cred_sweeper.run(content_provider=content_provider)
        creds = cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(0, len(creds), [x.to_json(False, False) for x in creds])

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_param_p(self) -> None:
        # internal parametrized tests for quick debug
        items = [  #
            ('test.yaml', b'password: "Fd[q#pX+@4*r`1]Io"', 'password', 'Fd[q#pX+@4*r`1]Io'),
            ("any", b'docker swarm join --token qii7t1m6423127xto389xc914l34451qz5135865564sg', 'token',
             'qii7t1m6423127xto389xc914l34451qz5135865564sg'),
            ("win.log", b'java -Password $(ConvertTo-SecureString "P@5$w0rD!" -AsPlainText -Force)',
             "ConvertTo-SecureString", "P@5$w0rD!"),
            ('tk.java',
             b' final OAuth2AccessToken accessToken = new OAuth2AccessToken("7c9yp7.y513e1t629w7e8f3n1z4m856a05o");',
             "OAuth2AccessToken accessToken", "7c9yp7.y513e1t629w7e8f3n1z4m856a05o"),
            ('my.toml', b'{nkey: XMIGDHSYNSJQ0XNR}', "nkey", "XMIGDHSYNSJQ0XNR"),
            ('my.yaml', b'password: "3287#JQ0XX@IG}"', "password", "3287#JQ0XX@IG}"),
            ("creds.py", b'"tokens": ["xabsjhdbasu7d9g", "ashbjhdifufhsds"]', "tokens", "xabsjhdbasu7d9g"),
            ("slt.py", b'\\t\\tsalt = "\\x187bhgerjhqw\\n iKa\\tW_R~0/8"', "salt", "\\x187bhgerjhqw\\n iKa\\tW_R~0/8"),
            ("log.txt",
             b'json\\nAuthorization: Basic jfhlksadjiu9813ryiuhdfskadjlkjh34\\n\\u003c/code\\u003e\\u003c/pre\\u003e"',
             "Authorization", "jfhlksadjiu9813ryiuhdfskadjlkjh34"),
            ("pwd.html", b'password =&gt; "ji3_8iKgaW_R~0/8"', "password", "ji3_8iKgaW_R~0/8"),
            ("pwd.py", b'password = "/_tcTz<D8sWXsW<E"', "password", "/_tcTz<D8sWXsW<E"),
            ("pwd.py", b'password = "I:FbCnXQc/9E02Il"', "password", "I:FbCnXQc/9E02Il"),
            ("url_part.py", b'39084?token=3487263-2384579834-234732875-345&key=DnBeiGdgy6253fytfdDHGg&hasToBeFound=2',
             'token', '3487263-2384579834-234732875-345'),
            ("prod.py", b"secret_api_key='Ahga%$FiQ@Ei8'", "secret_api_key", "Ahga%$FiQ@Ei8"),  #
            ("x.sh", b"connect 'odbc:proto://localhost:3289/connectrfs;user=admin1;password=bdsi73hsa;super=true",
             "password", "bdsi73hsa"),  #
            ("main.sh", b" otpauth://totp/alice%40google.com?secretik=JK2XPEH0BYXA3DPP&digits=8  ", "secretik",
             "JK2XPEH0BYXA3DPP"),  #
            ("test.template", b"    STP_PASSWORD=qbgomdtpqch \\", "STP_PASSWORD", "qbgomdtpqch"),  #
            ("test.template", b" Authorization: OAuth qii7t1m6423127xto389xc914l34451qz5135865564sg", "Authorization",
             "qii7t1m6423127xto389xc914l34451qz5135865564sg"),  #
            ("accept.py", b"password='Ahga%$FiQ@Ei8'", "password", "Ahga%$FiQ@Ei8"),  #
            ("test.template", b" NAMED_API_KEY=qii7t1m6423127xto389xc914l34451qz5135865564sg ", "NAMED_API_KEY",
             "qii7t1m6423127xto389xc914l34451qz5135865564sg"),  #
            ("my.kt", b'val password: String = "Ahga%$FiQ@Ei8"', "password", "Ahga%$FiQ@Ei8"),  #
        ]
        for file_name, data_line, variable, value in items:
            content_provider: AbstractProvider = FilesProvider([
                (file_name, io.BytesIO(data_line)),
            ])
            cred_sweeper = CredSweeper(ml_threshold=ThresholdPreset.lowest)
            cred_sweeper.run(content_provider=content_provider)
            creds = cred_sweeper.credential_manager.get_credentials()
            self.assertLessEqual(1, len(creds), data_line)
            self.assertEqual(variable, creds[0].line_data_list[0].variable)
            self.assertEqual(value, creds[0].line_data_list[0].value)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_random_p(self) -> None:
        # random generated value in well quoted value may be any (almost)
        safe_chars = [x for x in string.digits + string.ascii_letters + string.punctuation if x not in "\\'\"`"]
        value = ''.join(random.choice(safe_chars) for _ in range(16))
        line = f'password = "{value}"'
        content_provider: AbstractProvider = FilesProvider([("cred.go", io.BytesIO(line.encode()))])
        cred_sweeper = CredSweeper(ml_threshold=0)
        cred_sweeper.run(content_provider=content_provider)
        creds = cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(1, len(creds), line)
        self.assertEqual("password", creds[0].line_data_list[0].variable)
        self.assertEqual(value, creds[0].line_data_list[0].value)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_hashed_n(self) -> None:
        # checks whether hashed hides raw data from report
        test_value = str(uuid.uuid4())
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_filename = os.path.join(tmp_dir, f"{__name__}.yaml")
            with open(test_filename, 'w') as f:
                f.write(test_value)
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            cred_sweeper = CredSweeper(json_filename=json_filename, hashed=True)
            cred_sweeper.run(FilesProvider([test_filename]))
            report = Util.json_load(json_filename)
            # UUID is detected
            self.assertEqual(1, len(report))
            # but does not contain in report file
            self.assertNotIn(test_value, str(report))
