import json
import os
import tempfile
import unittest
import zipfile
from typing import List
from unittest.mock import patch

from credsweeper.app import CredSweeper
from credsweeper.credentials.candidate import Candidate
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.files_provider import FilesProvider
from tests import SAMPLES_FILES_COUNT, SAMPLES_PATH, AZ_DATA, SAMPLE_ZIP
from tests.file_handler.zip_bomb_1 import zb1
from tests.file_handler.zip_bomb_2 import zb2


class DataContentProviderTest(unittest.TestCase):
    WRONG_ZIP_FILE = b"PK\003\004_WRONG_ZIP_FILE"

    def test_represent_as_encoded_p(self) -> None:
        # surrogate parametrized test
        for param in [
            b"QUtJQTBPTjdWMkRSNTdQTDNKWE0=\n",  #
            b"\t12345\r\n\t67890  ==\n",  # with garbage
            b"1234567890==",  #
            b"MY/PASSWORD=",  #
            b"MY PASSWORD IS",  # -> 31 83 c0 49 25 8e 44 32 12
        ]:  # yapf: disable
            content_provider = DataContentProvider(data=param)
            self.assertTrue(content_provider.represent_as_encoded(), param)
            self.assertTrue(content_provider.decoded)

    def test_wrong_base64_n(self) -> None:
        for param in [
            b"NDIK",  # -> "42" encoded
            b"MY/PASS=WORD",  #
        ]:  # yapf: disable
            content_provider = DataContentProvider(data=param)
            self.assertFalse(content_provider.represent_as_encoded(), param)
            self.assertFalse(content_provider.decoded)

    def test_wrong_xml_n(self) -> None:
        content_provider1 = DataContentProvider(data=b"")
        with patch('logging.Logger.debug') as mocked_logger:
            self.assertFalse(content_provider1.represent_as_xml())
            mocked_logger.assert_not_called()
        content_provider2 = DataContentProvider(data=AZ_DATA)
        with patch('logging.Logger.debug') as mocked_logger:
            self.assertFalse(content_provider2.represent_as_xml())
            mocked_logger.assert_called_with("Weak data to parse as XML")
        content_provider3 = DataContentProvider(data=b"</wrong XML text>")
        with patch('logging.Logger.debug') as mocked_logger:
            self.assertFalse(content_provider3.represent_as_xml())
            mocked_logger.assert_called()

    def test_scan_wrong_provider_n(self) -> None:
        content_provider = DataContentProvider(b"dummy", "dummy")
        cs = CredSweeper(json_filename="dummy")
        with self.assertRaises(NotImplementedError):
            cs.file_scan(content_provider)

    def test_scan_bottom_reach_n(self) -> None:
        content_provider = DataContentProvider(self.WRONG_ZIP_FILE, "dummy")
        cs = CredSweeper(json_filename="dummy")
        self.assertEqual(0, len(cs.deep_scanner.recursive_scan(content_provider, 0, 1 << 16)))

    def test_scan_wrong_zip_data_n(self) -> None:
        content_provider = DataContentProvider(self.WRONG_ZIP_FILE, "dummy")
        cs = CredSweeper(json_filename="dummy")
        self.assertEqual(0, len(cs.deep_scanner.recursive_scan(content_provider, 1, 1 << 16)))

    def test_scan_empty_zip_n(self) -> None:
        content_provider = DataContentProvider(
            b'PK\x05\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', "dummy")
        cs = CredSweeper(json_filename="dummy")
        self.assertEqual(0, len(cs.deep_scanner.recursive_scan(content_provider, 1, 1 << 16)))

    def test_scan_zipfile_n(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            report_path = os.path.join(tmp_dir, "report.json")
            file_path = os.path.join(tmp_dir, "test_n.zip")
            self.assertFalse(os.path.exists(file_path))
            open(file_path, "wb").write(self.WRONG_ZIP_FILE)

            content_provider = FilesProvider([tmp_dir])
            cs = CredSweeper(json_filename=report_path, depth=1)

            file_extractors = content_provider.get_scannable_files(cs.config)
            self.assertEqual(1, len(file_extractors))
            scan_results = cs.file_scan(file_extractors[0])
            self.assertEqual(0, len(scan_results))
            self.assertFalse(os.path.isfile(report_path))

    def test_scan_zipfile_p(self) -> None:
        # create new zip archive with all samples
        with tempfile.TemporaryDirectory() as tmp_dir:
            report_path_1 = os.path.join(tmp_dir, "report_1.json")
            report_path_2 = os.path.join(tmp_dir, "report_2.json")

            cs = CredSweeper(json_filename=report_path_1, find_by_ext=True, depth=7)

            # calculate samples
            content_provider = FilesProvider([SAMPLES_PATH])
            file_extractors = content_provider.get_scannable_files(cs.config)
            self.assertLess(1, len(file_extractors))
            samples_scan_results: List[Candidate] = []
            for file_extractor in file_extractors:
                samples_scan_results.extend(cs.file_scan(file_extractor))
            len_samples_scan_results = len(samples_scan_results)
            self.assertLess(1, len_samples_scan_results)
            cs.credential_manager.set_credentials(samples_scan_results)
            cs.post_processing()
            cs.export_results()

            self.assertTrue(os.path.isfile(report_path_1))
            with open(report_path_1) as f:
                report = json.load(f)
            len_samples_report = len(report)
            self.assertTrue(1 < len_samples_report < len_samples_scan_results)

            # change the report file name
            cs.json_filename = report_path_2

            # clean credentials to test zip
            cs.credential_manager.candidates.clear()
            self.assertEqual(0, cs.credential_manager.len_credentials())

            # use the same approach but with single zip file which is made from the samples
            zip_file_path = os.path.join(tmp_dir, "test_p.zip")
            self.assertFalse(os.path.exists(zip_file_path))
            samples_file_count = 0
            with zipfile.ZipFile(zip_file_path, "a", zipfile.ZIP_DEFLATED, compresslevel=9) as zip_file:
                for dirpath, dirnames, filenames in os.walk(SAMPLES_PATH):
                    for filename in filenames:
                        filename_in_zip = f"{samples_file_count}/{filename}" if samples_file_count else filename
                        with zip_file.open(filename_in_zip, "w") as output_file:
                            with open(os.path.join(dirpath, filename), "rb") as input_file:
                                output_file.write(input_file.read())
                                samples_file_count += 1
            self.assertEqual(SAMPLES_FILES_COUNT, samples_file_count)
            content_provider = FilesProvider([zip_file_path])
            file_extractors = content_provider.get_scannable_files(cs.config)
            self.assertEqual(1, len(file_extractors))
            # single extractor
            zip_scan_results = cs.file_scan(file_extractors[0])
            # zip scan is used deep scan for source files too
            # so there might be a delta, because samples have tricky cases
            self.assertAlmostEqual(len_samples_scan_results, len(zip_scan_results), delta=3)

            cs.credential_manager.set_credentials(zip_scan_results)
            cs.post_processing()
            cs.export_results()

            self.assertTrue(os.path.isfile(report_path_1))
            with open(report_path_1) as f:
                report = json.load(f)
            len_samples_report = len(report)
            self.assertTrue(1 < len_samples_report < len_samples_scan_results)

    def test_scan_zipfile_size_limit_n(self) -> None:
        cs = CredSweeper()
        content_provider = DataContentProvider(open(SAMPLE_ZIP, "rb").read(), SAMPLE_ZIP)
        self.assertEqual(0, len(cs.deep_scanner.recursive_scan(content_provider, 3, 4)))

    def test_scan_zipfile_size_limit_p(self) -> None:
        cs = CredSweeper()
        content_provider = DataContentProvider(open(SAMPLE_ZIP, "rb").read(), SAMPLE_ZIP)
        self.assertEqual(1, len(cs.deep_scanner.recursive_scan(content_provider, 3, 1024)))

    def test_scan_zipfile_bomb_1_n(self) -> None:
        # create with depth to remove *.zip extension
        cs = CredSweeper(depth=2)
        content_provider = DataContentProvider(zb1, "zip_bomb_1")
        res_1 = cs.deep_scanner.recursive_scan(content_provider, 2, 1 << 30)
        self.assertEqual(0, len(res_1))

    def test_scan_zipfile_bomb_2_n(self) -> None:
        # create with depth to remove *.zip extension
        cs = CredSweeper(depth=4)
        content_provider = DataContentProvider(zb2, "zip_bomb_2")
        res_2 = cs.deep_scanner.recursive_scan(content_provider, 16, 1 << 16)
        self.assertEqual(0, len(res_2))

    def test_free_n(self) -> None:
        provider = DataContentProvider(AZ_DATA)
        self.assertEqual(AZ_DATA, provider.data)
        provider.free()
        self.assertIsNone(provider.data)
        provider.free()
        provider.free()
