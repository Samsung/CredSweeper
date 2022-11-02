import json
import os
import tempfile
import unittest
import zipfile
from typing import List

from credsweeper import DataContentProvider
from credsweeper.app import CredSweeper
from credsweeper.credentials import Candidate
from credsweeper.file_handler.text_provider import TextProvider
from tests import SAMPLES_FILES_COUNT, SAMPLES_DIR
from tests.file_handler.zip_bomb_1 import zb1
from tests.file_handler.zip_bomb_2 import zb2


class DataContentProviderTest(unittest.TestCase):
    WRONG_ZIP_FILE = b"PK\003\004_WRONG_ZIP_FILE"

    def test_scan_wrong_provider_n(self) -> None:
        content_provider = DataContentProvider(b"dummy", "dummy")
        cs = CredSweeper(json_filename="dummy")
        with self.assertRaises(NotImplementedError):
            cs.file_scan(content_provider)

    def test_scan_bottom_reach_n(self) -> None:
        content_provider = DataContentProvider(self.WRONG_ZIP_FILE, "dummy")
        cs = CredSweeper(json_filename="dummy")
        assert len(cs.data_scan(content_provider, 0, 1 << 16)) == 0

    def test_scan_wrong_zip_data_n(self) -> None:
        content_provider = DataContentProvider(self.WRONG_ZIP_FILE, "dummy")
        cs = CredSweeper(json_filename="dummy")
        assert len(cs.data_scan(content_provider, 1, 1 << 16)) == 0

    def test_scan_empty_zip_n(self) -> None:
        content_provider = DataContentProvider(
            b'PK\x05\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', "dummy")
        cs = CredSweeper(json_filename="dummy")
        assert len(cs.data_scan(content_provider, 1, 1 << 16)) == 0

    def test_scan_zipfile_n(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            report_path = os.path.join(tmp_dir, "report.json")
            file_path = os.path.join(tmp_dir, "test_n.zip")
            assert not os.path.exists(file_path)
            open(file_path, "wb").write(self.WRONG_ZIP_FILE)

            content_provider = TextProvider([tmp_dir])
            cs = CredSweeper(json_filename=report_path, depth=1)

            file_extractors = content_provider.get_scannable_files(cs.config)
            assert len(file_extractors) == 1
            scan_results = cs.file_scan(file_extractors[0])
            assert len(scan_results) == 0
            assert not os.path.isfile(report_path)

    def test_scan_zipfile_p(self) -> None:
        # create new zip archive with all samples
        with tempfile.TemporaryDirectory() as tmp_dir:
            report_path_1 = os.path.join(tmp_dir, "report_1.json")
            report_path_2 = os.path.join(tmp_dir, "report_2.json")

            cs = CredSweeper(json_filename=report_path_1, find_by_ext=True, depth=5)

            # calculate samples
            content_provider = TextProvider([SAMPLES_DIR])
            file_extractors = content_provider.get_scannable_files(cs.config)
            assert len(file_extractors) > 1
            samples_scan_results: List[Candidate] = []
            for file_extractor in file_extractors:
                samples_scan_results.extend(cs.file_scan(file_extractor))
            len_samples_scan_results = len(samples_scan_results)
            assert len_samples_scan_results > 1
            cs.credential_manager.set_credentials(samples_scan_results)
            cs.post_processing()
            cs.export_results()

            assert os.path.isfile(report_path_1)
            with open(report_path_1) as f:
                report = json.load(f)
            len_samples_report = len(report)
            assert len_samples_report < len_samples_scan_results
            assert len_samples_report > 1

            # change the report file name
            cs.json_filename = report_path_2

            # clean credentials to test zip
            cs.credential_manager.candidates.clear()
            assert len(cs.credential_manager.get_credentials()) == 0

            # use the same approach but with single zip file which is made from the samples
            zip_file_path = os.path.join(tmp_dir, "test_p.zip")
            assert not os.path.exists(zip_file_path)
            samples_file_count = 0
            with zipfile.ZipFile(zip_file_path, "a", zipfile.ZIP_DEFLATED, compresslevel=9) as zip_file:
                for dirpath, dirnames, filenames in os.walk(SAMPLES_DIR):
                    for filename in filenames:
                        filename_in_zip = f"{samples_file_count}/{filename}" if samples_file_count else filename
                        with zip_file.open(filename_in_zip, "w") as output_file:
                            with open(os.path.join(dirpath, filename), "rb") as input_file:
                                output_file.write(input_file.read())
                                samples_file_count += 1
            self.assertEqual(SAMPLES_FILES_COUNT, samples_file_count)
            content_provider = TextProvider([zip_file_path])
            file_extractors = content_provider.get_scannable_files(cs.config)
            assert len(file_extractors) == 1
            # single extractor
            zip_scan_results = cs.file_scan(file_extractors[0])
            self.assertEqual(len_samples_scan_results, len(zip_scan_results))

            cs.credential_manager.set_credentials(zip_scan_results)
            cs.post_processing()
            cs.export_results()

            assert os.path.isfile(report_path_1)
            with open(report_path_1) as f:
                report = json.load(f)
            len_samples_report = len(report)
            assert len_samples_report < len_samples_scan_results
            assert len_samples_report > 1

    def test_scan_zipfile_size_limit_p(self) -> None:
        sample_path = SAMPLES_DIR / "pem_key.zip"
        cs = CredSweeper()
        content_provider = DataContentProvider(open(sample_path, "rb").read(), sample_path)
        res_0 = cs.data_scan(content_provider, 3, 4)
        assert len(res_0) == 0
        res_1 = cs.data_scan(content_provider, 3, 1024)
        assert len(res_1) == 1

    def test_scan_zipfile_bomb_1_n(self) -> None:
        # create with depth to remove *.zip extension
        cs = CredSweeper(depth=2)
        content_provider = DataContentProvider(zb1, "zip_bomb_1")
        res_1 = cs.data_scan(content_provider, 2, 1 << 30)
        assert len(res_1) == 0

    def test_scan_zipfile_bomb_2_n(self) -> None:
        # create with depth to remove *.zip extension
        cs = CredSweeper(depth=4)
        content_provider = DataContentProvider(zb2, "zip_bomb_2")
        res_2 = cs.data_scan(content_provider, 16, 1 << 16)
        assert len(res_2) == 0
