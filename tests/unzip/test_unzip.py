import json
import os
import tempfile
import zipfile
from typing import List

from credsweeper import app
from credsweeper.credentials import Candidate
from credsweeper.file_handler.text_provider import TextProvider


def test_scan_zip_p() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        report_path = os.path.join(tmp_dir, f"report.json")
        zip_file_path = os.path.join(tmp_dir, f"test_p.zip")
        assert not os.path.exists(zip_file_path)
        this_dir = os.path.dirname(os.path.realpath(__file__))
        samples_dir = os.path.join(this_dir, "..", "samples")
        with zipfile.ZipFile(zip_file_path, "a", zipfile.ZIP_DEFLATED, compresslevel=9) as zip_file:
            for dirpath, dirnames, filenames in os.walk(samples_dir):
                for filename in filenames:
                    with zip_file.open(filename, "w") as output_file:
                        with open(os.path.join(dirpath, filename), "rb") as input_file:
                            output_file.write(input_file.read())

        cs = app.CredSweeper(unzip=True, json_filename=report_path, ml_validation=True)
        cs.config.exclude_extensions.remove(".zip")

        # calculate samples
        content_provider = TextProvider([samples_dir])
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

        assert os.path.isfile(report_path)
        with open(report_path) as f:
            report = json.load(f)
        len_samples_report = len(report)
        assert len_samples_report < len_samples_scan_results
        assert len_samples_report > 1

        # clean the report file
        os.remove(report_path)
        assert not os.path.isfile(report_path)

        # clean credentials to test zip
        cs.credential_manager.candidates.clear()
        assert len(cs.credential_manager.get_credentials()) == 0

        # use the same approach but with single zip file
        content_provider = TextProvider([zip_file_path])
        file_extractors = content_provider.get_scannable_files(cs.config)
        assert len(file_extractors) == 1
        # single extractor
        zip_scan_results = cs.file_scan(file_extractors[0])
        assert len_samples_scan_results == len(zip_scan_results)
        cs.credential_manager.set_credentials(zip_scan_results)
        cs.post_processing()
        cs.export_results()

        assert os.path.isfile(report_path)
        with open(report_path) as f:
            report = json.load(f)
        len_samples_report = len(report)
        assert len_samples_report < len_samples_scan_results
        assert len_samples_report > 1


def test_scan_zip_n() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        report_path = os.path.join(tmp_dir, f"report.json")
        file_path = os.path.join(tmp_dir, f"test_n.zip")
        assert not os.path.exists(file_path)
        open(file_path, "wb").write(b"PK_WRONG_ZIP_FILE")

        content_provider = TextProvider([tmp_dir])
        cs = app.CredSweeper(unzip=True, json_filename=report_path)
        cs.config.exclude_extensions.remove(".zip")

        file_extractors = content_provider.get_scannable_files(cs.config)
        assert len(file_extractors) == 1
        scan_results = cs.file_scan(file_extractors[0])
        assert len(scan_results) == 0
        assert not os.path.isfile(report_path)
