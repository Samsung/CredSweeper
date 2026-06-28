import binascii
import hashlib
import json
import os
import tempfile
import time
import unittest

import numpy as np
import pandas as pd
import yaml

from credsweeper.main import main, EXIT_SUCCESS
from credsweeper.scanner.scanner import RULES_PATH
from credsweeper.utils.util import Util
from tests import SAMPLES_FILTERED_COUNT, SAMPLES_POST_CRED_COUNT, SAMPLES_PATH, SAMPLES_IN_DEEP_3, AZ_STRING


class TestMain(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

    def tearDown(self):
        pass

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_main_path_p(self) -> None:
        target_path = SAMPLES_PATH / "password.patch"
        with tempfile.TemporaryDirectory() as tmp_dir:
            argv = [
                "--diff",
                str(target_path),
                "--save-json",
                str(os.path.join(tmp_dir, f"{__name__}.json")),
                "--save-xlsx",
                str(os.path.join(tmp_dir, f"{__name__}.xlsx")),
            ]
            self.assertEqual(EXIT_SUCCESS, main(argv))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, f"{__name__}.xlsx")))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, f"{__name__}.deleted.json")))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, f"{__name__}.added.json")))
            report = Util.json_load(os.path.join(tmp_dir, f"{__name__}.added.json"))
            self.assertTrue(report)
            self.assertEqual(3, report[0]["line_data_list"][0]["line_num"])
            self.assertEqual("dkajco1", report[0]["line_data_list"][0]["value"])

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_binary_patch_p(self) -> None:
        # test verifies case when binary diff might be scanned
        target_path = SAMPLES_PATH / "multifile.patch"
        with tempfile.TemporaryDirectory() as tmp_dir:
            argv = [
                "--diff_path",
                str(target_path), "--save-json",
                str(os.path.join(tmp_dir, f"{__name__}.json")), "--ml_threshold", "0", "--depth", "9"
            ]
            self.assertEqual(EXIT_SUCCESS, main(argv))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, f"{__name__}.deleted.json")))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, f"{__name__}.added.json")))
            report = Util.json_load(os.path.join(tmp_dir, f"{__name__}.added.json"))
            self.assertTrue(report)
            self.assertEqual(5, len(report))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_report_p(self) -> None:
        # verifies reports creations
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            xlsx_filename = os.path.join(tmp_dir, f"{__name__}.xlsx")
            argv = [
                "--path",
                str(SAMPLES_PATH),
                "--ml_threshold",
                "0",
                "--save-json",
                str(json_filename),
                "--save-xlsx",
                str(xlsx_filename),
            ]
            self.assertEqual(EXIT_SUCCESS, main(argv))
            self.assertTrue(os.path.exists(json_filename))
            self.assertTrue(os.path.exists(xlsx_filename))
            report = Util.json_load(json_filename)
            self.assertTrue(report)
            self.assertEqual(SAMPLES_FILTERED_COUNT, len(report))
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
            excel_report_delta_rows = 288
            self.assertEqual(SAMPLES_FILTERED_COUNT + excel_report_delta_rows, len(df))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_export_config_p(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            argv = ["--export_config", json_filename]
            self.assertEqual(EXIT_SUCCESS, main(argv))
            self.assertTrue(os.path.exists(json_filename))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_export_log_config_p(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_filename = os.path.join(tmp_dir, f"{__name__}.yaml")
            argv = ["--export_log_config", test_filename]
            self.assertEqual(EXIT_SUCCESS, main(argv))
            self.assertTrue(os.path.exists(test_filename))
            self.assertFalse(os.path.exists(os.path.join(tmp_dir, "log")))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_import_log_config_p(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_filename = os.path.join(tmp_dir, f"{__name__}.yaml")
            with open(test_filename, 'w') as f:
                f.write(f"---\nversion: 1\ndisable_existing_loggers: False\nhandlers:\n"
                        f"  logfile:\n"
                        f"    class: logging.handlers.RotatingFileHandler\n"
                        f"    level: NOTSET\n"
                        f"    filename: {tmp_dir}/log/logfile.log\n"
                        f"root:\n"
                        f"  level: NOTSET\n"
                        f"  handlers: [logfile]\n")
            argv = ["--banner", "--log_config", test_filename, "--log", "notset", "--path", tmp_dir]
            self.assertEqual(EXIT_SUCCESS, main(argv))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "log")))
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "log", "logfile.log")))
            if "nt" == os.name:
                # workaround for the case
                time.sleep(1)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_find_by_ext_n(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            for f in [".pem", ".cer", ".csr", ".der", ".pfx", ".p12", ".key", ".jks"]:
                file_path = os.path.join(tmp_dir, f"dummy{f}")
                self.assertFalse(os.path.exists(file_path))
                open(file_path, 'w').write(AZ_STRING)
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            argv = ["--path", tmp_dir, "--no-stdout", "--save-json", json_filename, "--log", "silence"]
            self.assertEqual(EXIT_SUCCESS, main(argv))
            self.assertTrue(os.path.exists(json_filename))
            with open(json_filename, "r") as json_file:
                report = json.load(json_file)
                self.assertEqual(0, len(report))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_find_by_ext_p(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            # .deR will be found too!
            for f in [".pem", ".cer", ".csr", ".deR"]:
                file_path = os.path.join(tmp_dir, f"dummy{f}")
                self.assertFalse(os.path.exists(file_path))
                open(file_path, 'w').write(AZ_STRING)

            # not of all will be found due they are empty
            for f in [".jks", ".KeY"]:
                file_path = os.path.join(tmp_dir, f"dummy{f}")
                self.assertFalse(os.path.exists(file_path))
                open(file_path, 'w').close()

            # the directory hides all files
            ignored_dir = os.path.join(tmp_dir, "target")
            os.mkdir(ignored_dir)
            for f in [".pfx", ".p12"]:
                file_path = os.path.join(ignored_dir, f"dummy{f}")
                self.assertFalse(os.path.exists(file_path))
                open(file_path, 'w').write(AZ_STRING)

            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            argv = ["--path", tmp_dir, "--find-by-ext", "--no-stdout", "--save-json", json_filename, "--log", "silence"]
            self.assertEqual(EXIT_SUCCESS, main(argv))
            self.assertTrue(os.path.exists(json_filename))
            with open(json_filename, "r") as json_file:
                report = json.load(json_file)
                self.assertEqual(4, len(report), report)
                for t in report:
                    self.assertEqual(0, t["line_data_list"][0]["line_num"])
                    self.assertIn(str(t["line_data_list"][0]["path"][-4:]), [".pem", ".cer", ".csr", ".deR"])

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_depth_n(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            # depth is not set
            argv = ["--log", "silence", "--path", str(SAMPLES_PATH), "--no-stdout", "--save-json", json_filename]
            self.assertEqual(EXIT_SUCCESS, main(argv))
            self.assertTrue(os.path.exists(json_filename))
            with open(json_filename, "r") as json_file:
                report = json.load(json_file)
                self.assertEqual(SAMPLES_POST_CRED_COUNT, len(report))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_depth_p(self) -> None:
        # check data samples integrity
        checksum = hashlib.md5(b'').digest()
        for root, dirs, files in os.walk(SAMPLES_PATH):
            for file in files:
                with open(os.path.join(root, file), "rb") as f:
                    cvs_checksum = hashlib.md5(f.read()).digest()
                checksum = bytes(a ^ b for a, b in zip(checksum, cvs_checksum))
        # update the checksum manually and keep line endings in the samples as is (git config core.autocrlf false)
        self.assertEqual("f65376222446725942c399020b683626", binascii.hexlify(checksum).decode())
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            # depth = 3
            argv = [
                "--log", "silence", "--path",
                str(SAMPLES_PATH), "--no-stdout", "--save-json", json_filename, "--depth", "3"
            ]
            self.assertEqual(EXIT_SUCCESS, main(argv))
            self.assertTrue(os.path.exists(json_filename))
            with open(json_filename, "r") as json_file:
                normal_report = json.load(json_file)
                self.assertEqual(SAMPLES_IN_DEEP_3, len(normal_report))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_denylist_n(self) -> None:
        target_path = str(SAMPLES_PATH / "github_classic_token")
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            denylist_filename = os.path.join(tmp_dir, "list.txt")
            with open(denylist_filename, "w") as f:
                f.write('4WZ4EQ # classic')  # part of line - will not exclude
            argv = [
                "--path", target_path, "--denylist", denylist_filename, "--no-stdout", "--save-json", json_filename,
                "--log", "silence"
            ]
            self.assertEqual(EXIT_SUCCESS, main(argv))
            with open(json_filename, "r") as json_file:
                report = json.load(json_file)
                self.assertEqual(1, len(report))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_denylist_p(self) -> None:
        target_path = str(SAMPLES_PATH / "github_classic_token")
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            denylist_filename = os.path.join(tmp_dir, "list.txt")
            with open(denylist_filename, "w") as f:
                f.write('ghp_00000000000000000000000000000004WZ4EQ # classic')  # full line
            argv = [
                "--path", target_path, "--denylist", denylist_filename, "--no-stdout", "--save-json", json_filename,
                "--log", "silence"
            ]
            self.assertEqual(EXIT_SUCCESS, main(argv))
            with open(json_filename, "r") as json_file:
                report = json.load(json_file)
                self.assertEqual(0, len(report))
            with open(denylist_filename, "w") as f:
                f.write('ghp_00000000000000000000000000000004WZ4EQ')  # value only
            argv = [
                "--path", target_path, "--denylist", denylist_filename, "--no-stdout", "--save-json", json_filename,
                "--log", "silence"
            ]
            self.assertEqual(EXIT_SUCCESS, main(argv))
            with open(json_filename, "r") as json_file:
                report = json.load(json_file)
                self.assertEqual(0, len(report))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_rules_ml_n(self) -> None:
        # checks whether all rules have test samples which detected without ML
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            argv = [
                "--path",
                str(SAMPLES_PATH),
                "--ml_threshold",
                "0",
                "--save-json",
                json_filename,
            ]
            self.assertEqual(EXIT_SUCCESS, main(argv))
            report = Util.json_load(json_filename)
            report_set = set([i["rule"] for i in report])
            rules = Util.yaml_load(RULES_PATH)
            rules_set = set([i["name"] for i in rules if "code" in i["target"]])
            self.assertSetEqual(rules_set, report_set)
            self.assertEqual(SAMPLES_FILTERED_COUNT, len(report))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_rules_ml_p(self) -> None:
        # checks whether all rules have positive test samples with almost the same arguments during benchmark
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            argv = [
                "--path",
                str(SAMPLES_PATH),
                "--save-json",
                json_filename,
            ]
            self.assertEqual(EXIT_SUCCESS, main(argv))
            report = Util.json_load(json_filename)
            report_set = set([i["rule"] for i in report])
            rules = Util.yaml_load(RULES_PATH)
            # test rules integrity
            rules.sort(key=lambda x: x["name"])
            rules_text = yaml.dump_all(rules, sort_keys=True)
            checksum = hashlib.md5(rules_text.encode()).hexdigest()
            # update the expected value manually if some changes
            self.assertEqual("8befed20d1a666bfb047a62596ba4770", checksum)
            rules_set = set([i["name"] for i in rules if "code" in i["target"]])
            self.assertSetEqual(rules_set, report_set)
            self.assertEqual(SAMPLES_POST_CRED_COUNT, len(report))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_no_filters_n(self) -> None:
        # checks with disabled ML and filtering
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, f"{__name__}.json")
            argv = [
                "--path",
                str(SAMPLES_PATH),
                "--ml_threshold",
                "0",
                "--no-filters",
                "--save-json",
                json_filename,
            ]
            self.assertEqual(EXIT_SUCCESS, main(argv))
            report = Util.json_load(json_filename)
            # the number of reported items should increase
            self.assertLess(SAMPLES_FILTERED_COUNT, len(report))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_severity_patch_xlsx_n(self) -> None:
        # uuid is info level - no report
        with tempfile.TemporaryDirectory() as tmp_dir:
            argv = [  #
                "--severity",
                "low",
                "--diff",
                str(SAMPLES_PATH / "uuid-update.patch"),
                "--save-xlsx",
                os.path.join(tmp_dir, f"{__name__}.xlsx"),
                "--save-json",
                os.path.join(tmp_dir, f"{__name__}.json"),
            ]
            self.assertEqual(EXIT_SUCCESS, main(argv))
            # reports are created
            self.assertEqual(3, len(os.listdir(tmp_dir)))
            # but empty
            self.assertListEqual([], Util.json_load(os.path.join(tmp_dir, f"{__name__}.deleted.json")))
            self.assertListEqual([], Util.json_load(os.path.join(tmp_dir, f"{__name__}.added.json")))
            self.assertEqual(0, len(pd.read_excel(os.path.join(tmp_dir, f"{__name__}.xlsx"))))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_severity_patch_xlsx_p(self) -> None:
        # info level produces xlsx file with "added" and "deleted" sheets and two json files
        with tempfile.TemporaryDirectory() as tmp_dir:
            xlsx_filename = os.path.join(tmp_dir, f"{__name__}.xlsx")
            argv = [  #
                "--severity",
                "info",
                "--diff",
                str(SAMPLES_PATH / "uuid-update.patch"),
                "--save-xlsx",
                xlsx_filename,
                "--save-json",
                os.path.join(tmp_dir, f"{__name__}.json"),
            ]
            self.assertEqual(EXIT_SUCCESS, main(argv))
            deleted_report_file = os.path.join(tmp_dir, f"{__name__}.deleted.json")
            deleted_report = Util.json_load(deleted_report_file)
            self.assertEqual("UUID", deleted_report[0]["rule"])
            added_report_file = os.path.join(tmp_dir, f"{__name__}.added.json")
            added_report = Util.json_load(added_report_file)
            self.assertEqual("UUID", added_report[0]["rule"])
            book = pd.read_excel(xlsx_filename, sheet_name=None, header=None)
            # two sheets should be created
            self.assertSetEqual({"deleted", "added"}, set(book.keys()))
            # values in xlsx are wrapped to double quotes
            deleted_value = f'"{deleted_report[0]["line_data_list"][0]["value"]}"'
            self.assertTrue(np.isin(deleted_value, book["deleted"].values))
            added_value = f'"{added_report[0]["line_data_list"][0]["value"]}"'
            self.assertTrue(np.isin(added_value, book["added"].values))
