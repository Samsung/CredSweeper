import binascii
import hashlib
import os
import pathlib
import subprocess
import sys
from pathlib import Path

from credsweeper.scanner.scanner import RULES_PATH
from credsweeper.utils.util import Util

RESULTS_DIR = pathlib.Path(__file__).parent / "results"


def execute_scanner(dataset_location: str, report_file_str: str, train_rules_str: str, jobs: int, doc_target: bool):
    """Execute CredSweeper as a separate process to make sure no global states is shared with training script"""
    dir_path = os.path.dirname(os.path.realpath(__file__))
    command = (f"{sys.executable} -m credsweeper"
               f" --jobs {jobs}"
               f" --path {dataset_location}/data"
               f" {'--doc' if doc_target else ''}"
               f" --save-json {report_file_str}"
               f" --rules {train_rules_str}"
               " --pedantic"
               " --ml_threshold 0"
               " --sort"
               " --subtext"
               " --log info"
               " --no-stdout")
    error_code = subprocess.check_call(command, shell=True, cwd=dir_path)
    if 0 != error_code:
        sys.exit(error_code)


def data_checksum(dir_path: Path) -> str:
    checksum = hashlib.md5(b'').digest()
    for root, dirs, files in os.walk(dir_path):
        for file in files:
            with open(os.path.join(root, file), "rb") as f:
                cvs_checksum = hashlib.md5(f.read()).digest()
            checksum = bytes(a ^ b for a, b in zip(checksum, cvs_checksum))
    return binascii.hexlify(checksum).decode()


def prepare_train_data(cred_data_location: str, jobs: int, doc_target: bool):
    print("Start train data preparation...", flush=True)

    # use current rules
    rules = Util.yaml_load(RULES_PATH)
    target = "doc" if doc_target else "code"
    new_rules = [x for x in rules if x.get("use_ml") and target in x["target"]]
    train_rules_config_path = RESULTS_DIR / "train_config.yaml"
    Util.yaml_dump(new_rules, train_rules_config_path)

    meta_dir_checksum = data_checksum(Path(cred_data_location) / "meta")
    print(f"meta checksum {meta_dir_checksum}", flush=True)

    data_dir_checksum = data_checksum(Path(cred_data_location) / "data")
    print(f"data checksum {data_dir_checksum}", flush=True)
    detected_data_filename = RESULTS_DIR / f"detected_data.{data_dir_checksum}.json"

    if not os.path.exists(detected_data_filename):
        print(f"Get CredSweeper results from {cred_data_location}. May take some time", flush=True)
        execute_scanner(cred_data_location, str(detected_data_filename), str(train_rules_config_path), jobs, doc_target)
    else:
        print(f"Get cached result {data_dir_checksum}", flush=True)

    print("Train data prepared!", flush=True)
    return meta_dir_checksum, data_dir_checksum
