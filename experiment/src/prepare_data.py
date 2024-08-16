import binascii
import hashlib
import os
import subprocess
import sys
from pathlib import Path

from credsweeper.utils import Util


def execute_scanner(dataset_location: str, result_location_str, j):
    """Execute CredSweeper as a separate process to make sure no global states is shared with training script"""
    dir_path = os.path.dirname(os.path.realpath(__file__)) + "/.."
    command = f"{sys.executable} -m credsweeper --path {dataset_location}/data" \
              f" --save-json {result_location_str} --log info" \
              f" --job {j} --sort --rules results/train_config.yaml --ml_threshold 0 --subtext"
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


def prepare_train_data(cred_data_location: str, j: int):
    print("Start train data preparation...")

    if not os.path.exists("train_config.yaml"):
        # use pattern or keyword type
        rules = Util.yaml_load("../credsweeper/rules/config.yaml")
        new_rules = [x for x in rules if x.get("use_ml")]
        Util.yaml_dump(new_rules, "results/train_config.yaml")

    meta_checksum=data_checksum(Path(cred_data_location) / "meta")
    print(f"meta checksum {meta_checksum}")

    data_dir_checksum = data_checksum(Path(cred_data_location) / "data")
    print(f"data checksum {data_dir_checksum}")
    detected_data_filename = f"results/detected_data.{data_dir_checksum}.json"

    if not os.path.exists(detected_data_filename):
        print(f"Get CredSweeper results from {cred_data_location}. May take some time")
        execute_scanner(cred_data_location, detected_data_filename, j)
    else:
        print(f"Get cached result {data_dir_checksum}")

    print("Train data prepared!")
