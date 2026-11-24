import binascii
import contextlib
import hashlib
import os
import subprocess
import sys
from pathlib import Path

from constants import RESULTS_DIR
from credsweeper.common.constants import UTF_8
from credsweeper.scanner.scanner import RULES_PATH
from credsweeper.utils.util import Util
from experiment.constants import THIS_DIR


def execute_scanner(dataset_location: str, report_file_str: str, train_rules_str: str, jobs: int, doc_target: bool):
    """Execute CredSweeper as a separate process to make sure no global states is shared with training script"""
    command_args = [
        sys.executable,
        "-m", "credsweeper",
        "--banner",
        "--jobs", str(jobs),
        "--path", f"{dataset_location}/data",
        "--save-json", report_file_str,
        "--rules", train_rules_str,
        "--pedantic",
        "--ml_threshold", "0",
        "--sort",
        "--subtext",
        "--log", "info",
        "--no-stdout",
    ]
    if doc_target:
        command_args.append("--doc")
    subprocess.run(command_args, check=True, cwd=THIS_DIR)


def data_checksum(dir_path: Path) -> str:
    hashes = []
    print(f"Collecting data hashes in {dir_path}", flush=True)
    with contextlib.chdir(dir_path):
        for root, dirs, files in os.walk('.'):
            for file in files:
                with open(os.path.join(root, file), "rb") as f:
                    file_data = f.read()
                    data = b''.join([
                        root.encode(UTF_8), b'\0',
                        file.encode(UTF_8), b'\0',
                        str(len(file_data)).encode(UTF_8), b'\0',
                        file_data,
                    ])
                    hashes.append(hashlib.md5(data).digest())
    checksum = hashlib.md5(b''.join(sorted(hashes))).hexdigest()
    print(f"Collected hash {checksum} from data {dir_path}", flush=True)
    return checksum


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
