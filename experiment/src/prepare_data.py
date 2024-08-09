import os
import subprocess
import sys

from credsweeper.utils import Util


def execute_scanner(dataset_location: str, result_location_str, j):
    """Execute CredSweeper as a separate process to make sure no global states is shared with training script"""
    dir_path = os.path.dirname(os.path.realpath(__file__)) + "/.."
    command = f"{sys.executable} -m credsweeper --path {dataset_location}/data" \
              f" --save-json {result_location_str} --log info" \
              f" --job {j} --sort --rules results/train_config.yaml --ml_threshold 0"
    error_code = subprocess.check_call(command, shell=True, cwd=dir_path)
    if 0 != error_code:
        sys.exit(error_code)


def prepare_train_data(cred_data_location: str, j: int):
    print("Start train data preparation...")

    if not os.path.exists("train_config.yaml"):
        # use pattern or keyword type
        rules = Util.yaml_load("../credsweeper/rules/config.yaml")
        new_rules = [x for x in rules if "code" in x.get("target") and x.get("type") in ["pattern", "keyword"]]
        Util.yaml_dump(new_rules, "results/train_config.yaml")

    if not os.path.exists("results/detected_data.json"):
        print(f"Get CredSweeper results from {cred_data_location}. May take some time")
        execute_scanner(cred_data_location, "results/detected_data.json", j)

    print("Train data prepared!")
