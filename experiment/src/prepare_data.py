import os
import subprocess
import sys

from credsweeper.utils import Util
from ..augmentation.main import main as aug_main


def execute_scanner(dataset_location: str, result_location_str, j):
    """Execute CredSweeper as a separate process to make sure no global states is shared with training script"""
    dir_path = os.path.dirname(os.path.realpath(__file__)) + "/.."
    command = f"{sys.executable} -m credsweeper --path {dataset_location}/data" \
              f" --save-json {result_location_str} " \
              f"--job {j} --sort --rules train_config.yaml --ml_threshold 0"
    subprocess.check_call(command, shell=True, cwd=dir_path, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)


def prepare_train_data(cred_data_location: str, j: int):
    print("Start train data preparation...")
    os.makedirs("data", exist_ok=True)

    if not os.path.exists("train_config.yaml"):
        # use only rules which marked as use_ml may be valuable
        rules = Util.yaml_load("../credsweeper/rules/config.yaml")
        new_rules = [x for x in rules if x.get("use_ml")]
        Util.yaml_dump(new_rules, "train_config.yaml")

    if not os.path.exists("data/result_aug_data.json"):
        print(f"Augment data from {cred_data_location}")
        aug_main(cred_data_location, 0.5, 2)
        execute_scanner(cred_data_location + "/aug_data", "data/result_aug_data.json", j)

    if not os.path.exists("data/result.json"):
        print(f"Get CredSweeper results from {cred_data_location}. May take some time")
        execute_scanner(cred_data_location, "data/result.json", j)

    print("Train data prepared!")
