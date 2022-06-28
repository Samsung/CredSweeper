import os
import sys
import subprocess


def execute_scanner(dataset_location: str, result_location_str, j, use_ml=False):
    """Execute CredSweeper as a separate process to make sure no global states is shared with training script"""
    dir_path = os.path.dirname(os.path.realpath(__file__)) + "/.."
    command = f"{sys.executable} -m credsweeper --path {dataset_location}/data --save-json {result_location_str} -j {j}"
    if not use_ml:
        command += " --ml_threshold 0"
    subprocess.call(command, shell=True, cwd=dir_path, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)


def get_aug_data(dataset_location: str):
    """Execute CredSweeper as a separate process to make sure no global states is shared with training script"""
    dir_path = os.path.dirname(os.path.realpath(__file__)) + "/.."
    command = f"{sys.executable} main.py {dataset_location} 0.1 5"
    subprocess.call(command, shell=True, cwd=dir_path + "/augmentation")


def prepare_train_data(cred_data_location: str, j: int):
    os.makedirs("data", exist_ok=True)

    if not os.path.exists("data/result_aug_data.json"):
        print(f"Augment data from {cred_data_location}")
        get_aug_data(cred_data_location)
        execute_scanner(cred_data_location + "/aug_data", "data/result_aug_data.json", j)

    if not os.path.exists("data/result.json"):
        print(f"Get CredSweeper results from {cred_data_location}. May take some time")
        execute_scanner(cred_data_location, "data/result.json", j)

    print("Train data prepared!")
