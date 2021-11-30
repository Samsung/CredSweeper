import json
import os
from typing import List, Tuple


def load_fixed_split() -> Tuple[List[str], List[str]]:
    dir_path = os.path.dirname(os.path.realpath(__file__))
    split_file_path = os.path.join(dir_path, "split.json")
    with open(split_file_path) as f:
        split_data = json.load(f)

    train_repo_list = split_data["train_repo_list"]
    test_repo_list = split_data["test_repo_list"]

    return train_repo_list, test_repo_list
