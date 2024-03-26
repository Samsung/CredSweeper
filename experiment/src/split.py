import os
from typing import List, Tuple

from credsweeper.utils import Util


def load_fixed_split() -> Tuple[List[str], List[str]]:
    dir_path = os.path.dirname(os.path.realpath(__file__))
    split_file_path = os.path.join(dir_path, "split.json")

    split_data = Util.json_load(split_file_path)

    train_repo_list = split_data["train_repo_list"]
    test_repo_list = split_data["test_repo_list"]

    return train_repo_list, test_repo_list
