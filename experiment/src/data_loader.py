import json
import os
import pathlib
from copy import deepcopy
from typing import Tuple, Dict

import numpy as np
import pandas as pd

identifier = Tuple[str, int]

ml_categories = [
    "Authentication Credentials",  #
    "Cryptographic Primitives",  #
    "Generic Secret",  #
    "Generic Token",  #
    "Password",  #
    "Predefined Pattern",  #
]


def strip_data_path(file_path, split="CredData/"):
    file_path = pathlib.Path(file_path).as_posix()
    return file_path.split(split, 1)[-1]


def read_detected_data(file_path: str, split="CredData/") -> Dict[identifier, Dict]:
    print(f"Reading detections from {file_path}")
    with open(file_path) as f:
        detections = json.load(f)

    detected_lines = {}

    for detection in detections:
        if 1 != len(detection["line_data_list"]):
            continue
        for line_data in detection["line_data_list"]:
            relative_path = strip_data_path(line_data["path"], split)
            index = relative_path, line_data["line_num"]
            data_to_save = deepcopy(line_data)
            data_to_save["path"] = relative_path
            data_to_save["RuleName"] = [detection["rule"]]

            if index not in detected_lines:
                detected_lines[index] = data_to_save
            else:
                detected_lines[index]["RuleName"].append(detection["rule"])

    print(f"Detected {len(detected_lines)} unique lines!")
    print(f"{len(detections)} detections in total")

    return detected_lines


def read_metadata(meta_dir: str, split="CredData/") -> Dict[identifier, Dict]:
    print(f"Reading meta from {meta_dir}")
    meta_lines = {}
    j = 0

    for file_path in os.listdir(meta_dir):
        csv_file = os.path.join(meta_dir, file_path)
        if not file_path.endswith(".csv"):
            print(f"skip garbage: {csv_file}")
            continue
        file_meta = pd.read_csv(csv_file, dtype={'RepoName': str, 'GroundTruth': str})
        for i, row in file_meta.iterrows():
            j += 1
            if "Template" == row["GroundTruth"]:
                print(f"WARNING: transform Template to FALSE\n{row}")
                row["GroundTruth"] = "F"
            if row["Category"] not in ml_categories:
                print(f"WARNING: skip not ml category {row['FilePath']},{row['LineStart:LineEnd']}"
                      f",{row['GroundTruth']},{row['Category']}")
                continue
            line_start, line_end = row["LineStart:LineEnd"].split(":")
            if line_start != line_end:
                print(f"WARNING: skip multiline as train or test data {row}")
                continue
            relative_path = strip_data_path(row["FilePath"], split)
            index = relative_path, int(line_start)
            if index not in meta_lines:
                row_data = row.to_dict()
                row_data["FilePath"] = relative_path
                meta_lines[index] = row_data
            else:
                print(f"WARNING: {index} already in meta_lines {row['GroundTruth']} {row['Category']}")

    print(f"Loaded {len(meta_lines)} lines from meta of {j} total")

    return meta_lines


def join_label(detected_data: Dict[identifier, Dict], meta_data: Dict[identifier, Dict]) -> pd.DataFrame:
    values = []
    for index, line_data in detected_data.items():
        label = False
        if index not in meta_data:
            print(f"WARNING: {index} is not in meta!!!\n{line_data}")
        elif meta_data[index]["Category"] not in ml_categories:
            # skip not ML values like private keys and so on
            print(f"WARNING: {line_data} is not ML category! {meta_data[index]}")
        else:
            if 'T' == meta_data[index]["GroundTruth"]:
                label = True
        line_data["GroundTruth"] = label
        values.append(line_data)
    # values = list(detected_data.values())
    df = pd.DataFrame(values)
    df["repo"] = [repo.split("/")[1] for repo in df["path"]]
    df["ext"] = [os.path.splitext(ext)[-1] for ext in df["path"]]
    df["type"] = [repo.split("/")[2] for repo in df["path"]]  # src, test, other
    return df


def get_y_labels(df: pd.DataFrame) -> np.ndarray:
    true_cases = np.array(df["GroundTruth"], dtype=np.float32)
    return true_cases
