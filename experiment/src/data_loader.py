import json
import os
import pathlib
from copy import deepcopy
from typing import Tuple, Dict

import numpy as np
import pandas as pd

identifier = Tuple[str, int]


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
            if "Template" == row["GroundTruth"]:
                # skip templates as train or test data
                continue
            line_number = int(row["LineStart:LineEnd"].split(":")[0])
            relative_path = strip_data_path(row["FilePath"], split)
            index = relative_path, line_number
            j += 1
            if index not in meta_lines:
                row_data = row.to_dict()
                row_data["FilePath"] = relative_path
                meta_lines[index] = row_data

    print(f"Loaded {len(meta_lines)} lines from meta!")
    print(f"{j} lines in meta in total")

    return meta_lines


def join_label(detected_data: Dict[identifier, Dict], meta_data: Dict[identifier, Dict]) -> pd.DataFrame:
    ml_categories = [
        "Authentication Credentials",  #
        "Cryptographic Primitives",  #
        "Generic Secret",  #
        "Generic Token",  #
        "Password",  #
        "Predefined Pattern",  #
    ]
    values = []
    for index, line_data in detected_data.items():
        if index not in meta_data:
            print(f"WARNING: {line_data} is not in meta!!!", flush=True)
            continue
        else:
            label = meta_data[index]["GroundTruth"] == "T"
            if meta_data[index]["Category"] not in ml_categories:
                # skip not ML values like private keys and so on
                continue
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
