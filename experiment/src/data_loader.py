import json
import os
from copy import deepcopy
from typing import Tuple, Dict

import numpy as np
import pandas as pd

identifier = Tuple[str, int]


def strip_data_path(file_path, split="CredData/"):
    file_path = file_path.replace("//", "/")
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
        file_meta = pd.read_csv(csv_file, dtype={'RepoName': str, 'GroundTruth': str})
        for i, row in file_meta.iterrows():
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
    for index, line_data in detected_data.items():
        if index not in meta_data:
            label = False
        else:
            label = meta_data[index]["GroundTruth"] == "T"
        line_data["GroundTruth"] = label
    values = list(detected_data.values())
    df = pd.DataFrame(values)
    df["repo"] = [l.split("/")[1] for l in df["path"]]
    df["ext"] = [os.path.splitext(l)[-1] for l in df["path"]]
    return df


def get_missing(detected_data: Dict[identifier, Dict], meta_data: Dict[identifier, Dict]) -> pd.DataFrame:
    missing = []
    for index, data in meta_data.items():
        if index not in detected_data:
            data["GroundTruth"] = data["GroundTruth"] == "T"
            data["repo"] = data["FilePath"].split("/")[1]
            missing.append(data)
    df = pd.DataFrame(missing)
    return df


def train_model():
    pass


def eval_no_model(df: pd.DataFrame, df_missing: pd.DataFrame):
    tp = len(df[df["GroundTruth"]])
    fp = len(df[~df["GroundTruth"]])
    tn = len(df_missing[~df_missing["GroundTruth"]])
    fn = len(df_missing[df_missing["GroundTruth"]])

    total_lines = tp + fp + tn + fn

    total_true_count = tp + fn
    total_false_count = total_lines - total_true_count

    true_positive: int = tp
    false_positive: int = fp
    true_negative: int = total_false_count - fp
    false_negative: int = fn
    false_positive_rate: float = false_positive / total_false_count
    false_negative_rate: float = (total_true_count - true_positive) / total_true_count
    precision: float = true_positive / (true_positive + false_positive)
    recall: float = true_positive / (true_positive + false_negative)
    f1: float = (2 * precision * recall) / (precision + recall)

    report = f"TP : {true_positive}, FP : {false_positive}, TN : {true_negative}, " \
             f"FN : {false_negative}, FPR : {false_positive_rate:.10f}, " \
             f"FNR : {false_negative_rate:.10f}, PRC : {precision:.10f}, " \
             f"RCL : {recall:.10f}, F1 : {f1:.10f}"
    print(report)


def eval_with_model(df: pd.DataFrame, df_missing: pd.DataFrame, predictions: np.ndarray):
    df["Correct"] = df["GroundTruth"] == predictions
    tp = len(df[df["GroundTruth"] & df["Correct"]])
    fp = len(df[~df["GroundTruth"] & ~df["Correct"]])
    tn = len(df[~df["GroundTruth"] & df["Correct"]])
    fn = len(df[df["GroundTruth"] & ~df["Correct"]])

    tn += len(df_missing[~df_missing["GroundTruth"]])
    fn += len(df_missing[df_missing["GroundTruth"]])

    total_lines = tp + fp + tn + fn

    total_true_count = tp + fn
    total_false_count = total_lines - total_true_count

    true_positive: int = tp
    false_positive: int = fp
    true_negative: int = total_false_count - fp
    false_negative: int = fn
    false_positive_rate: float = false_positive / total_false_count
    false_negative_rate: float = (total_true_count - true_positive) / total_true_count
    precision: float = true_positive / (true_positive + false_positive)
    recall: float = true_positive / (true_positive + false_negative)
    f1: float = (2 * precision * recall) / (precision + recall)

    report = f"TP : {true_positive}, FP : {false_positive}, TN : {true_negative}, " \
             f"FN : {false_negative}, FPR : {false_positive_rate:.10f}, " \
             f"FNR : {false_negative_rate:.10f}, PRC : {precision:.10f}, " \
             f"RCL : {recall:.10f}, F1 : {f1:.10f}"
    print(report)


def get_y_labels(df: pd.DataFrame) -> np.ndarray:
    true_cases = np.array(df["GroundTruth"], dtype=np.int8)
    return true_cases
