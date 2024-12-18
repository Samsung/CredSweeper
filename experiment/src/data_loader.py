import contextlib
import copy
import json
import os
import pathlib
import subprocess
from copy import deepcopy
from functools import cache
from typing import Tuple, Dict, Set, Any

import numpy as np
import pandas as pd
from colorama import Fore, Style, Back

from credsweeper.common.constants import ML_HUNK
from credsweeper.utils import Util

# path, line, val_start, val_end
identifier = Tuple[str, int, int, int]


def transform_to_meta_path(file_path):
    """Transform any path to '......./data/xxxxxxxx/[type]...../yyyyyyyy.ext' to find in meta markup"""
    file_path = pathlib.Path(file_path).as_posix()
    path_list = file_path.split('/')
    assert path_list.count("data") == 1, file_path  # only one "data" directory allowed
    meta_path = ""
    for n, x in enumerate(path_list):
        if x == "data":
            meta_path = '/'.join(path_list[n:])
            break
    assert meta_path, f"data dir was not found in {file_path}"  # just extra check
    return meta_path


def read_detected_data(file_path: str) -> Dict[identifier, Dict]:
    print(f"Reading detections from {file_path}")
    with open(file_path) as f:
        detections = json.load(f)

    detected_lines = {}

    for cred in detections:
        rule_name = cred["rule"]
        # skip not ML values like private keys and so on. Unsupported for ml train. "use_ml" rules ONLY
        assert 0 < len(cred["line_data_list"]), cred  # at least, one line_data_list must present
        line_data = deepcopy(cred["line_data_list"][0])
        line_data.pop("entropy_validation")
        line_data.pop("info")
        line_data["line"] = None  # will be read during join_label with data for ML input only
        meta_path = transform_to_meta_path(line_data["path"])
        line_data["path"] = meta_path
        line_data["RuleName"] = [rule_name]

        index = meta_path, line_data["line_num"], line_data["value_start"], line_data["value_end"]
        if index not in detected_lines:
            detected_lines[index] = line_data
        else:
            detected_lines[index]["RuleName"].append(rule_name)

    print(f"Detected {len(detected_lines)} unique lines!")
    print(f"{len(detections)} detections in total")

    return detected_lines


def read_metadata(meta_dir: str) -> Dict[identifier, Dict]:
    print(f"Reading meta from {meta_dir}")
    meta_lines = {}
    j = 0

    for file_path in os.listdir(meta_dir):
        csv_file = os.path.join(meta_dir, file_path)
        if not file_path.endswith(".csv"):
            print(f"skip garbage: {csv_file}")
            continue
        try:
            df = pd.read_csv(csv_file,
                             dtype={
                                 "RepoName": str,
                                 "GroundTruth": str,
                                 "Category": str,
                                 "LineStart": "Int64",
                                 "LineEnd": "Int64",
                                 "ValueStart": "Int64",
                                 "ValueEnd": "Int64",
                             })
        except Exception as exc:
            print(csv_file, exc)
            raise
        # Int64 is important to change with NaN
        df["LineStart"] = df["LineStart"].fillna(-1).astype(int)
        df["LineEnd"] = df["LineEnd"].fillna(-1).astype(int)
        df["ValueStart"] = df["ValueStart"].fillna(-1).astype(int)
        df["ValueEnd"] = df["ValueEnd"].fillna(-1).astype(int)
        # all templates are false
        df.loc[df["GroundTruth"] == "Template", "GroundTruth"] = 'F'
        for _, row in df.iterrows():
            j += 1
            if row["LineStart"] != row["LineEnd"] \
                    or all(x in ["AWS Multi", "Google Multi"] for x in row["Category"].split(':')):
                # print(f"WARNING: skip not ml category {row['FilePath']},{line_start},{line_end}"
                #      f",{row['GroundTruth']},{row['Category']}")
                continue
            assert 'F' == row["GroundTruth"] or 'T' == row["GroundTruth"] and 0 <= row["ValueStart"], row

            meta_path = transform_to_meta_path(row["FilePath"])
            index = meta_path, row['LineStart'], row['ValueStart'], row['ValueEnd']
            if index not in meta_lines:
                row_data = row.to_dict()
                row_data["Used"] = False
                row_data["FilePath"] = meta_path
                meta_lines[index] = row_data
            else:
                print(f"WARNING: {index} already in meta_lines {row['GroundTruth']} {row['Category']}"
                      f"\n{meta_lines[index]}")

    print(f"Loaded {len(meta_lines)} lines from meta of {j} total")

    return meta_lines


def get_colored_line(line_data: Dict[str, Any]) -> str:
    val_start = int(line_data['value_start'])
    val_end = int(line_data['value_end'])
    colored_line = line_data['line'][:val_start] \
                   + Fore.LIGHTYELLOW_EX \
                   + line_data['line'][val_start:val_end] \
                   + Style.RESET_ALL \
                   + line_data['line'][val_end:]

    with contextlib.suppress(Exception):
        var_start = int(line_data['variable_start'])
        var_end = int(line_data['variable_end'])
        if 0 <= var_start < var_end:
            colored_line = colored_line[:var_start] \
                           + Fore.LIGHTBLUE_EX \
                           + colored_line[var_start:var_end] \
                           + Style.RESET_ALL \
                           + colored_line[var_end:]

    colored_sub_line = Util.subtext(colored_line, line_data['value_start'], ML_HUNK)
    return f"{colored_sub_line}{Style.RESET_ALL}"


def join_label(detected_data: Dict[identifier, Dict], meta_data: Dict[identifier, Dict],
               cred_data_location: str) -> pd.DataFrame:

    @cache
    def read_text(path) -> list[str]:
        with open(path, "r", encoding="utf8") as f:
            return f.read().replace("\r\n", '\n').replace('\r', '\n').split('\n')

    positive_lines = set((x[0], x[1]) for x, y in meta_data.items() if 'T' == y["GroundTruth"])
    values = []
    detected_rules: Set[str] = set()
    for index, line_data in detected_data.items():
        for i in line_data["RuleName"]:
            detected_rules.add(i)
        text = read_text(f'{cred_data_location}/{line_data["path"]}')
        line = text[line_data["line_num"] - 1]
        line_data["line"] = line
        if not line_data["value"]:
            print(f"WARNING: empty value\n{line_data}")
            continue
        label = False
        if markup := meta_data.get(index):
            # it means index in meta_data with exactly match
            if 'T' == markup["GroundTruth"]:
                label = True
            markup["Used"] = True
            markup_rules = markup["Category"].split(':')
            if not set(markup_rules).intersection(set(line_data["RuleName"])):
                print(f"1.CHECK CATEGORIES\n{markup_rules}, {line_data['RuleName']}\n{str(markup)}" +
                      get_colored_line(line_data))
        elif markup := meta_data.get((index[0], index[1], index[2], -1)):
            # perhaps, the line has only start markup - so value end position is -1
            if 'T' == markup["GroundTruth"]:
                label = True
            markup["Used"] = True
            markup_rules = markup["Category"].split(':')
            if not set(markup["Category"].split(':')).intersection(set(line_data["RuleName"])):
                print(f"2.CHECK CATEGORIES\n{markup_rules}, {line_data['RuleName']}\n{str(markup)}" +
                      get_colored_line(line_data))
        elif markup := meta_data.get((index[0], index[1], -1, -1)):
            # perhaps, the line has false markup - so value start-end position is -1, -1
            if 'T' == markup["GroundTruth"]:
                raise RuntimeError(f"ERROR: markup {markup} cannot be TRUE\n{line_data}")
            markup["Used"] = True
            markup_rules = markup["Category"].split(':')
            if not set(markup["Category"].split(':')).intersection(set(line_data["RuleName"])):
                print(f"3.CHECK CATEGORIES\n{markup_rules}, {line_data['RuleName']}\n{str(markup)}" +
                      get_colored_line(line_data))
        elif (index[0], index[1]) in positive_lines:
            print(f"WARNING: {index} is not in meta!!! Skip due the line in positive dataset\n" +
                  get_colored_line(line_data))
            continue
        else:
            print(f"WARNING: {index} is not in meta!!! IT WILL BE USED AS NEGATIVE CASE\n" +
                  get_colored_line(line_data))
        # check the value in detected data
        assert line[line_data["value_start"]:line_data["value_end"]] == line_data["value"], (
            line_data, line[line_data["value_start"]:line_data["value_end"]], line_data["value"])
        # todo: variable input has to be markup in meta too, or/and new feature "VariableExists" created ???
        line_data["GroundTruth"] = label
        line_data["ext"] = Util.get_extension(line_data["path"])
        values.append(line_data)

    all_meta_found = True
    for markup in meta_data.values():
        if 'T' == markup["GroundTruth"] and not markup["Used"]:
            for markup_rule in markup["Category"].split(':'):
                if markup_rule in detected_rules:
                    if all_meta_found:
                        # print header of the markup once
                        print(f"{Back.MAGENTA}{Fore.BLACK}WARNING: Not all TRUE meta found!{Style.RESET_ALL}")
                        print(','.join(markup.keys()))
                        all_meta_found = False
                    print(','.join(str(x) for x in markup.values()))
                    text = read_text(f'{cred_data_location}/{markup["FilePath"]}')
                    line = text[markup["LineStart"] - 1]
                    if 0 <= markup["ValueStart"] and 0 <= markup["ValueEnd"]:
                        line = line[:markup["ValueStart"]] \
                               + Fore.LIGHTGREEN_EX \
                               + line[markup["ValueStart"]:markup["ValueEnd"]] \
                               + Style.RESET_ALL \
                               + line[markup["ValueEnd"]:]
                    elif 0 <= markup["ValueStart"]:
                        line = line[:markup["ValueStart"]] \
                               + Fore.LIGHTGREEN_EX \
                               + line[markup["ValueStart"]:] \
                               + Style.RESET_ALL
                    print(line)
                    break
    read_text.cache_clear()
    df = pd.DataFrame(values)
    return df


def get_y_labels(df: pd.DataFrame) -> np.ndarray:
    true_cases = np.array(df["GroundTruth"], dtype=np.float32)
    return true_cases
