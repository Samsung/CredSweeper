import json
import os
import pathlib
from copy import deepcopy
from typing import Tuple, Dict

import numpy as np
import pandas as pd

from credsweeper.utils import Util

# path, line, val_start, val_end
identifier = Tuple[str, int, int, int]


def transform_to_meta_path(file_path):
    """Transform any path to 'data/xxxxxxxx/[type]/yyyyyyyy.ext' to find in meta markup"""
    file_path = pathlib.Path(file_path).as_posix()
    path_list = file_path.split('/')
    meta_path = '/'.join(["data", path_list[-3], path_list[-2], path_list[-1]])
    return meta_path


def read_detected_data(file_path: str) -> Dict[identifier, Dict]:
    print(f"Reading detections from {file_path}")
    with open(file_path) as f:
        detections = json.load(f)

    detected_lines = {}

    for cred in detections:
        rule_name = cred["rule"]
        # skip not ML values like private keys and so on. Unsupported for ml train. "use_ml" rules ONLY
        assert 1 == len(cred["line_data_list"]), cred
        line_data = deepcopy(cred["line_data_list"][0])
        line_data.pop("entropy_validation")
        line_data.pop("info")
        line = line_data["line"].lstrip()
        offset = len(line_data["line"]) - len(line)
        line_data["line"] = line.rstrip()
        line_data["value_start"] -= offset
        line_data["value_end"] -= offset
        assert line_data["value"] == line_data["line"][line_data["value_start"]:line_data["value_end"]], line_data
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
        df = pd.read_csv(csv_file,
                         dtype={"RepoName": str,
                                "GroundTruth": str,
                                "Category": str,
                                "LineStart": "Int64",
                                "LineEnd": "Int64",
                                "ValueStart": "Int64",
                                "ValueEnd": "Int64",
                                })
        # Int64 is important to change with NaN
        df["LineStart"] = df["LineStart"].fillna(-1).astype(int)
        df["LineEnd"] = df["LineEnd"].fillna(-1).astype(int)
        df["ValueStart"] = df["ValueStart"].fillna(-1).astype(int)
        df["ValueEnd"] = df["ValueEnd"].fillna(-1).astype(int)
        # all templates are false
        df.loc[df["GroundTruth"] == "Template", "GroundTruth"] = 'F'
        for _, row in df.iterrows():
            j += 1
            if row["LineStart"] != row["LineEnd"] or any(
                    x in row["Category"] for x in ["AWS Multi", "Google Multi"]):
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


def join_label(detected_data: Dict[identifier, Dict], meta_data: Dict[identifier, Dict]) -> pd.DataFrame:
    values=[]

    # line_index_set: Set[Tuple[str, int]] = set()
    # rules_set: Set[str] = set()
    # reference_line_data = None
    for index, line_data in detected_data.items():
        if not line_data["value"]:
            print(f"WARNING: empty value\n{line_data}")
            continue
        label = False
        if markup := meta_data.get(index):
            # it means index in meta_data with exactly match
            if 'T' == markup["GroundTruth"]:
                label = True
                # dbg check
                # if set(markup["Category"].split(':')) != set(line_data["RuleName"]):
                #     print("a.CHECK CATEGORIES", set(markup["Category"].split(':')), set(line_data["RuleName"]),
                #           str(markup))
            markup["Used"] = True
            if not set(markup["Category"].split(':')).intersection(set(line_data["RuleName"])):
                print("1.CHECK CATEGORIES", set(markup["Category"].split(':')), set(line_data["RuleName"]),  str(markup))
        elif markup := meta_data.get((index[0], index[1], index[2], -1)):
            # perhaps, the line has only start markup - so value end position is -1
            if 'T' == markup["GroundTruth"]:
                label = True
                # dbg check
                # if set(markup["Category"].split(':')) != set(line_data["RuleName"]):
                #     print("b.CHECK CATEGORIES", set(markup["Category"].split(':')), set(line_data["RuleName"]),
                #           str(markup))
            markup["Used"] = True
            if not set(markup["Category"].split(':')).intersection(set(line_data["RuleName"])):
                print("2.CHECK CATEGORIES", set(markup["Category"].split(':')), set(line_data["RuleName"]), str(markup))
        elif markup := meta_data.get((index[0], index[1], -1, -1)):
            # perhaps, the line has false markup - so value start-end position is -1, -1
            if 'T' == markup["GroundTruth"]:
                raise RuntimeError(f"ERROR: markup {markup} cannot be TRUE\n{line_data}")
            markup["Used"] = True
            if not set(markup["Category"].split(':')).intersection(set(line_data["RuleName"])):
                print("3.CHECK CATEGORIES", set(markup["Category"].split(':')), set(line_data["RuleName"]), str(markup))
        else:
            print(f"WARNING: {index} is not in meta!!!\n{line_data}")
            continue

        line = line_data["line"]
        # the line in detected data mus be striped
        assert line == line.strip(), line_data
        # check the value in detected data
        assert line[line_data["value_start"]:line_data["value_end"]] == line_data["value"]
        # todo: variable input has to be markup in meta too, or/and new feature "VariableExists" created ???

        line_data["GroundTruth"] = label
        line_data["ext"] = Util.get_extension(line_data["path"])
        line_data["type"] = line_data["path"].split('/')[-2]

        # line_index_set.add((index[0], index[1]))
        # rules_set.update(line_data["RuleName"])
        # if not reference_line_data:
        #     reference_line_data = copy.deepcopy(line_data)

        # remove to reduce memory usage
        # line_data.pop("line_num")
        # line_data.pop("path")
        # line_data.pop("value_end")

        values .append(line_data)

    # for _, i in meta_data.items():
    #     if i["Used"] is True:
    #         continue
    #     elif i["GroundTruth"] == 'T' \
    #             and any(x in rules_set for x in i["Category"].split(':')) \
    #             and (i["FilePath"], i["LineStart"]) in line_index_set \
    #             and 0 <= i["ValueStart"] < i["ValueEnd"]:
    #         print(f"NOT FOUND:{i}")
    #         markup_data = {
    #             "line": None,  # read
    #             "line_num": i["LineStart"], # not used
    #             "path": i["FilePath"],
    #             "value": None,
    #             "value_start": i["ValueStart"],  # remove
    #             "value_end": i["ValueEnd"],  # remove
    #             "variable": None,  # ???
    #             'RuleName': (x for x in i["Category"].split(':') if x in line_index_set),
    #             'GroundTruth': 'T',
    #             'ext': Util.get_extension(i["FilePath"]),
    #             'type': i["FilePath"].split('/')[-2]
    #         }
    #         assert markup_data.keys() == reference_line_data.keys(), reference_line_data.keys()

    df = pd.DataFrame(values)
    return df


def get_y_labels(df: pd.DataFrame) -> np.ndarray:
    true_cases = np.array(df["GroundTruth"], dtype=np.float32)
    return true_cases
