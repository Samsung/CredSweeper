from typing import Tuple, Union

import numpy as np
import pandas as pd

from credsweeper.common.constants import Severity, ML_HUNK
from credsweeper.credentials import Candidate
from credsweeper.credentials import LineData
from credsweeper.ml_model import MlValidator
from credsweeper.utils import Util


class CustomLineData(LineData):
    """Object that allows to create LineData from scanner results"""

    def __init__(self, line: str, value: str, line_num: int, path: str, variable: str, value_start: int) -> None:
        self.line: str = line
        self.line_num: int = line_num
        self.path: str = path
        self.value = value
        self.file_type = Util.get_extension(path)
        self.variable = variable
        self.value_start = value_start


def get_candidates(line_data: dict):
    """Get list of candidates. 1 candidate for each rule that detected this line"""
    ld = CustomLineData(line_data["line"], line_data["value"], line_data["line_num"], line_data["path"],
                        line_data["variable"], line_data["value_start"])
    candidates = []
    for rule in line_data["RuleName"]:
        candidates.append(
            Candidate(
                line_data_list=[ld],
                patterns=[],
                rule_name=rule,
                severity=Severity.MEDIUM,
                use_ml=True,
            ))
    return candidates


def get_features(line_data: Union[dict, pd.Series],
                 ml_validator: MlValidator) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Get features from a single detection using CredSweeper.MlValidator module"""

    candidates = get_candidates(line_data)

    line_input = ml_validator.encode_line(line_data["line"], line_data["value_start"])
    if variable := line_data["variable"]:
        if len(variable) > ML_HUNK:
            variable = variable[:ML_HUNK]
        variable_input = ml_validator.encode_value(variable)
    else:
        variable_input = ml_validator.encode_value('')

    if value := line_data["value"]:
        if len(value) > ML_HUNK:
            value = value[:ML_HUNK]
        value_input = ml_validator.encode_value(value)
    else:
        raise RuntimeError(f"Empty value is not allowed {line_data}")

    line = line_data["line"]
    assert line[line_data["value_start"]:].startswith(line_data["value"]), line_data

    extracted_features = ml_validator.extract_features(candidates)

    return line_input, variable_input, value_input, extracted_features


def prepare_data(df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Get features from a DataFrame detection using CredSweeper.MlValidator module"""

    ml_validator = MlValidator(0.5)  # MLValidator object loads config (MAY be updated!) with features

    x_size = len(df)
    x_line_input = np.zeros(shape=[x_size, MlValidator.MAX_LEN, ml_validator.num_classes], dtype=np.float32)
    x_variable_input = np.zeros(shape=[x_size, ML_HUNK, ml_validator.num_classes], dtype=np.float32)
    x_value_input = np.zeros(shape=[x_size, ML_HUNK, ml_validator.num_classes], dtype=np.float32)
    # features size preprocess to calculate the dimension automatically
    features = get_features(  #
        line_data={  #
            "path": "",  #
            "line_num": 1,  #
            "line": "ABC123",  #
            "value": "123",  #
            "value_start": 3,  #
            "variable": None,  #
            "RuleName": ["API"],  #
        },  #
        ml_validator=ml_validator)
    features_size = features[3].shape[1]
    print(f"Features size: {features_size}", flush=True)
    x_features = np.zeros(shape=[x_size, features_size], dtype=np.float32)
    n = 0
    for i, row in df.iterrows():
        assert bool(row["line"]) and bool(row["value"]), row
        line_input, variable_input, value_input, extracted_features = get_features(row, ml_validator)
        x_line_input[n] = line_input
        x_variable_input[n] = variable_input
        x_value_input[n] = value_input
        x_features[n] = extracted_features
        n += 1
    return x_line_input, x_variable_input, x_value_input, x_features
