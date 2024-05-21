import logging
import os
import string
from typing import List, Tuple, Union

import numpy as np
import onnxruntime as ort

from credsweeper.common.constants import ThresholdPreset
from credsweeper.credentials import Candidate, CandidateKey
from credsweeper.ml_model import features
from credsweeper.utils import Util

logger = logging.getLogger(__name__)


class MlValidator:
    """ML validation class"""
    HALF_LEN = 80  # limit of variable or value size
    MAX_LEN = 2 * HALF_LEN  # for whole line limit
    NON_ASCII = '\xFF'
    CHAR_INDEX = {char: index for index, char in enumerate('\0' + string.printable + NON_ASCII)}
    NUM_CLASSES = len(CHAR_INDEX)

    def __init__(self, threshold: Union[float, ThresholdPreset], azure: bool = False, cuda: bool = False) -> None:
        """Init

        Args:
            threshold: decision threshold
        """
        dir_path = os.path.dirname(os.path.realpath(__file__))
        model_file_path = os.path.join(dir_path, "ml_model.onnx")
        if azure:
            provider = "AzureExecutionProvider"
        elif cuda:
            provider = "CUDAExecutionProvider"
        else:
            provider = "CPUExecutionProvider"
        self.model_session = ort.InferenceSession(model_file_path, providers=[provider])

        model_details = Util.json_load(os.path.join(dir_path, "model_config.json"))
        if isinstance(threshold, float):
            self.threshold = threshold
        elif isinstance(threshold, ThresholdPreset) and "thresholds" in model_details:
            self.threshold = model_details["thresholds"][threshold.value]
        else:
            self.threshold = 0.5

        self.common_feature_list = []
        self.unique_feature_list = []
        logger.info("Init ML validator, model file path: %s", model_file_path)
        logger.debug("ML validator details: %s", model_details)
        for feature_definition in model_details["features"]:
            feature_class = feature_definition["type"]
            kwargs = feature_definition.get("kwargs", {})
            feature_constructor = getattr(features, feature_class, None)
            if feature_constructor is None:
                raise ValueError(f'Error while parsing model details. Cannot create feature "{feature_class}"')
            try:
                feature = feature_constructor(**kwargs)
            except TypeError:
                raise TypeError(f'Error while parsing model details. Cannot create feature "{feature_class}"'
                                f' with kwargs "{kwargs}"')
            if feature_definition["type"] in ["RuleName"]:
                self.unique_feature_list.append(feature)
            else:
                self.common_feature_list.append(feature)

    @staticmethod
    def encode(text: str, limit: int) -> np.ndarray:
        """Encodes prepared text to array"""
        result_array = np.zeros(shape=(limit, MlValidator.NUM_CLASSES), dtype=np.float32)
        if text is None:
            return result_array
        len_text = len(text)
        if limit > len_text:
            # fill empty part
            text += '\0' * (limit - len_text)
        for i, c in enumerate(text):
            if c in MlValidator.CHAR_INDEX:
                result_array[i, MlValidator.CHAR_INDEX[c]] = 1
            else:
                result_array[i, MlValidator.CHAR_INDEX[MlValidator.NON_ASCII]] = 1
        return result_array

    @staticmethod
    def subtext(text: str, pos: int, hunk_size: int) -> str:
        """cut text symmetrically for given position or use remained quota to be fitted in 2x hunk_size"""
        left_quota = 0 if hunk_size <= pos else hunk_size - pos
        right_remain = len(text) - pos
        right_quota = 0 if hunk_size <= right_remain else right_remain - hunk_size
        left_pos = pos - hunk_size
        right_pos = pos + hunk_size
        if left_quota:
            left_pos += left_quota
            right_pos += left_quota
        if right_quota:
            left_pos += right_quota
            right_pos += right_quota
        return text[left_pos:right_pos]

    @staticmethod
    def encode_line(text: str, position: int):
        """Encodes line with balancing for position"""
        offset = len(text) - len(text.lstrip())
        pos = position - offset
        stripped = text.strip()
        if MlValidator.MAX_LEN < len(stripped):
            stripped = MlValidator.subtext(stripped, pos, MlValidator.HALF_LEN)
        return MlValidator.encode(stripped, MlValidator.MAX_LEN)

    @staticmethod
    def encode_value(text: str) -> np.ndarray:
        """Encodes line with balancing for position"""
        stripped = text.strip()
        return MlValidator.encode(stripped[:MlValidator.HALF_LEN], MlValidator.HALF_LEN)

    def _call_model(self, line_input: np.ndarray, variable_input: np.ndarray, value_input: np.ndarray,
                    feature_input: np.ndarray) -> np.ndarray:
        input_feed = {
            "line_input": line_input.astype(np.float32),
            "variable_input": variable_input.astype(np.float32),
            "value_input": value_input.astype(np.float32),
            "feature_input": feature_input.astype(np.float32),
        }
        result = self.model_session.run(output_names=None, input_feed=input_feed)
        if result and isinstance(result[0], np.ndarray):
            return result[0]
        raise RuntimeError(f"Unexpected type {type(result[0])}")

    def extract_common_features(self, candidates: List[Candidate]) -> np.ndarray:
        """Extract features that are guaranteed to be the same for all candidates on the same line with same value."""
        feature_array = np.array([], dtype=np.float32)
        # Extract features from credential candidate
        default_candidate = candidates[0]
        for feature in self.common_feature_list:
            new_feature = feature([default_candidate])[0]
            if not isinstance(new_feature, np.ndarray):
                new_feature = np.array([new_feature])
            feature_array = np.append(feature_array, new_feature)
        return feature_array

    def extract_unique_features(self, candidates: List[Candidate]) -> np.ndarray:
        """Extract features that can be different between candidates. Join them with or operator."""
        feature_array = np.array([], dtype=np.int8)
        default_candidate = candidates[0]
        for feature in self.unique_feature_list:
            new_feature = feature([default_candidate])[0]
            if not isinstance(new_feature, np.ndarray):
                new_feature = np.array([new_feature])
            feature_array = np.append(feature_array, new_feature)
        for candidate in candidates[1:]:
            for feature in self.unique_feature_list:
                new_feature = feature([candidate])[0]
                if not isinstance(new_feature, np.ndarray):
                    new_feature = np.array([new_feature])
                feature_array = feature_array | new_feature
        return feature_array

    def get_group_features(self, candidates: List[Candidate]) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """
        `np.newaxis` used to add new dimension if front, so input will be treated as a batch
        """
        # all candidates are from the same line
        default_candidate = candidates[0]
        line_input = MlValidator.encode_line(default_candidate.line_data_list[0].line,
                                             default_candidate.line_data_list[0].value_start)[np.newaxis]
        variable = ""
        value = ""
        for candidate in candidates:
            if not variable and candidate.line_data_list[0].variable:
                variable = candidate.line_data_list[0].variable
            if not value and candidate.line_data_list[0].value:
                value = candidate.line_data_list[0].value
            if variable and value:
                break
        variable_input = MlValidator.encode_value(variable)[np.newaxis]
        value_input = MlValidator.encode_value(value)[np.newaxis]
        feature_array = self.extract_features(candidates)
        return line_input, variable_input, value_input, feature_array

    def extract_features(self, candidates: List[Candidate]) -> np.ndarray:
        """extracts common and unique features from list of candidates"""
        common_features = self.extract_common_features(candidates)
        unique_features = self.extract_unique_features(candidates)
        feature_hstack = np.hstack([common_features, unique_features])
        feature_array = np.array([feature_hstack])
        return feature_array

    def _batch_call_model(self, line_input_list, variable_input_list, value_input_list, features_list) -> np.ndarray:
        """auxiliary method to invoke twice"""
        line_inputs_vstack = np.vstack(line_input_list)
        variable_inputs_vstack = np.vstack(variable_input_list)
        value_inputs_vstack = np.vstack(value_input_list)
        feature_array_vstack = np.vstack(features_list)
        result_call = self._call_model(line_inputs_vstack, variable_inputs_vstack, value_inputs_vstack,
                                       feature_array_vstack)
        result = result_call[:, 0]
        return result

    def validate_groups(self, group_list: List[Tuple[CandidateKey, List[Candidate]]],
                        batch_size: int) -> Tuple[np.ndarray, np.ndarray]:
        """Use ml model on list of candidate groups.

        Args:
            group_list: List of tuples (value, group)
            batch_size: ML model batch

        Return:
            Boolean numpy array with decision based on the threshold,
            and numpy array with probability predicted by the model

        """
        line_input_list = []
        variable_input_list = []
        value_input_list = []
        features_list = []
        probability = np.zeros(len(group_list), dtype=np.float32)
        head = tail = 0
        for group_key, candidates in group_list:
            line_input, variable_input, value_input, feature_array = self.get_group_features(candidates)
            line_input_list.append(line_input)
            variable_input_list.append(variable_input)
            value_input_list.append(value_input)
            features_list.append(feature_array)
            tail += 1
            if 0 == tail % batch_size:
                # use the approach to reduce memory consumption for huge candidates list
                probability[head:tail] = self._batch_call_model(line_input_list, variable_input_list, value_input_list,
                                                                features_list)
                head = tail
                line_input_list.clear()
                variable_input_list.clear()
                value_input_list.clear()
                features_list.clear()
        if head != tail:
            probability[head:tail] = self._batch_call_model(line_input_list, variable_input_list, value_input_list,
                                                            features_list)
        is_cred = probability > self.threshold
        for i in range(len(is_cred)):
            logger.debug("ML decision: %s with prediction: %s for value: %s", is_cred[i], round(probability[i], 8),
                         group_list[i][0])
        # apply cast to float to avoid json export issue
        return is_cred, probability.astype(float)
