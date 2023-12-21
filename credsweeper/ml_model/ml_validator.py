import logging
import os
import string
from typing import List, Tuple, Union, Any

import numpy as np
import onnxruntime as ort

from credsweeper.common.constants import ThresholdPreset
from credsweeper.credentials import Candidate
from credsweeper.ml_model import features
from credsweeper.utils import Util

logger = logging.getLogger(__name__)


class MlValidator:
    """ML validation class"""

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
        char_filtered = string.ascii_lowercase + string.digits + string.punctuation

        self.char_to_index = {char: index + 1 for index, char in enumerate(char_filtered)}
        self.char_to_index['NON_ASCII'] = len(self.char_to_index) + 1

        model_details = Util.json_load(os.path.join(dir_path, "model_config.json"))
        if isinstance(threshold, float):
            self.threshold = threshold
        elif isinstance(threshold, ThresholdPreset) and "thresholds" in model_details:
            self.threshold = model_details["thresholds"][threshold.value]
        else:
            self.threshold = 0.5
        self.maxlen = int(model_details.get("max_len", 50))
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
                raise TypeError(
                    f'Error while parsing model details. Cannot create feature "{feature_class}" with kwargs "{kwargs}"'
                )
            if feature_definition["type"] in ["RuleName"]:
                self.unique_feature_list.append(feature)
            else:
                self.common_feature_list.append(feature)

    def encode(self, line, char_to_index) -> np.ndarray:
        """Encodes line to array"""
        num_classes = len(char_to_index) + 1
        result_array = np.zeros((self.maxlen, num_classes))
        line = line.strip().lower()[-self.maxlen:]
        for i in range(self.maxlen):
            if i < len(line):
                c = line[i]
                if c in char_to_index:
                    result_array[i, char_to_index[c]] = 1
                else:
                    result_array[i, char_to_index["NON_ASCII"]] = 1
            else:
                result_array[i, 0] = 1
        return result_array

    def _call_model(self, line_input: np.ndarray, feature_input: np.ndarray) -> Any:
        line_input = line_input.astype(np.float32)
        feature_input = feature_input.astype(np.float32)
        return self.model_session.run(None, {"line_input": line_input, "feature_input": feature_input})[0]

    def extract_common_features(self, candidates: List[Candidate]) -> np.ndarray:
        """Extract features that are guaranteed to be the same for all candidates on the same line with same value."""
        feature_array = np.array([], dtype=float)
        # Extract features from credential candidate
        default_candidate = candidates[0]
        for feature in self.common_feature_list:
            new_feature = feature([default_candidate])[0]
            if not isinstance(new_feature, np.ndarray):
                new_feature = np.array([new_feature])
            feature_array = np.append(feature_array, new_feature)
        return feature_array

    def extract_unique_features(self, candidates: List[Candidate]) -> np.ndarray:
        """Extract features that can by different between candidates. Join them with or operator."""
        feature_array = np.array([], dtype=bool)
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

    def validate(self, candidate: Candidate) -> Tuple[bool, float]:
        """Validate single credential candidate."""
        sample_as_batch = [(candidate.line_data_list[0].value, [candidate])]
        is_cred_batch, probability_batch = self.validate_groups(sample_as_batch, 1)
        return is_cred_batch[0], probability_batch[0]

    def get_group_features(self, value: str, candidates: List[Candidate]) -> Tuple[np.ndarray, np.ndarray]:
        """
        `np.newaxis` used to add new dimension if front, so input will be treated as a batch
        """
        line_input = self.encode(value, self.char_to_index)[np.newaxis]

        common_features = self.extract_common_features(candidates)
        unique_features = self.extract_unique_features(candidates)
        feature_array = np.hstack([common_features, unique_features])
        feature_array = np.array([feature_array])
        return line_input, feature_array

    def _batch_call_model(self, line_inputs, feature_array_list):
        """auxiliary method to invoke twice"""
        line_inputs_stack = np.vstack(line_inputs)
        feature_array_vstack = np.vstack(feature_array_list)
        return self._call_model(line_inputs_stack, feature_array_vstack)[:, 0]

    def validate_groups(self, group_list: List[Tuple[str, List[Candidate]]],
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
        features_list = []
        probability = np.zeros(len(group_list))
        head = tail = 0
        for (value, candidates) in group_list:
            line_input, feature_array = self.get_group_features(value, candidates)
            line_input_list.append(line_input)
            features_list.append(feature_array)
            tail += 1
            if 0 == tail % batch_size:
                # use the approach to reduce memory consumption for huge candidates list
                probability[head:tail] = self._batch_call_model(line_input_list, features_list)
                head = tail
                line_input_list.clear()
                features_list.clear()
        if head != tail:
            probability[head:tail] = self._batch_call_model(line_input_list, features_list)
        is_cred = probability > self.threshold
        for i in range(len(is_cred)):
            logger.debug("ML decision: %s with prediction: %s for value: %s", is_cred[i], round(probability[i], 3),
                         group_list[i][0])
        return is_cred, probability
