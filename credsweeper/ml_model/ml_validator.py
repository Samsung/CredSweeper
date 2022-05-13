import json
import os
import pathlib
import string
from typing import List, Tuple, Optional

from credsweeper.common.constants import ThresholdPreset, DEFAULT_ENCODING
from credsweeper.credentials import Candidate
from credsweeper.logger.logger import logging

ML_VALIDATOR_IMPORT_ERROR = "Start importing"
try:
    import numpy as np
    import onnxruntime as ort
    ML_VALIDATOR_IMPORT_ERROR = None
except ModuleNotFoundError as e:
    ML_VALIDATOR_IMPORT_ERROR = "The ML Validation function cannot be used without additional ML packages.\n" \
                                f"{e.msg}\n" \
                                "Run `pip install credsweeper[ml]` to fix it."


class MlValidator:

    @classmethod
    def __init__(cls, threshold: Optional[Tuple[float, ThresholdPreset]]) -> None:
        if ML_VALIDATOR_IMPORT_ERROR:
            raise ModuleNotFoundError(ML_VALIDATOR_IMPORT_ERROR)
        dir_path = os.path.dirname(os.path.realpath(__file__))
        model_file_path = os.path.join(dir_path, "ml_model.onnx")
        index_file_path = os.path.join(dir_path, "char_to_index.pkl")
        cls.model_session = ort.InferenceSession(model_file_path)
        char_filtered = string.ascii_lowercase + string.digits + string.punctuation
        cls.char_to_index = {char: index + 1 for index, char in enumerate(char_filtered)}
        cls.char_to_index['NON_ASCII'] = len(cls.char_to_index) + 1

        model_detail_path = f"{pathlib.Path(__file__).parent.absolute()}/model_config.json"
        with open(model_detail_path, encoding=DEFAULT_ENCODING) as f:
            model_details = json.load(f)
        if isinstance(threshold, float):
            cls.threshold = threshold
        elif isinstance(threshold, ThresholdPreset) and "thresholds" in model_details:
            cls.threshold = model_details["thresholds"][threshold.value]
        else:
            cls.threshold = 0.5
        cls.maxlen = model_details.get("max_len", 50)
        cls.common_feature_list = []
        cls.unique_feature_list = []
        logging.info(f'Init ML validator, model file path: {model_file_path} \tindex file path: {index_file_path}')
        logging.debug(f'ML validator details: {model_details}')
        from credsweeper.ml_model import features
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
                cls.unique_feature_list.append(feature)
            else:
                cls.common_feature_list.append(feature)

    @classmethod
    def encode(cls, line, char_to_index) -> 'np.ndarray':
        num_classes = len(char_to_index) + 1
        result_array = np.zeros((cls.maxlen, num_classes))
        line = line.strip().lower()[-cls.maxlen:]
        for i in range(cls.maxlen):
            if i < len(line):
                c = line[i]
                if c in char_to_index:
                    result_array[i, char_to_index[c]] = 1
                else:
                    result_array[i, char_to_index["NON_ASCII"]] = 1
            else:
                result_array[i, 0] = 1
        return result_array

    @classmethod
    def _call_model(cls, line_input: 'np.ndarray', feature_input: 'np.ndarray') -> 'np.ndarray':
        line_input = line_input.astype(np.float32)
        feature_input = feature_input.astype(np.float32)
        return cls.model_session.run(None, {"line_input": line_input, "feature_input": feature_input})[0]

    @classmethod
    def extract_common_features(cls, candidates: List[Candidate]) -> 'np.ndarray':
        """Extract features that are guaranteed to be the same for all candidates on the same line with same value."""
        feature_array = np.array([], dtype=float)
        # Extract features from credential candidate
        default_candidate = candidates[0]
        for feature in cls.common_feature_list:
            new_feature = feature([default_candidate])[0]
            if not isinstance(new_feature, np.ndarray):
                new_feature = np.array([new_feature])
            feature_array = np.append(feature_array, new_feature)
        return feature_array

    @classmethod
    def extract_unique_features(cls, candidates: List[Candidate]) -> 'np.ndarray':
        """Extract features that can by different between candidates. Join them with or operator."""
        feature_array = np.array([], dtype=bool)
        default_candidate = candidates[0]
        for feature in cls.unique_feature_list:
            new_feature = feature([default_candidate])[0]
            if not isinstance(new_feature, np.ndarray):
                new_feature = np.array([new_feature])
            feature_array = np.append(feature_array, new_feature)
        for candidate in candidates[1:]:
            for feature in cls.unique_feature_list:
                new_feature = feature([candidate])[0]
                if not isinstance(new_feature, np.ndarray):
                    new_feature = np.array([new_feature])
                feature_array = feature_array | new_feature
        return feature_array

    @classmethod
    def validate(cls, candidate: Candidate) -> Tuple[bool, float]:
        """Validate single credential candidate."""
        sample_as_batch = [(candidate.line_data_list[0].value, [candidate])]
        is_cred_batch, probability_batch = cls.validate_groups(sample_as_batch, 1)
        return is_cred_batch[0], probability_batch[0]

    @classmethod
    def get_group_features(cls, value: str, candidates: List[Candidate]) -> Tuple['np.ndarray', 'np.ndarray']:
        # `np.newaxis` used to add new dimension if front, so input will be treated as a batch
        line_input = cls.encode(value, cls.char_to_index)[np.newaxis]

        common_features = cls.extract_common_features(candidates)
        unique_features = cls.extract_unique_features(candidates)
        feature_array = np.hstack([common_features, unique_features])
        feature_array = np.array([feature_array])
        return line_input, feature_array

    @classmethod
    def validate_groups(cls, group_list: List[Tuple[str, List[Candidate]]],
                        batch_size: int) -> Tuple['np.ndarray', 'np.ndarray']:
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
        for (value, candidates) in group_list:
            line_input, feature_array = cls.get_group_features(value, candidates)
            line_input_list.append(line_input)
            features_list.append(feature_array)

        probability = np.zeros(len(features_list))
        for i in range(0, len(features_list), batch_size):
            line_inputs = line_input_list[i:i + batch_size]
            line_inputs = np.vstack(line_inputs)
            feature_array = features_list[i:i + batch_size]
            feature_array = np.vstack(feature_array)
            probability[i:i + batch_size] = cls._call_model(line_inputs, feature_array)[:, 0]
        is_cred = probability > cls.threshold
        for i in range(len(is_cred)):
            logging.debug(
                f"ML decision: {is_cred[i]} with prediction: {round(probability[i], 3)} for value: {group_list[i][0]}")
        return is_cred, probability
