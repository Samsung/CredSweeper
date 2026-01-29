import hashlib
import json
import logging
from pathlib import Path
from typing import List, Tuple, Union, Optional, Dict

import numpy as np
from onnxruntime import InferenceSession

import credsweeper.ml_model.features as features
from credsweeper.common.constants import ThresholdPreset, ML_HUNK
from credsweeper.credentials.candidate import Candidate
from credsweeper.credentials.candidate_key import CandidateKey
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class MlValidator:
    """ML validation class"""
    MAX_LEN = 2 * ML_HUNK  # for whole line limit
    # used for initial fill
    ZERO_CHAR = '\x00'
    # applied for unknown characters
    FAKE_CHAR = '\x01'

    _dir_path = Path(__file__).parent

    def __init__(
            self,  #
            threshold: Union[float, ThresholdPreset],  #
            ml_config: Union[None, str, Path] = None,  #
            ml_model: Union[None, str, Path] = None,  #
            ml_providers: Optional[str] = None) -> None:
        """Init

        Args:
            threshold: decision threshold
            ml_config: path to ml config
            ml_model: path to ml model
            ml_providers: coma separated list of providers https://onnxruntime.ai/docs/execution-providers/
        """
        self.__session: Optional[InferenceSession] = None

        if ml_config:
            ml_config_path = Path(ml_config)
        else:
            ml_config_path = MlValidator._dir_path / "ml_config.json"
        with open(ml_config_path, "rb") as f:
            __ml_config_data = f.read()

        model_config = json.loads(__ml_config_data)

        if ml_model:
            ml_model_path = Path(ml_model)
        else:
            ml_model_path = MlValidator._dir_path / "ml_model.onnx"
        with open(ml_model_path, "rb") as f:
            self.__ml_model_data = f.read()

        if ml_providers:
            self.providers = ml_providers.split(',')
        else:
            self.providers = ["CPUExecutionProvider"]

        if isinstance(threshold, float):
            self.threshold = threshold
        elif isinstance(threshold, ThresholdPreset) and "thresholds" in model_config:
            self.threshold = model_config["thresholds"][threshold.value]
        else:
            self.threshold = 0.5
            logger.warning(f"Use fallback threshold value: {self.threshold}")

        char_set = set(model_config["char_set"])
        if len(char_set) != len(model_config["char_set"]):
            logger.warning('Duplicated symbols in "char_set"?')
        if self.ZERO_CHAR in char_set or self.FAKE_CHAR in char_set:
            raise ValueError(f'Unacceptable symbols 0x00 or 0x01 in "char_set"={char_set}')
        self.char_dict = {self.ZERO_CHAR: 0, self.FAKE_CHAR: 1}
        self.char_dict.update({
            char: index
            for index, char in enumerate(sorted(list(char_set)), start=len(self.char_dict))
        })
        self.num_classes = len(self.char_dict)

        self.common_feature_list = []
        self.unique_feature_list = []
        if logger.isEnabledFor(logging.INFO):
            config_md5 = hashlib.md5(__ml_config_data).hexdigest()
            model_md5 = hashlib.md5(self.__ml_model_data).hexdigest()
            logger.info("Init ML validator with providers: '%s' ; model:'%s' md5:%s ; config:'%s' md5:%s",
                        self.providers, ml_config_path, config_md5, ml_model_path, model_md5)
            logger.debug(str(model_config))
        for feature_definition in model_config["features"]:
            feature_class = feature_definition["type"]
            kwargs = feature_definition.get("kwargs", {})
            feature_constructor = getattr(features, feature_class, None)
            if feature_constructor is None:
                raise ValueError(f"Error while parsing model details. Cannot create feature '{feature_class}'"
                                 f" from {feature_definition}")
            try:
                feature = feature_constructor(**kwargs)
            except TypeError:
                logger.error(f"Error while parsing model details. Cannot create feature '{feature_class}'"
                             f" from {feature_definition}")
                raise
            if feature_definition["type"] in ["RuleName"]:
                self.unique_feature_list.append(feature)
            else:
                self.common_feature_list.append(feature)

    def __reduce__(self):
        # TypeError: cannot pickle 'onnxruntime.capi.onnxruntime_pybind11_state.InferenceSession' object
        self.__session = None
        return super().__reduce__()

    @property
    def session(self) -> InferenceSession:
        """session getter to prevent pickle error"""
        if not self.__session:
            self.__session = InferenceSession(self.__ml_model_data, providers=self.providers)
        if not self.__session:
            raise RuntimeError("InferenceSession was not initialized!")
        return self.__session

    def encode(self, text: str, limit: int) -> np.ndarray:
        """Encodes prepared text to array"""
        result_array: np.ndarray = np.zeros(shape=(limit, self.num_classes), dtype=np.float32)
        if text is None:
            return result_array
        for i, c in enumerate(text):
            if i >= limit:
                break
            if c in self.char_dict:
                result_array[i, self.char_dict[c]] = 1.0
            else:
                result_array[i, self.char_dict[MlValidator.FAKE_CHAR]] = 1.0
        return result_array

    def encode_line(self, text: str, position: int):
        """Encodes line with balancing for position"""
        offset = len(text) - len(text.lstrip())
        pos = position - offset
        stripped = text.strip()
        if MlValidator.MAX_LEN < len(stripped):
            stripped = Util.subtext(stripped, pos, ML_HUNK)
        return self.encode(stripped, MlValidator.MAX_LEN)

    def encode_value(self, text: str) -> np.ndarray:
        """Encodes line with balancing for position"""
        stripped = text.strip()
        return self.encode(stripped[:ML_HUNK], ML_HUNK)

    def _call_model(self, line_input: np.ndarray, variable_input: np.ndarray, value_input: np.ndarray,
                    feature_input: np.ndarray) -> np.ndarray:
        input_feed: Dict[str, np.ndarray] = {
            "line_input": line_input.astype(np.float32),
            "variable_input": variable_input.astype(np.float32),
            "value_input": value_input.astype(np.float32),
            "feature_input": feature_input.astype(np.float32),
        }
        result = self.session.run(output_names=None, input_feed=input_feed)
        if result and isinstance(result[0], np.ndarray):
            return result[0]
        raise RuntimeError(f"Unexpected type {type(result[0])}")

    def extract_common_features(self, candidates: List[Candidate]) -> np.ndarray:
        """Extract features that are guaranteed to be the same for all candidates on the same line with same value."""
        feature_array: np.ndarray = np.array([], dtype=np.float32)
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
        feature_array: np.ndarray = np.array([], dtype=np.int8)
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
        line_input = self.encode_line(default_candidate.line_data_list[0].line,
                                      default_candidate.line_data_list[0].value_start)[np.newaxis]
        variable = ''
        value = ''
        for candidate in candidates:
            if not variable and candidate.line_data_list[0].variable:
                variable = candidate.line_data_list[0].variable
            if not value and candidate.line_data_list[0].value:
                value = candidate.line_data_list[0].value
            if variable and value:
                break
        variable_input = self.encode_value(variable)[np.newaxis]
        value_input = self.encode_value(value)[np.newaxis]
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
        probability: np.ndarray = np.zeros(len(group_list), dtype=np.float32)
        head = tail = 0
        for _group_key, candidates in group_list:
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
        is_cred = self.threshold <= probability
        if logger.isEnabledFor(logging.DEBUG):
            for i, decision in enumerate(is_cred):
                logger.debug("ML decision: %s with prediction: %s for value: %s", decision, probability[i],
                             group_list[i][0])
        # apply cast to float to avoid json export issue
        return is_cred, probability.astype(float)
