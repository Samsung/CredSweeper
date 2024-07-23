import copy
import unittest
from typing import Tuple

import numpy as np

from credsweeper import ThresholdPreset
from credsweeper.app import APP_PATH
from credsweeper.config import Config
from credsweeper.credentials import Candidate, CandidateKey
from credsweeper.ml_model import MlValidator
from credsweeper.utils import Util
from tests import NEGLIGIBLE_ML_THRESHOLD


class TestMlValidator(unittest.TestCase):

    def setUp(self):
        self.ml_validator = MlValidator(threshold=ThresholdPreset.medium)
        assert self.ml_validator is not None
        file_name = APP_PATH / "secret" / "config.json"
        config_dict = Util.json_load(file_name)
        config_dict["validation"] = {}
        config_dict["validation"]["api_validation"] = False
        config_dict["use_filters"] = True
        config_dict["find_by_ext"] = False
        config_dict["depth"] = 0
        config_dict["doc"] = False
        config_dict["find_by_ext_list"] = []
        config_dict["size_limit"] = None
        self.config = Config(config_dict)

    def test_ml_validator_simple_p(self):
        def validate(_candidate: Candidate) -> Tuple[bool, float]:
            """Validate single credential candidate."""
            candidate_key = CandidateKey(_candidate.line_data_list[0])
            sample_as_batch = [(candidate_key, [_candidate])]
            is_cred_batch, probability_batch = self.ml_validator.validate_groups(sample_as_batch, 1)
            return is_cred_batch[0], probability_batch[0]

        candidate = Candidate.get_dummy_candidate(self.config, "main.py", ".py", "info")
        candidate.rule_name = "Password"
        candidate.line_data_list[0].line = 'password="Ahga%$FiQ@Ei8"'
        candidate.line_data_list[0].variable = "password"
        candidate.line_data_list[0].value_start = 16
        candidate.line_data_list[0].value_end = 25
        candidate.line_data_list[0].value = "Ahga%$FiQ@Ei8"

        decision, probability = validate(candidate)
        self.assertAlmostEqual(0.9997520446777344, probability, delta=NEGLIGIBLE_ML_THRESHOLD)

        candidate.line_data_list[0].path = "sample.py"
        candidate.line_data_list[0].file_type = ".yaml"
        decision, probability = validate(candidate)
        self.assertAlmostEqual(0.9994515776634216, probability, delta=NEGLIGIBLE_ML_THRESHOLD)

        candidate.line_data_list[0].path = "test.zip"
        candidate.line_data_list[0].file_type = ".zip"
        decision, probability = validate(candidate)
        self.assertAlmostEqual(0.9994281530380249, probability, delta=NEGLIGIBLE_ML_THRESHOLD)

        candidate.line_data_list[0].path = "other.txt"
        candidate.line_data_list[0].file_type = ".txt"
        decision, probability = validate(candidate)
        self.assertAlmostEqual(0.9980608820915222, probability, delta=NEGLIGIBLE_ML_THRESHOLD)

    def test_extract_features_p(self):
        candidate1 = Candidate.get_dummy_candidate(self.config, "main.py", ".py", "info")
        candidate1.line_data_list[0].line = 'ABC123'
        candidate1.line_data_list[0].variable = "ABC"
        candidate1.line_data_list[0].value_start = 3
        candidate1.line_data_list[0].value_end = 6
        candidate1.line_data_list[0].value = "123"
        candidate1.rule_name = "Password"
        features1 = self.ml_validator.extract_features([candidate1])
        self.assertAlmostEqual(18, np.count_nonzero(features1), delta=NEGLIGIBLE_ML_THRESHOLD)
        candidate2 = copy.deepcopy(candidate1)
        features2 = self.ml_validator.extract_features([candidate1, candidate2])
        self.assertAlmostEqual(18, np.count_nonzero(features2), delta=NEGLIGIBLE_ML_THRESHOLD)
        candidate2.rule_name = "Secret"
        features3 = self.ml_validator.extract_features([candidate1, candidate2])
        self.assertAlmostEqual(19, np.count_nonzero(features3), delta=NEGLIGIBLE_ML_THRESHOLD)
