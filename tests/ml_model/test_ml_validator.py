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
from tests import AZ_STRING


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
        self.assertAlmostEqual(probability, 0.9998799562454224, delta=0.0001)

        candidate.line_data_list[0].path = "sample.py"
        candidate.line_data_list[0].file_type = ".yaml"
        decision, probability = validate(candidate)
        self.assertAlmostEqual(probability, 0.9997391104698181, delta=0.0001)

        candidate.line_data_list[0].path = "test.zip"
        candidate.line_data_list[0].file_type = ".zip"
        decision, probability = validate(candidate)
        self.assertAlmostEqual(probability, 0.9996746778488159, delta=0.0001)

        candidate.line_data_list[0].path = "other.txt"
        candidate.line_data_list[0].file_type = ".txt"
        decision, probability = validate(candidate)
        self.assertAlmostEqual(probability, 0.9992635250091553, delta=0.0001)

    def test_extract_features_p(self):
        candidate1 = Candidate.get_dummy_candidate(self.config, "main.py", ".py", "info")
        candidate1.line_data_list[0].line = 'ABC123'
        candidate1.line_data_list[0].variable = "ABC"
        candidate1.line_data_list[0].value_start = 3
        candidate1.line_data_list[0].value_end = 6
        candidate1.line_data_list[0].value = "123"
        candidate1.rule_name = "Password"
        features1 = self.ml_validator.extract_features([candidate1])
        self.assertEqual(18, np.count_nonzero(features1))
        candidate2 = copy.deepcopy(candidate1)
        features2 = self.ml_validator.extract_features([candidate1, candidate2])
        self.assertEqual(18, np.count_nonzero(features2))
        candidate2.rule_name = "Secret"
        features3 = self.ml_validator.extract_features([candidate1, candidate2])
        self.assertEqual(19, np.count_nonzero(features3))
