import unittest
from typing import Tuple

from credsweeper import ThresholdPreset
from credsweeper.app import APP_PATH
from credsweeper.config import Config
from credsweeper.credentials import Candidate, CandidateKey
from credsweeper.ml_model import MlValidator
from credsweeper.utils import Util
from tests import AZ_STRING


class TestMlValidator(unittest.TestCase):

    def test_ml_validator_simple_p(self):
        def validate(ml_validator, candidate: Candidate) -> Tuple[bool, float]:
            """Validate single credential candidate."""
            candidate_key = CandidateKey(candidate.line_data_list[0])
            sample_as_batch = [(candidate_key, [candidate])]
            is_cred_batch, probability_batch = ml_validator.validate_groups(sample_as_batch, 1)
            return is_cred_batch[0], probability_batch[0]

        ml_validator = MlValidator(threshold=ThresholdPreset.medium)
        assert ml_validator is not None
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
        config = Config(config_dict)
        candidate = Candidate.get_dummy_candidate(config, "main.py", ".py", "info")
        candidate.rule_name = "Password"
        candidate.line_data_list[0].line = 'password="Ahga%$FiQ@Ei8"'
        candidate.line_data_list[0].variable = "password"
        candidate.line_data_list[0].value_start = 16
        candidate.line_data_list[0].value_end = 25
        candidate.line_data_list[0].value = "Ahga%$FiQ@Ei8"

        decision, probability = validate(ml_validator, candidate)
        self.assertAlmostEqual(probability, 0.9980274438858032, delta=0.0001)

        candidate.line_data_list[0].path = "sample.py"
        candidate.line_data_list[0].file_type = ".yaml"
        decision, probability = validate(ml_validator, candidate)
        self.assertAlmostEqual(probability, 0.9974609613418579, delta=0.0001)

        candidate.line_data_list[0].path = "test.zip"
        candidate.line_data_list[0].file_type = ".zip"
        decision, probability = validate(ml_validator, candidate)
        self.assertAlmostEqual(probability, 0.9963459372520447, delta=0.0001)

        candidate.line_data_list[0].path = "other.txt"
        candidate.line_data_list[0].file_type = ".txt"
        decision, probability = validate(ml_validator, candidate)
        self.assertAlmostEqual(probability, 0.9911893606185913, delta=0.0001)

    def test_subtext_n(self):
        self.assertEqual("", MlValidator.subtext("", 0, 0))

    def test_subtext_p(self):
        self.assertEqual("The quick ", MlValidator.subtext(AZ_STRING, 0, 5))
        self.assertEqual("The quick ", MlValidator.subtext(AZ_STRING, 3, 5))
        self.assertEqual(" fox jumps", MlValidator.subtext(AZ_STRING, 20, 5))
        self.assertEqual("e lazy dog", MlValidator.subtext(AZ_STRING, len(AZ_STRING) - 2, 5))
        self.assertEqual("the lazy dog", MlValidator.subtext(AZ_STRING, len(AZ_STRING) - 2, 6))

