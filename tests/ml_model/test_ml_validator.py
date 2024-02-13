import unittest

from credsweeper import ThresholdPreset
from credsweeper.app import APP_PATH
from credsweeper.config import Config
from credsweeper.credentials import Candidate
from credsweeper.ml_model import MlValidator
from credsweeper.utils import Util


class TestMlValidator(unittest.TestCase):
    def test_ml_validator_simple_p(self):
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
        candidate = Candidate.get_dummy_candidate(config, "main.py", ".py", "test_info")
        candidate.line_data_list[0].line = '"geheimnis" : "Jhd2gH5634"'
        candidate.line_data_list[0].variable = "geheimnis"
        candidate.line_data_list[0].value = "Jhd2gH5634"

        decision, probability = ml_validator.validate(candidate)
        self.assertAlmostEqual(probability, 0.9149, delta=0.0001)

        candidate.line_data_list[0].path = "sample.py"
        candidate.line_data_list[0].file_type = ".yaml"
        decision, probability = ml_validator.validate(candidate)
        self.assertAlmostEqual(probability, 0.6610, delta=0.0001)

        candidate.line_data_list[0].path = "test.zip"
        candidate.line_data_list[0].file_type = ".zip"
        decision, probability = ml_validator.validate(candidate)
        self.assertAlmostEqual(probability, 0.8482, delta=0.0001)

        candidate.line_data_list[0].path = "other.zip"
        candidate.line_data_list[0].file_type = ".py"
        decision, probability = ml_validator.validate(candidate)
        self.assertAlmostEqual(probability, 0.9149, delta=0.0001)
