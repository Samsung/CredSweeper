from credsweeper import ThresholdPreset
from credsweeper.app import APP_PATH


from credsweeper.config import Config
from credsweeper.credentials import Candidate
from credsweeper.ml_model import MlValidator
from credsweeper.utils import Util


def test_ml_validator_simple_p():
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
    candidate = Candidate.get_dummy_candidate(config, "test.py", ".py", "test_info")
    candidate.line_data_list[0].line = '"geheimnis" : "Jhd2gH5634"'
    candidate.line_data_list[0].variable = "geheimnis"
    candidate.line_data_list[0].value = "Jhd2gH5634"

    decision, probability = ml_validator.validate(candidate)
    assert 0.919577 < probability < 0.919578
    assert decision

    candidate.line_data_list[0].path = "test.yaml"
    candidate.line_data_list[0].file_type = ".yaml"
    decision, probability = ml_validator.validate(candidate)
    assert 0.240346 < probability < 0.240347
    assert not decision

    candidate.line_data_list[0].path = "test.zip"
    candidate.line_data_list[0].file_type = ".zip"
    decision, probability = ml_validator.validate(candidate)
    assert 0.51862 < probability < 0.51864
    assert not decision

    candidate.line_data_list[0].path = "test.zip bla bla bla"
    candidate.line_data_list[0].file_type = ".py"
    decision, probability = ml_validator.validate(candidate)
    assert 0.919577 < probability < 0.919578
    assert decision
