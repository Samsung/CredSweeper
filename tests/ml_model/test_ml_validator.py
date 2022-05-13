from credsweeper.ml_model import MlValidator


def test_ml_validator_simple_p():
    ml_validator = MlValidator(threshold=None)
    assert ml_validator is not None
