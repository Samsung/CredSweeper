import hashlib
import os

from credsweeper.ml_model import MlValidator


def test_ml_validator_simple_p():
    ml_validator = MlValidator(threshold=None)
    assert ml_validator is not None


def test_ml_model_integrity_p():
    dir_path = os.path.dirname(os.path.realpath(__file__))
    model_file_path = os.path.join(dir_path, "..", "..", "credsweeper", "ml_model", "ml_model.onnx")
    assert os.path.exists(model_file_path)
    with open(model_file_path, "rb") as f:
        model_bin = f.read()
        assert len(model_bin) == 165415
        # calculated with external tool
        # 586526a2cd12dc84feca550535dab296604cfec56c0f9e32f6aae3d2c831eaa7  ml_model.onnx
        model_file_hash = hashlib.sha256(model_bin).hexdigest()
        assert model_file_hash == "586526a2cd12dc84feca550535dab296604cfec56c0f9e32f6aae3d2c831eaa7"
