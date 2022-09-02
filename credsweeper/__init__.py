import os
import re

from credsweeper.app import CredSweeper
from credsweeper.common.constants import ThresholdPreset
from credsweeper.file_handler import ContentProvider, ByteContentProvider, DiffContentProvider, StringContentProvider, \
    DataContentProvider, \
    TextContentProvider
from credsweeper.ml_model.ml_validator import MlValidator
from credsweeper.validations.apply_validation import ApplyValidation

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"

__all__ = [
    'ApplyValidation',  #
    'ByteContentProvider',  #
    'ContentProvider',  #
    'CredSweeper',  #
    'DataContentProvider',  #
    'DiffContentProvider',  #
    'MlValidator',  #
    'StringContentProvider',  #
    'TextContentProvider',  #
    'ThresholdPreset',  #
    '__version__'
]

__git_hash = ""
try:
    import subprocess

    _stdout, _stderr = subprocess.Popen(
        ["git", "rev-parse", "--short", "HEAD"],  #
        stdout=subprocess.PIPE,  #
        stderr=subprocess.PIPE).communicate()
    _hash = _stdout.decode(encoding="ascii", errors="ignore").strip()
    if 0 == len(_stderr) and re.match("[0-9a-fA-F]{4,40}", _hash):
        __git_hash = "." + _hash
        _stdout, _stderr = subprocess.Popen(
            ["git", "status", "--short"],  #
            stdout=subprocess.PIPE,  #
            stderr=subprocess.PIPE).communicate()
        if 0 != len(_stdout):
            __git_hash += "~"
except Exception as exc:
    pass
__version__ = f"1.4.2{__git_hash}"
