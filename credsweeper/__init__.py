from pathlib import Path

from credsweeper.app import CredSweeper
from credsweeper.common.constants import ThresholdPreset
from credsweeper.file_handler import ContentProvider, ByteContentProvider, DiffContentProvider, StringContentProvider, \
    DataContentProvider, \
    TextContentProvider
from credsweeper.ml_model.ml_validator import MlValidator
from credsweeper.validations.apply_validation import ApplyValidation

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
    'CREDSWEEPER_DIR',  #
    '__version__'
]

CREDSWEEPER_DIR = Path(__file__).resolve().parent

__version__ = "1.4.3"
