from credsweeper.app import CredSweeper
from credsweeper.common.constants import ThresholdPreset, Severity, Confidence
from credsweeper.file_handler.byte_content_provider import ByteContentProvider
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.diff_content_provider import DiffContentProvider
from credsweeper.file_handler.files_provider import FilesProvider
from credsweeper.file_handler.patches_provider import PatchesProvider
from credsweeper.file_handler.string_content_provider import StringContentProvider
from credsweeper.file_handler.text_content_provider import TextContentProvider

from credsweeper.ml_model.ml_validator import MlValidator

__all__ = [
    "CredSweeper",  #
    "FilesProvider",  #
    "PatchesProvider",  #
    "ByteContentProvider",  # todo: remove from the export
    "Confidence",  #
    "ContentProvider",  # todo: remove from the export
    "DataContentProvider",  # todo: remove from the export
    "DiffContentProvider",  # todo: remove from the export
    "MlValidator",  #
    "Severity",  #
    "StringContentProvider",  # todo: remove from the export
    "TextContentProvider",  # todo: remove from the export
    "ThresholdPreset",  #
    "__version__"
]

__version__ = "1.19.5"
