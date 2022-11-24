import base64
import json
import logging
import string
from typing import List, Optional, Any

import yaml

from credsweeper.common.constants import DEFAULT_ENCODING
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.utils import Util

logger = logging.getLogger(__name__)


class DataContentProvider(ContentProvider):
    """Dummy raw provider to keep bytes

    Parameters:
        data: byte sequence to be stored.
        file_path: optional string. Might be specified if you know true file name lines was taken from.

    """

    def __init__(
            self,  #
            data: bytes,  #
            file_path: Optional[str] = None,  #
            file_type: Optional[str] = None,  #
            info: Optional[str] = None) -> None:
        super().__init__(file_path=file_path, file_type=file_type, info=info)
        self.data = data
        self.structure: Optional[List[Any]] = None
        self.decoded: Optional[bytes] = None
        self.lines: List[str] = []
        self.line_numbers: List[int] = []

    @property
    def data(self) -> bytes:
        """data getter"""
        return self.__data

    @data.setter
    def data(self, data: bytes) -> None:
        """data setter"""
        self.__data = data

    def represent_as_structure(self) -> bool:
        """Tries to convert data with many parsers. Stores result to internal structure
        Return True if some structure found
        """
        try:
            text = self.data.decode(encoding='utf-8', errors='strict')
        except Exception:
            return False
        # # # Python
        try:
            if ";" in text or 2 < text.count("\n"):
                self.structure = Util.parse_python(text)
                logger.debug("CONVERTED from Python")
            else:
                logger.debug("Data do not contain line feed - weak PYTHON")
        except Exception as exc:
            logger.debug("Cannot parse as Python:%s %s", exc, self.data)
            self.structure = None
        if self.structure is not None and (isinstance(self.structure, dict) and 0 < len(self.structure.keys())
                                           or isinstance(self.structure, list) and 0 < len(self.structure)):
            return True
        # JSON
        try:
            if "{" in text:
                self.structure = json.loads(text)
                logger.debug("CONVERTED from json")
            else:
                logger.debug("Data do not contain { - weak JSON")
        except Exception as exc:
            logger.debug("Cannot parse as json:%s %s", exc, self.data)
            self.structure = None
        if self.structure is not None and (isinstance(self.structure, dict) and 0 < len(self.structure.keys())
                                           or isinstance(self.structure, list) and 0 < len(self.structure)):
            return True
        # # # YAML - almost always recognized
        try:
            if ":" in text and 2 < text.count("\n"):
                self.structure = yaml.load(text, Loader=yaml.FullLoader)
                logger.debug("CONVERTED from yaml")
            else:
                logger.debug("Data do not contain colon mark - weak YAML")
        except Exception as exc:
            logger.debug("Cannot parse as yaml:%s %s", exc, self.data)
            self.structure = None
        if self.structure is not None and (isinstance(self.structure, dict) and 0 < len(self.structure.keys())
                                           or isinstance(self.structure, list) and 0 < len(self.structure)):
            return True
        # # # None of above
        return False

    def represent_as_xml(self) -> bool:
        """Tries to read data as xml

        Return:
             True if reading was successful

        """
        try:
            xml_text = self.data.decode(encoding=DEFAULT_ENCODING).splitlines()
            self.lines, self.line_numbers = Util.get_xml_from_lines(xml_text)
        except Exception as exc:
            logger.debug("Cannot parse as XML:%s %s", exc, self.data)
            return False
        return bool(self.lines and self.line_numbers)

    def represent_as_encoded(self) -> bool:
        """Encodes data from base64. Stores result in decoded

        Return:
             True if the data correctly parsed and verified

        """
        if len(self.data) < 12 or (b"=" in self.data and b"=" != self.data[-1]):
            logger.debug("Weak data to decode from base64: %s", self.data)
        try:
            self.decoded = base64.b64decode(  #
                self.data.decode(encoding="ascii", errors="strict").  #
                translate(str.maketrans("", "", string.whitespace)),  #
                validate=True)  #
        except Exception as exc:
            logger.debug("Cannot decoded as base64:%s %s", exc, self.data)
            return False
        return self.decoded is not None and 0 < len(self.decoded)

    def get_analysis_target(self) -> List[AnalysisTarget]:
        """Return nothing. The class provides only data storage.

        Raise:
            NotImplementedError

        """
        raise NotImplementedError()
