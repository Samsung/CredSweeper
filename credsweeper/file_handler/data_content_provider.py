import json
import logging
import warnings
from functools import cached_property
from typing import List, Optional, Any, Generator

import yaml
from bs4 import XMLParsedAsHTMLWarning

from credsweeper.common.constants import MIN_DATA_LEN
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.logger import TRACE
from credsweeper.utils.util import Util

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning, module='bs4')
logger = logging.getLogger(__name__)

# <t>12345678</t> - minimal xml with a credential
MIN_XML_LEN = 16


class DataContentProvider(ContentProvider):
    """Dummy raw provider to keep bytes"""

    def __init__(
            self,  #
            data: bytes,  #
            file_path: Optional[str] = None,  #
            file_type: Optional[str] = None,  #
            info: Optional[str] = None) -> None:
        """
        Parameters:
            data: byte sequence to be stored for deep analysis

        """
        super().__init__(file_path=file_path, file_type=file_type, info=info)
        self.__data = data
        self.__text: Optional[str] = None
        self.structure: Optional[List[Any]] = None
        self.decoded: Optional[bytes] = None
        self.lines: List[str] = []
        self.line_numbers: List[int] = []

    @cached_property
    def data(self) -> Optional[bytes]:
        """data RO getter for DataContentProvider and the property is used in deep scan"""
        return self.__data

    def free(self) -> None:
        """free data after scan to reduce memory usage"""
        self.__data = None
        if "data" in self.__dict__:
            delattr(self, "data")
        self.__text = None
        if "text" in self.__dict__:
            delattr(self, "text")
        self.structure = None
        self.decoded = None
        self.lines = []
        self.line_numbers = []

    @cached_property
    def text(self) -> str:
        """Getter to produce a text from DEFAULT_ENCODING. Empty str for unrecognized data"""
        if self.__text is None:
            self.__text = Util.decode_text(self.__data) or ''
        return self.__text

    def __is_structure(self) -> bool:
        """Check whether a structure was recognized"""
        return self.structure is not None and (isinstance(self.structure, dict) and 0 < len(self.structure.keys())
                                               or isinstance(self.structure, list) and 0 < len(self.structure))

    def represent_as_structure(self) -> Optional[bool]:
        """Tries to convert data with many parsers. Stores result to internal structure

        Return:
             True if some structure found
             False if no data found
             None if the format is not acceptable

        """
        if MIN_DATA_LEN > len(self.text):
            return False
        # JSON & NDJSON
        if '{' in self.text and '}' in self.text and '"' in self.text and ':' in self.text:
            try:
                self.structure = json.loads(self.text)
                logger.log(TRACE, "CONVERTED from json")
            except Exception as exc:  # pylint: disable=broad-exception-caught
                # fallback
                logger.log(TRACE, "Cannot parse as json %s:%s %s", type(exc), exc, self.descriptor)
            else:
                if self.__is_structure():
                    return True
            try:
                self.structure = []
                for line in self.text.splitlines():
                    # each line must be in json format, otherwise - exception rises
                    self.structure.append(json.loads(line))
                logger.log(TRACE, "CONVERTED from ndjson")
            except Exception as exc:  # pylint: disable=broad-exception-caught
                # fallback
                logger.log(TRACE, "Cannot parse as ndjson %s:%s %s", type(exc), exc, self.descriptor)
                self.structure = None
            else:
                if self.__is_structure():
                    return True
        else:
            logger.log(TRACE, "Data do not contain { - weak JSON")

        # # # Python
        try:
            # search only in sources with strings
            if (';' in self.text or 2 < self.text.count('\n') or 2 < self.text.count('\r')) \
                    and ('"' in self.text or "'" in self.text):
                self.structure = Util.parse_python(self.text)
                logger.log(TRACE, "CONVERTED from Python")
            else:
                logger.log(TRACE, "Data do not contain line feed - weak PYTHON")
        except Exception as exc:  # pylint: disable=broad-exception-caught
            # fallback
            logger.log(TRACE, "Cannot parse as Python %s:%s %s", type(exc), exc, self.descriptor)
        else:
            if self.__is_structure():
                return True
        # # # YAML - almost always recognized
        try:
            if ':' in self.text and (2 < self.text.count('\n') or 2 < self.text.count('\r')):
                self.structure = yaml.safe_load(self.text)
                logger.log(TRACE, "CONVERTED from yaml")
            else:
                logger.log(TRACE, "Data do not contain colon mark - weak YAML")
        except Exception as exc:  # pylint: disable=broad-exception-caught
            # fallback
            logger.log(TRACE, "Cannot parse as yaml %s:%s %s", type(exc), exc, self.descriptor)
        else:
            if self.__is_structure():
                return True
        # # # None of above
        return None

    def represent_as_xml(self) -> Optional[bool]:
        """Tries to read data as xml

        Return:
             True if reading was successful
             False if no data found
             None if the format is not acceptable

        """
        if MIN_XML_LEN > len(self.text):
            return False
        try:
            if '<' in self.text and '>' in self.text and "</" in self.text:
                xml_text = self.text.splitlines()
                self.lines, self.line_numbers = Util.get_xml_from_lines(xml_text)
                logger.log(TRACE, "CONVERTED from xml")
                return bool(self.lines and self.line_numbers)
            logger.log(TRACE, "Weak data to parse as XML")
        except Exception as exc:  # pylint: disable=broad-exception-caught
            # fallback
            logger.log(TRACE, "Cannot parse as XML %s:%s %s", type(exc), exc, self.descriptor)
        return None

    def yield_analysis_target(self, min_len: int) -> Generator[AnalysisTarget, None, None]:
        """Return nothing. The class provides only data storage.

        Args:
            min_len: minimal line length to scan

        Raise:
            NotImplementedError

        """
        raise NotImplementedError()
