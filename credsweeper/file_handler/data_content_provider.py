import base64
import json
import logging
import string
from typing import List, Optional, Any

import yaml
from bs4 import BeautifulSoup

from credsweeper.common.constants import DEFAULT_ENCODING
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.utils import Util

logger = logging.getLogger(__name__)

# similar min_line_len in rule_template - no real credential in data less than 8 bytes
MIN_DATA_LEN = 8

# 8 bytes encodes to 12 symbols 12345678 -> MTIzNDU2NzgK
MIN_ENCODED_DATA_LEN = 12

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
        self.__inited_text: str = ""
        self.data = data
        self.structure: Optional[List[Any]] = None
        self.decoded: Optional[bytes] = None
        self.lines: List[str] = []
        self.line_numbers: List[int] = []

    @property
    def data(self) -> Optional[bytes]:
        """data getter for DataContentProvider"""
        return self.__data

    @data.setter
    def data(self, data: Optional[bytes]) -> None:
        """data setter for DataContentProvider"""
        self.__data = data

    @property
    def __text(self) -> str:
        """Getter which throws exception in case of bad decoding"""
        if not self.__inited_text:
            self.__inited_text = self.data.decode(encoding=DEFAULT_ENCODING, errors="strict")
        return self.__inited_text

    def __is_structure(self) -> bool:
        """Check whether a structure was recognized"""
        return self.structure is not None and (isinstance(self.structure, dict) and 0 < len(self.structure.keys())
                                               or isinstance(self.structure, list) and 0 < len(self.structure))

    def represent_as_structure(self) -> bool:
        """Tries to convert data with many parsers. Stores result to internal structure
        Return True if some structure found
        """
        try:
            if MIN_DATA_LEN > len(self.__text):
                return False
        except Exception:
            return False
        # JSON
        try:
            if "{" in self.__text:
                self.structure = json.loads(self.__text)
                logger.debug("CONVERTED from json")
            else:
                logger.debug("Data do not contain { - weak JSON")
        except Exception as exc:
            logger.debug("Cannot parse as json:%s %s", exc, self.data)
        else:
            if self.__is_structure():
                return True
        # # # Python
        try:
            if ";" in self.__text or 2 < self.__text.count("\n"):
                self.structure = Util.parse_python(self.__text)
                logger.debug("CONVERTED from Python")
            else:
                logger.debug("Data do not contain line feed - weak PYTHON")
        except Exception as exc:
            logger.debug("Cannot parse as Python:%s %s", exc, self.data)
        else:
            if self.__is_structure():
                return True
        # # # YAML - almost always recognized
        try:
            if ":" in self.__text and 2 < self.__text.count("\n"):
                self.structure = yaml.load(self.__text, Loader=yaml.FullLoader)
                logger.debug("CONVERTED from yaml")
            else:
                logger.debug("Data do not contain colon mark - weak YAML")
        except Exception as exc:
            logger.debug("Cannot parse as yaml:%s %s", exc, self.data)
        else:
            if self.__is_structure():
                return True
        # # # None of above
        return False

    def represent_as_xml(self) -> bool:
        """Tries to read data as xml

        Return:
             True if reading was successful

        """
        if MIN_XML_LEN > len(self.data):
            return False
        try:
            if "<" in self.__text and ">" in self.__text and "</" in self.__text:
                xml_text = self.__text.splitlines()
                self.lines, self.line_numbers = Util.get_xml_from_lines(xml_text)
            else:
                logger.debug("Weak data to parse as XML")
                return False
        except Exception as exc:
            logger.debug("Cannot parse as XML:%s %s", exc, self.data)
        else:
            return bool(self.lines and self.line_numbers)
        return False

    def represent_as_html(self) -> bool:
        """Tries to read data as html

        Return:
             True if reading was successful

        """
        try:
            text = self.data.decode(encoding=DEFAULT_ENCODING)
            html = None
            if "</" in text and ">" in text:
                html = BeautifulSoup(text, features="html.parser")
            if html:
                # simple parse as it is displayed to user
                # dbg = html.find_all(text=True)
                for p in html.find_all("p"):
                    p.append('\n')
                lines = html.get_text().splitlines()
                for line_number, doc_line in enumerate(lines):
                    line = doc_line.strip()
                    if line:
                        self.line_numbers.append(line_number + 1)
                        self.lines.append(line)

                # transform table if table cell is assigned to header cell
                # make from cells a chain like next is assigned to previous
                for table in html.find_all('table'):
                    table_header = None
                    for tr in table.find_all('tr'):
                        record_line = ""
                        if table_header:
                            for th, td in zip(table_header.find_all(['td', 'th']), tr.find_all('td')):
                                th_text = th.get_text(strip=True)
                                td_text = td.get_text(strip=True)
                                if not record_line:
                                    record_line = f'"{td_text}"'
                                else:
                                    record_line += f' = "{td_text}"'
                                self.line_numbers.append(td.sourceline)
                                self.lines.append(f'{th_text} = "{td_text}"')
                            self.line_numbers.append(tr.sourceline)
                            self.lines.append(record_line)
                        else:
                            for td in tr.find_all(['td', 'th']):
                                td_text = td.get_text(strip=True)
                                if not record_line:
                                    record_line = f'"{td_text}"'
                                else:
                                    record_line += f' = "{td_text}"'
                                self.line_numbers.append(td.sourceline)
                                self.lines.append(td_text)
                            self.line_numbers.append(tr.sourceline)
                            self.lines.append(record_line)
                            table_header = tr

                logger.debug("CONVERTED from html")
            else:
                logger.debug("Data do not contain specific tags - weak HTML")
        except Exception as exc:
            logger.debug("Cannot parse as HTML:%s %s", exc, self.data)
        else:
            return bool(self.lines and self.line_numbers)
        return False

    def represent_as_encoded(self) -> bool:
        """Encodes data from base64. Stores result in decoded

        Return:
             True if the data correctly parsed and verified

        """
        if len(self.data) < MIN_ENCODED_DATA_LEN \
                or (b"=" in self.data and 0x3D != self.data[-1] and 0x20 < self.data[-1]):
            logger.debug("Weak data to decode from base64: %s", self.data)
            return False
        try:
            self.decoded = base64.b64decode(  #
                self.data.decode(encoding="ascii", errors="strict").  #
                translate(str.maketrans("", "", string.whitespace)),  #
                validate=True)  #
        except Exception as exc:
            logger.debug("Cannot decoded as base64:%s %s", exc, self.data)
        else:
            return self.decoded is not None and 0 < len(self.decoded)
        return False

    def get_analysis_target(self) -> List[AnalysisTarget]:
        """Return nothing. The class provides only data storage.

        Raise:
            NotImplementedError

        """
        raise NotImplementedError()
