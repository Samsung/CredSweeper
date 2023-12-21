import base64
import json
import logging
import string
import warnings
from typing import List, Optional, Any, Generator, Callable, Tuple

import yaml
from bs4 import BeautifulSoup, Tag, XMLParsedAsHTMLWarning

from credsweeper.common.constants import DEFAULT_ENCODING, ASCII
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.utils import Util

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning, module='bs4')
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
        self.__html_lines_size = len(data)  # the size is used to limit extra memory consumption during html combination

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
        # JSON & NDJSON
        if "{" in self.__text and "}" in self.__text and "\"" in self.__text and ":" in self.__text:
            try:
                self.structure = json.loads(self.__text)
                logger.debug("CONVERTED from json")
            except Exception as exc:
                logger.debug("Cannot parse as json:%s %s", exc, self.data)
            else:
                if self.__is_structure():
                    return True
            try:
                self.structure = []
                for line in self.__text.splitlines():
                    # each line must be in json format, otherwise - exception rises
                    self.structure.append(json.loads(line))
                logger.debug("CONVERTED from ndjson")
            except Exception as exc:
                logger.debug("Cannot parse as ndjson:%s %s", exc, self.data)
                self.structure = None
            else:
                if self.__is_structure():
                    return True
        else:
            logger.debug("Data do not contain { - weak JSON")

        # # # Python
        try:
            # search only in sources with strings
            if (";" in self.__text or 2 < self.__text.count("\n")) and ("\"" in self.__text or "'" in self.__text):
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
                logger.debug("CONVERTED from xml")
            else:
                logger.debug("Weak data to parse as XML")
                return False
        except Exception as exc:
            logger.debug("Cannot parse as XML:%s %s", exc, self.data)
        else:
            return bool(self.lines and self.line_numbers)
        return False

    def _check_multiline_cell(self, cell: Tag) -> Optional[Tuple[int, str]]:
        """multiline cell will be analysed as text or return single line from cell
        returns line number and one line for analysis
        If there are no text or the text will be analysed as multiline - it returns None"""
        # use not stripped get_text, otherwise all format is cleaned
        cell_text = cell.get_text()
        cell_lines = cell_text.splitlines()
        line_numbers: List[int] = []
        stripped_lines: List[str] = []
        for offset, line in enumerate(cell_lines):
            if stripped_line := line.strip():
                line_numbers.append(cell.sourceline + offset)
                stripped_lines.append(stripped_line)
        if 0 == len(stripped_lines):
            return None
        elif 1 == len(stripped_lines):
            return line_numbers[0], stripped_lines[0]
        else:
            # the cell will be analysed as multiline text
            self.line_numbers.extend(line_numbers)
            self.lines.extend(stripped_lines)
            self.__html_lines_size += sum(len(x) for x in stripped_lines)
            return None

    def _simple_html_representation(self, html: BeautifulSoup):
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
                self.__html_lines_size += len(line)

    @staticmethod
    def _table_depth_reached(table: Tag, depth: int) -> bool:
        if parent := table.parent:
            if isinstance(parent, BeautifulSoup):
                return False
            if 0 > depth:
                return True
            if "table" == parent.name:
                depth -= 1
            return DataContentProvider._table_depth_reached(parent, depth)
        return True

    def _table_representation(
            self,  #
            table: Tag,  #
            depth: int,  #
            recursive_limit_size: int,  #
            keywords_required_substrings_check: Callable[[str], bool]):
        """
        transform table if table cell is assigned to header cell
        make from cells a chain like next is assigned to previous
        """
        if DataContentProvider._table_depth_reached(table, depth):
            logger.warning("Recursive depth limit was reached during HTML table combinations")
            return
        table_header: Optional[List[Optional[str]]] = None
        for tr in table.find_all('tr'):
            if recursive_limit_size < self.__html_lines_size:
                break
            record_numbers = []
            record_lines = []
            record_leading = None
            if table_header is None:
                table_header = []
                # first row in table may be a header with <td> and a style, but search <th> too
                for cell in tr.find_all(['th', 'td']):
                    if recursive_limit_size < self.__html_lines_size:
                        break
                    if td_numbered_line := self._check_multiline_cell(cell):
                        td_text = td_numbered_line[1]
                        td_text_has_keywords = keywords_required_substrings_check(td_text.lower())
                        if td_text_has_keywords:
                            table_header.append(td_text)
                        else:
                            table_header.append(None)
                        if record_leading is None:
                            if td_text_has_keywords:
                                record_leading = td_text
                            else:
                                record_leading = ""
                        else:
                            record_numbers.append(td_numbered_line[0])
                            record_lines.append(f"{record_leading} = {td_text}")
                        # add single text to lines for analysis
                        self.line_numbers.append(td_numbered_line[0])
                        self.lines.append(td_text)
                        self.__html_lines_size += len(td_text)
                    else:
                        # empty cell or multiline cell
                        table_header.append(None)
                        continue
            else:
                # not a first line in table - may be combined with a header
                for header_pos, cell in enumerate(tr.find_all('td')):
                    if recursive_limit_size < self.__html_lines_size:
                        break
                    if td_numbered_line := self._check_multiline_cell(cell):
                        td_text = td_numbered_line[1]
                        td_text_has_keywords = keywords_required_substrings_check(td_text.lower())
                        if record_leading is None:
                            if td_text_has_keywords:
                                record_leading = td_text
                            else:
                                record_leading = ""
                        elif record_leading:
                            record_numbers.append(td_numbered_line[0])
                            record_lines.append(f"{record_leading} = {td_text}")
                        if header_pos < len(table_header):
                            if header_text := table_header[header_pos]:
                                self.line_numbers.append(td_numbered_line[0])
                                self.lines.append(f"{header_text} = {td_text}")
                                self.__html_lines_size += len(td_text)
                    else:
                        # empty cell or multiline cell
                        table_header.append(None)
                        continue
            if record_lines:
                # add combinations with left column
                self.line_numbers.extend(record_numbers)
                self.lines.extend(record_lines)
                self.__html_lines_size += sum(len(x) for x in record_lines)

    def _html_tables_representation(
            self,  #
            html: BeautifulSoup,  #
            depth: int,  #
            recursive_limit_size: int,  #
            keywords_required_substrings_check: Callable[[str], bool]):
        """Iterates for all tables in html to explore cells and their combinations"""
        depth -= 1
        if 0 > depth:
            return
        for table in html.find_all('table'):
            if recursive_limit_size < self.__html_lines_size:
                logger.warning("Recursive size limit was reached during HTML table combinations")
                break
            self._table_representation(table, depth, recursive_limit_size, keywords_required_substrings_check)

    def represent_as_html(
            self,  #
            depth: int,  #
            recursive_limit_size: int,  #
            keywords_required_substrings_check: Callable[[str], bool]) -> bool:
        """Tries to read data as html

        Return:
             True if reading was successful

        """
        try:
            text = self.data.decode(encoding=DEFAULT_ENCODING)
            if "</" in text and ">" in text:
                if html := BeautifulSoup(text, features="html.parser"):
                    self._simple_html_representation(html)
                    # apply recursive_limit_size/2 to reduce extra calculation
                    # of all accompanying losses per objects allocation
                    self._html_tables_representation(html, depth, recursive_limit_size >> 1,
                                                     keywords_required_substrings_check)
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
                self.data.decode(encoding=ASCII, errors="strict").  #
                translate(str.maketrans("", "", string.whitespace)),  #
                validate=True)  #
        except Exception as exc:
            logger.debug("Cannot decoded as base64:%s %s", exc, self.data)
        else:
            return self.decoded is not None and 0 < len(self.decoded)
        return False

    def yield_analysis_target(self, min_len: int) -> Generator[AnalysisTarget, None, None]:
        """Return nothing. The class provides only data storage.

        Args:
            min_len: minimal line length to scan

        Raise:
            NotImplementedError

        """
        raise NotImplementedError()
