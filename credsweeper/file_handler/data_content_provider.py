import json
import logging
import warnings
from functools import cached_property
from typing import List, Optional, Any, Generator, Callable, Tuple

import yaml
from bs4 import BeautifulSoup, Tag, XMLParsedAsHTMLWarning

from credsweeper.common.constants import MIN_DATA_LEN
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.utils.util import Util

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning, module='bs4')
logger = logging.getLogger(__name__)

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
        self.__data = data
        self.__text: Optional[str] = None
        self.structure: Optional[List[Any]] = None
        self.decoded: Optional[bytes] = None
        self.lines: List[str] = []
        self.line_numbers: List[int] = []
        self.__html_lines_size = len(data)  # the size is used to limit extra memory consumption during html combination

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
                logger.debug("CONVERTED from json")
            except Exception as exc:
                logger.debug("Cannot parse as json:%s %s", exc, self.data)
            else:
                if self.__is_structure():
                    return True
            try:
                self.structure = []
                for line in self.text.splitlines():
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
            if (';' in self.text or 2 < self.text.count('\n') or 2 < self.text.count('\r')) \
                    and ('"' in self.text or "'" in self.text):
                self.structure = Util.parse_python(self.text)
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
            if ':' in self.text and (2 < self.text.count('\n') or 2 < self.text.count('\r')):
                self.structure = yaml.load(self.text, Loader=yaml.FullLoader)
                logger.debug("CONVERTED from yaml")
            else:
                logger.debug("Data do not contain colon mark - weak YAML")
        except Exception as exc:
            logger.debug("Cannot parse as yaml:%s %s", exc, self.data)
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
                logger.debug("CONVERTED from xml")
                return bool(self.lines and self.line_numbers)
            else:
                logger.debug("Weak data to parse as XML")
        except Exception as exc:
            logger.debug("Cannot parse as XML:%s %s", exc, self.data)
        return None

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

    @staticmethod
    def simple_html_representation(html: BeautifulSoup) -> Tuple[List[int], List[str], int]:
        """simple parse as it is displayed to user and appends the lines"""
        line_numbers: List[int] = []
        lines: List[str] = []
        lines_size = 0
        # use dedicated variable to deal with yapf and flake
        tags_to_split = [
            "p", "br", "tr", "li", "ol", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "pre", "div", "th", "td"
        ]
        for p in html.find_all(tags_to_split):
            p.append('\t')
        html_lines = html.get_text().splitlines()
        for line_number, doc_line in enumerate(html_lines):
            line = doc_line.strip()
            if line:
                line_numbers.append(line_number + 1)
                lines.append(line)
                lines_size += len(line)
        return line_numbers, lines, lines_size

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
        rowspan_columns = []
        for tr in table.find_all("tr"):
            if recursive_limit_size < self.__html_lines_size:
                # weird tables may lead to oversize memory
                break
            record_numbers = []
            record_lines = []
            record_leading = None
            if table_header is None:
                table_header = []
                # first row in table may be a header with <td> and a style, but search <th> too
                for cell in tr.find_all(["th", "td"]):
                    if recursive_limit_size < self.__html_lines_size:
                        # keep the duplicates for early breaks!
                        break
                    colspan_header = int(cell.get("colspan", 1))
                    if td_numbered_line := self._check_multiline_cell(cell):
                        td_text = td_numbered_line[1]
                        td_text_has_keywords = keywords_required_substrings_check(td_text.lower())
                        for _ in range(colspan_header):
                            rowspan_header = int(cell.get("rowspan", 1))
                            rowspan_columns.append(rowspan_header)
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
                            record_lines.append(f"{record_leading} : {td_text}")
                        # add single text to lines for analysis
                        self.line_numbers.append(td_numbered_line[0])
                        self.lines.append(td_text)
                        self.__html_lines_size += len(td_text)
                    else:
                        # empty cell or multiline cell
                        for _ in range(colspan_header):
                            # number of columns is defined with header only
                            rowspan_header = int(cell.get("rowspan", 1))
                            rowspan_columns.append(rowspan_header)
                            table_header.append(None)
            else:
                header_pos = 0
                # not a first line in table - may be combined with a header
                for cell in tr.find_all("td"):
                    if recursive_limit_size < self.__html_lines_size:
                        # keep the duplicates for early breaks!
                        break
                    while header_pos < len(rowspan_columns) and 1 < rowspan_columns[header_pos]:
                        rowspan_columns[header_pos] -= 1
                        header_pos += 1
                    colspan_cell = int(cell.get("colspan", 1))
                    rowspan_cell = int(cell.get("rowspan", 1))
                    for i in range(header_pos, header_pos + colspan_cell):
                        if i < len(rowspan_columns):
                            rowspan_columns[i] += rowspan_cell - 1
                    if td_numbered_line := self._check_multiline_cell(cell):
                        td_text = td_numbered_line[1]
                        if record_leading is None:
                            td_text_has_keywords = keywords_required_substrings_check(td_text.lower())
                            if td_text_has_keywords:
                                record_leading = td_text
                            else:
                                record_leading = ""
                        elif record_leading:
                            record_numbers.append(td_numbered_line[0])
                            record_lines.append(f"{record_leading} : {td_text}")
                        if header_pos < len(table_header):
                            if header_text := table_header[header_pos]:
                                self.line_numbers.append(td_numbered_line[0])
                                self.lines.append(f"{header_text} : {td_text}")
                                self.__html_lines_size += len(td_text)
                    else:
                        # empty cell or multiline cell
                        table_header.append(None)
                    header_pos += colspan_cell
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
        for table in html.find_all("table"):
            if recursive_limit_size < self.__html_lines_size:
                logger.warning("Recursive size limit was reached during HTML table combinations")
                break
            self._table_representation(table, depth, recursive_limit_size, keywords_required_substrings_check)

    def represent_as_html(
            self,  #
            depth: int,  #
            recursive_limit_size: int,  #
            keywords_required_substrings_check: Callable[[str], bool]) -> Optional[bool]:
        """Tries to read data as html

        Return:
             True if reading was successful
             False if no data found
             None if the format is not acceptable

        """
        try:
            if "</" in self.text and ">" in self.text:
                if html := BeautifulSoup(self.text, features="html.parser"):
                    line_numbers, lines, lines_size = self.simple_html_representation(html)
                    self.line_numbers.extend(line_numbers)
                    self.lines.extend(lines)
                    self.__html_lines_size += lines_size
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
        return None

    def represent_as_encoded(self) -> Optional[bool]:
        """Decodes data from base64. Stores result in decoded

        Return:
             True if the data correctly parsed and verified
             False if no data found
             None if the format is not acceptable

        """
        if len(self.data) < MIN_ENCODED_DATA_LEN \
                or (b"=" in self.data and 0x3D != self.data[-1] and 0x20 < self.data[-1]):
            logger.debug("Weak data to decode from base64: %s", self.data)
            return False
        try:
            self.decoded = Util.decode_base64(  #
                text=Util.PEM_CLEANING_PATTERN.sub(r'', self.text).replace('\\', ''),  #
                padding_safe=True,  #
                urlsafe_detect=True)  #
        except Exception as exc:
            logger.debug("Cannot decoded as base64:%s %s", exc, self.data)
        else:
            return self.decoded is not None and 0 < len(self.decoded)
        return None

    def yield_analysis_target(self, min_len: int) -> Generator[AnalysisTarget, None, None]:
        """Return nothing. The class provides only data storage.

        Args:
            min_len: minimal line length to scan

        Raise:
            NotImplementedError

        """
        raise NotImplementedError()
