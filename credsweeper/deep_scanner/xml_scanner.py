import logging
import re
from abc import ABC
from typing import List, Optional, Tuple

from lxml import etree

from credsweeper.common.constants import MAX_LINE_LENGTH, DEFAULT_PATTERN_LEN
from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.string_content_provider import StringContentProvider
from credsweeper.file_handler.struct_content_provider import StructContentProvider
from credsweeper.logger import TRACE
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)

# <t>12345678</t> - minimal xml with a credential
MIN_XML_LEN = 16


class XmlScanner(AbstractScanner, ABC):
    """Realises xml scanning"""

    # A well-formed XML must start from < or a whitespace character
    XML_FIRST_BRACKET_PATTERN = re.compile(rb"^\s*<")
    XML_OPENING_TAG_PATTERN = re.compile(rb"<([0-9A-Za-z_]{1,256})")

    shelf = True

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """Used to detect XML format from raw bytes"""
        if XmlScanner.XML_FIRST_BRACKET_PATTERN.search(data, 0, MAX_LINE_LENGTH):
            if first_bracket_match := XmlScanner.XML_OPENING_TAG_PATTERN.search(data, 0, MAX_LINE_LENGTH):
                start_pos = first_bracket_match.start()
                closing_tag = b"</" + first_bracket_match.group(1) + b">"
                if start_pos < data.find(closing_tag, start_pos):
                    return True
        return False

    def represent_xml_as_structure(self, lines: List[str]) -> List[str | dict]:
        """Parse XML to structure with possible tag combination"""
        structure: List[str | dict] = []
        for element in etree.fromstringlist(lines).iter():
            if text := Util.extract_element_data(element, "text"):
                if len(text) < DEFAULT_PATTERN_LEN:
                    continue
                tag = Util.extract_element_data(element, "tag")
                if self.scanner.keywords_required_substrings_check(tag.lower()):
                    structure.append({tag: text})
                else:
                    structure.append(text)
        return structure

    def represent_xml_as_text(self, lines: List[str]) -> Tuple[List[str], List[int]]:
        """Parse XML to structure with possible tag combination"""
        structure: List[str] = []
        line_numbers: List[int] = []
        for element in etree.fromstringlist(lines).iter():
            if text := Util.extract_element_data(element, "text"):
                if len(text) < DEFAULT_PATTERN_LEN:
                    continue
                tag = Util.extract_element_data(element, "tag")
                if self.scanner.keywords_required_substrings_check(tag.lower()):
                    structure.append(f"{tag} : {text}")
                    line_numbers.append(element.sourceline or -1)
                else:
                    text_lines = text.splitlines()
                    structure.extend(text_lines)
                    line_numbers.extend([element.sourceline or -1 for _ in range(len(text_lines))])
        return structure, line_numbers

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Tries to represent data as XML text and scan as text lines"""
        try:
            if 0 == depth:
                lines, line_numbers = self.represent_xml_as_text(data_provider.lines)
                str_provider = StringContentProvider(lines=lines,
                                                     line_numbers=line_numbers,
                                                     file_path=data_provider.file_path,
                                                     file_type=data_provider.file_type,
                                                     info=f"{data_provider.info}|XML")
                return self.scanner.scan(str_provider)
            if structure := self.represent_xml_as_structure(data_provider.lines):
                struct_data_provider = StructContentProvider(struct=structure,
                                                             file_path=data_provider.file_path,
                                                             file_type=data_provider.file_type,
                                                             info=f"{data_provider.info}|XML")
                new_limit = recursive_limit_size - len(data_provider.data)
                return self.structure_scan(struct_data_provider, depth, new_limit)
        except etree.XMLSyntaxError as xml_exc:
            logger.log(TRACE, "%s %s", xml_exc, data_provider.descriptor)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            # fallback
            logger.warning("%s:%s:%s", type(exc), exc, data_provider.descriptor)
        return None
