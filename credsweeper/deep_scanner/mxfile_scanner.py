import logging
from abc import ABC
from typing import List, Optional

from bs4 import BeautifulSoup
from lxml import etree

from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.string_content_provider import StringContentProvider

logger = logging.getLogger(__name__)


class MxfileScanner(AbstractScanner, ABC):
    """Scanner for drawio diagram"""

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Tries to get text data from the xml format"""
        try:
            lines = []
            line_numbers = []
            tree = etree.fromstring(data_provider.text)
            for element in tree.iter():
                if "mxCell" == getattr(element, "tag"):
                    line_number = element.sourceline
                    attr = getattr(element, "attrib")
                    if attr is None or not (value := attr.get("value")):
                        continue
                    if html := BeautifulSoup(value, features="html.parser"):
                        _, value_lines, __ = data_provider.simple_html_representation(html)
                        for line in value_lines:
                            lines.append(line)
                            line_numbers.append(line_number)
            mxfile_data_provider = StringContentProvider(lines=lines,
                                                         line_numbers=line_numbers,
                                                         file_path=data_provider.file_path,
                                                         file_type=data_provider.file_type,
                                                         info=f"{data_provider.info}|MXFILE")
            return self.scanner.scan(mxfile_data_provider)
        except Exception as exc:
            logger.error(exc)
        return None
