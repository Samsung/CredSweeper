import logging
from abc import ABC
from typing import List, Optional, Union

from lxml import etree

from credsweeper.common.constants import MIN_DATA_LEN, MAX_LINE_LENGTH
from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.string_content_provider import StringContentProvider
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class TmxScanner(AbstractScanner, ABC):
    """Realises tmX files scanning for values only. Image tags are skipped."""

    @staticmethod
    def match(data: Union[bytes, bytearray]) -> bool:
        """Used to detect tm7,tm6,etc. (ThreadModeling) format."""
        for opening_tag, closing_tag in [(b"<ThreatModel", b"</ThreatModel>"),
                                         (b"<KnowledgeBase", b"</KnowledgeBase>")]:
            opening_pos = data.find(opening_tag, 0, MAX_LINE_LENGTH)
            if 0 <= opening_pos < data.find(closing_tag, opening_pos):
                # opening and closing tags were found - suppose it is an HTML
                return True
        return False

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Tries to represent data as xml text and scan as text lines"""
        try:
            lines = []
            # the format is always in single line xlm, so line numbers are not actual
            tree = etree.fromstring(data_provider.data)
            for element in tree.iter():
                tag = Util.extract_element_data(element, "tag")
                if "Image" in tag:
                    continue
                text = Util.extract_element_data(element, "text")
                if MIN_DATA_LEN > len(text):
                    continue
                lines.append(text)
            tmx_data_provider = StringContentProvider(lines=lines,
                                                      file_path=data_provider.file_path,
                                                      file_type=data_provider.file_type,
                                                      info=f"{data_provider.info}|TMX")
            return self.scanner.scan(tmx_data_provider)
        except Exception as exc:
            logger.warning("Cannot processed tmX file %s %s", str(data_provider.file_path), str(exc))
        return None
