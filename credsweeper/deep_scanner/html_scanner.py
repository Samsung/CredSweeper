import logging
from abc import ABC
from typing import List, Optional, Union

from credsweeper.common.constants import MAX_LINE_LENGTH
from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.string_content_provider import StringContentProvider

logger = logging.getLogger(__name__)


class HtmlScanner(AbstractScanner, ABC):
    """Implements html scanning if possible"""

    @staticmethod
    def match(data: Union[bytes, bytearray]) -> bool:
        """Used to detect html format. Suppose, invocation of is_xml() was True before."""
        for opening_tag, closing_tag in [(b"<html", b"</html>"), (b"<body", b"</body>"), (b"<table", b"</table>"),
                                         (b"<p>", b"</p>"), (b"<span>", b"</span>"), (b"<div>", b"</div>"),
                                         (b"<li>", b"</li>"), (b"<ol>", b"</ol>"), (b"<ul>", b"</ul>"),
                                         (b"<th>", b"</th>"), (b"<tr>", b"</tr>"), (b"<td>", b"</td>")]:
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
        """Tries to represent data as html text and scan as text lines"""
        if result := data_provider.represent_as_html(depth, recursive_limit_size,
                                                     self.scanner.keywords_required_substrings_check):
            string_data_provider = StringContentProvider(lines=data_provider.lines,
                                                         line_numbers=data_provider.line_numbers,
                                                         file_path=data_provider.file_path,
                                                         file_type=data_provider.file_type,
                                                         info=f"{data_provider.info}|HTML")
            return self.scanner.scan(string_data_provider)
        return None if result is None else []
