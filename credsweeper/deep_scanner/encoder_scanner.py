import contextlib
import logging
import re
from abc import ABC
from typing import List, Optional

from credsweeper.common.constants import MAX_LINE_LENGTH
from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)

# 8 bytes encodes to 12 symbols 12345678 -> MTIzNDU2NzgK
MIN_ENCODED_DATA_LEN = 12


class EncoderScanner(AbstractScanner, ABC):
    """Implements recursive iteration when data might be encoded from base64"""

    BASE64_PATTERN = re.compile(
        rb"(\xFF\xFE|\xFE\xFF)?("
        rb"(?:(?P<a>[A-Z])|(?P<b>[a-z])|(?P<c>[0-9/+])|[\s\x00\\])+(?(a)(?(b)(?(c)(=+|$)|(?!x)x)|(?!x)x)|(?!x)x)|"
        rb"(?:(?P<e>[A-Z])|(?P<f>[a-z])|(?P<g>[0-9_-])|[\s\x00\\])+(?(e)(?(f)(?(g)(=+|$)|(?!x)x)|(?!x)x)|(?!x)x))")

    @staticmethod
    def match(data: bytes) -> bool:
        """Check if data may be base64 encoded with whitespaces (escaping too)"""
        if len(data) >= MIN_ENCODED_DATA_LEN \
                and EncoderScanner.BASE64_PATTERN.match(data, pos=0, endpos=MAX_LINE_LENGTH):
            return True
        return False

    @staticmethod
    def decode(text: str) -> Optional[bytes]:
        """Decodes base64 text with cleaning whitespaces. Returns None when the decoding fails"""
        with contextlib.suppress(Exception):
            return Util.decode_base64(text=Util.PEM_CLEANING_PATTERN.sub(r'', text).replace('\\', ''),
                                      padding_safe=True,
                                      urlsafe_detect=True)
        return None

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Tries to decode data from base64 encode to bytes and scan as bytes again"""
        if decoded := EncoderScanner.decode(data_provider.text):
            decoded_data_provider = DataContentProvider(data=decoded,
                                                        file_path=data_provider.file_path,
                                                        file_type=data_provider.file_type,
                                                        info=f"{data_provider.info}|BASE64")
            new_limit = recursive_limit_size - len(decoded_data_provider.data)
            return self.recursive_scan(decoded_data_provider, depth, new_limit)
        return None
