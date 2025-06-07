import logging
from abc import ABC
from typing import List, Optional

from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider

logger = logging.getLogger(__name__)


class EncoderScanner(AbstractScanner, ABC):
    """Implements recursive iteration when data might be encoded"""

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Tries to decode data from base64 encode to bytes and scan as bytes again"""
        if result := data_provider.represent_as_encoded():
            decoded_data_provider = DataContentProvider(data=data_provider.decoded,
                                                        file_path=data_provider.file_path,
                                                        file_type=data_provider.file_type,
                                                        info=f"{data_provider.info}|BASE64")
            new_limit = recursive_limit_size - len(decoded_data_provider.data)
            return self.recursive_scan(decoded_data_provider, depth, new_limit)
        return None if result is None else []
