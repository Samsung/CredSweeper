import gzip
import io
import logging
from abc import ABC
from typing import List, Optional

from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider

logger = logging.getLogger(__name__)


class GzipScanner(AbstractScanner, ABC):
    """Realises gzip scanning"""

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """According https://www.rfc-editor.org/rfc/rfc1952"""
        if data.startswith(b"\x1F\x8B") and not data.startswith(b"\x1F\x8B\x00"):
            # compression method is non-zero value
            return True
        return False

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Extracts data from gzip archive and launches data_scan"""
        try:
            with gzip.open(io.BytesIO(data_provider.data)) as f:
                if data_provider.file_type.endswith(".gz"):
                    file_type = data_provider.file_type[:-3]
                elif data_provider.file_type.endswith(".tgz"):
                    # .tar.gz synonym
                    file_type = data_provider.file_type[:-4]
                else:
                    file_type = data_provider.file_type
                data = AbstractScanner.read_compressed_with_limit(f, recursive_limit_size)
                gzip_content_provider = DataContentProvider(data=data,
                                                            file_path=data_provider.file_path,
                                                            file_type=file_type,
                                                            info=f"{data_provider.info}|GZIP:{len(data)}")
                gzip_candidates = self.recursive_scan(gzip_content_provider, depth, recursive_limit_size)
                return gzip_candidates
        except AbstractScanner.LimitError as gzip_limit_exc:
            logger.warning("%s %s", data_provider.descriptor, gzip_limit_exc)
            return []
        except Exception as gzip_exc:
            logger.warning("%s:%s", data_provider.descriptor, gzip_exc)
        return None
