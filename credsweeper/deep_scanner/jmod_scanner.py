import io
import logging
from abc import ABC
from typing import List, Optional
from zipfile import BadZipFile

from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.zip_scanner import ZipScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.logger import TRACE
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class JmodScanner(ZipScanner, ABC):
    """Implements java .jmod scanning"""

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """Only one version exists"""
        if data.startswith(b"JM\x01\x00PK\x03\x04"):
            return True
        return False

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Extracts data from ZIP after prefix"""
        try:
            candidates = []
            recursive_limit_size -= len(data_provider.data)
            stream = io.BytesIO(data_provider.data)
            stream.read(4)
            for filename, filedata in ZipScanner.walk_zip(stream, recursive_limit_size, self.config):
                jmod_content_provider = DataContentProvider(data=filedata,
                                                            file_path=data_provider.file_path,
                                                            file_type=Util.get_type(filename),
                                                            info=f"{data_provider.info}|JMOD:{filename}")
                jmod_candidates = self.recursive_scan(jmod_content_provider, depth, recursive_limit_size)
                candidates.extend(jmod_candidates)
            return candidates
        except BadZipFile as zip_exc:
            logger.log(TRACE, "%s %s", zip_exc, data_provider.descriptor)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            # too many exception types might be produced with broken zip
            logger.warning("%s:%s:%s", type(exc), exc, data_provider.descriptor)
        return None
