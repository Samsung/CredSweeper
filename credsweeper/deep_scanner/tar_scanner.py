import contextlib
import io
import logging
import tarfile
from abc import ABC
from typing import List, Optional, Union

from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.file_path_extractor import FilePathExtractor
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class TarScanner(AbstractScanner, ABC):
    """Implements tar scanning"""

    @staticmethod
    def match(data: Union[bytes, bytearray]) -> bool:
        """According https://en.wikipedia.org/wiki/List_of_file_signatures"""
        if 512 <= len(data) and 257 == data.find(b"\x75\x73\x74\x61\x72", 257, 262) \
                and (262 == data.find(b"\x00\x30\x30", 262, 265)
                     or 262 == data.find(b"\x20\x20\x00", 262, 265)):
            with contextlib.suppress(Exception):
                chksum = tarfile.nti(data[148:156])  # type: ignore
                unsigned_chksum, signed_chksum = tarfile.calc_chksums(data)  # type: ignore
                if chksum == unsigned_chksum or chksum == signed_chksum:
                    return True
        return False

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Extracts files one by one from tar archive and launches data_scan"""
        try:
            candidates = []
            with tarfile.TarFile(fileobj=io.BytesIO(data_provider.data)) as tf:
                for tfi in tf.getmembers():
                    # skip directory
                    if not tfi.isreg():
                        continue
                    if FilePathExtractor.check_exclude_file(self.config, tfi.name):
                        continue
                    if 0 > recursive_limit_size - tfi.size:
                        logger.error(f"{tfi.name}: size {tfi.size}"
                                     f" is over limit {recursive_limit_size} depth:{depth}")
                        continue
                    with tf.extractfile(tfi) as f:
                        tar_content_provider = DataContentProvider(data=f.read(),
                                                                   file_path=data_provider.file_path,
                                                                   file_type=Util.get_extension(tfi.name),
                                                                   info=f"{data_provider.info}|TAR:{tfi.name}")
                        # Nevertheless, use extracted data size
                        new_limit = recursive_limit_size - len(tar_content_provider.data)
                        tar_candidates = self.recursive_scan(tar_content_provider, depth, new_limit)
                        candidates.extend(tar_candidates)
            return candidates
        except Exception as tar_exc:
            # too many exception types might be produced with broken tar
            logger.error(f"{data_provider.file_path}:{tar_exc}")
        return None
