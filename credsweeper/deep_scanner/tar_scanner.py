import contextlib
import io
import logging
from abc import ABC
import tarfile
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
        if 512 <= len(data):
            if 0x75 == data[257] and 0x73 == data[258] and 0x74 == data[259] \
                    and 0x61 == data[260] and 0x72 == data[261] and (
                    0x00 == data[262] and 0x30 == data[263] and 0x30 == data[264]
                    or
                    0x20 == data[262] and 0x20 == data[263] and 0x00 == data[264]
            ):
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
