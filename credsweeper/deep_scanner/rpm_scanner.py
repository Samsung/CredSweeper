import io
import logging
from abc import ABC
from typing import List, Optional

import rpmfile

from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.file_path_extractor import FilePathExtractor
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class RpmScanner(AbstractScanner, ABC):
    """Implements rpm scanning"""

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Extracts files one by one from the package type and launches recursive scan"""
        try:
            candidates = []
            with rpmfile.open(fileobj=io.BytesIO(data_provider.data)) as rpm_file:
                for member in rpm_file.getmembers():
                    # skip directory
                    if 0 != member.isdir:
                        continue
                    if FilePathExtractor.check_exclude_file(self.config, member.name):
                        continue
                    if 0 > recursive_limit_size - member.size:
                        logger.error(f"{member.filename}: size {member.size}"
                                     f" is over limit {recursive_limit_size} depth:{depth}")
                        continue
                    rpm_content_provider = DataContentProvider(data=rpm_file.extractfile(member).read(),
                                                               file_path=data_provider.file_path,
                                                               file_type=Util.get_extension(member.name),
                                                               info=f"{data_provider.info}|RPM:{member.name}")
                    new_limit = recursive_limit_size - len(rpm_content_provider.data)
                    rpm_candidates = self.recursive_scan(rpm_content_provider, depth, new_limit)
                    candidates.extend(rpm_candidates)
            return candidates
        except Exception as rpm_exc:
            logger.error(f"{data_provider.file_path}:{rpm_exc}")
        return None
