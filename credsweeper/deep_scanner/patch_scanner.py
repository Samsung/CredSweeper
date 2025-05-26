import io
import logging
from abc import ABC
from typing import List, Optional

from credsweeper.common.constants import DiffRowType
from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.patches_provider import PatchesProvider

logger = logging.getLogger(__name__)


class PatchScanner(AbstractScanner, ABC):
    """Implements .patch scanning"""

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Tries to scan EML with text representation"""
        try:
            candidates: List[Candidate] = []
            # common limitation
            new_limit_size = recursive_limit_size - len(data_provider.data)
            # ADDED
            path_added = [(data_provider.file_path, io.BytesIO(data_provider.data))]
            added_content_provider = PatchesProvider(path_added, change_type=DiffRowType.ADDED)
            for added_file in added_content_provider.get_scannable_files(self.config):
                added_candidates = self.scan(added_file, depth, new_limit_size)
                candidates.extend(added_candidates)
            # DELETED
            path_deleted = [(data_provider.file_path, io.BytesIO(data_provider.data))]
            deleted_content_provider = PatchesProvider(path_deleted, change_type=DiffRowType.DELETED)
            for deleted_file in deleted_content_provider.get_scannable_files(self.config):
                added_candidates = self.scan(deleted_file, depth, new_limit_size)
                candidates.extend(added_candidates)
            # update the line data for deep scan only
            for i in candidates:
                for line_data in i.line_data_list:
                    line_data.path = f"{data_provider.file_path}/{line_data.path}"
                    line_data.info = f"{data_provider.info}|PATCH:{line_data.info}"
            return candidates
        except Exception as patch_exc:
            logger.error(f"{data_provider.file_path}:{patch_exc}")
        return None
