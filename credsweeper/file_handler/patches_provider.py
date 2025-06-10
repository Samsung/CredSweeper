import io
import logging
from pathlib import Path
from typing import List, Union, Tuple, Sequence

from credsweeper.common.constants import DiffRowType
from credsweeper.config.config import Config
from credsweeper.file_handler.abstract_provider import AbstractProvider
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.file_handler.diff_content_provider import DiffContentProvider
from credsweeper.file_handler.file_path_extractor import FilePathExtractor
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class PatchesProvider(AbstractProvider):
    """Provide data from a list of `.patch` files.
    """

    def __init__(self, paths: Sequence[Union[str, Path, io.BytesIO, Tuple[Union[str, Path], io.BytesIO]]],
                 change_type: DiffRowType) -> None:
        """Initialize Files Patch Provider for patch files from 'paths'.

        Args:
            paths: file paths list to scan. All files should be in `.patch` format
            change_type: DiffRowType, type of analyses changes in patch (added or deleted)
              of ignored directories from the gitignore file

        """
        super().__init__(paths)
        self.change_type = change_type

    def load_patch_data(self, config: Config) -> List[List[str]]:
        """Loads data from patch"""
        raw_patches = []
        for file_path in self.paths:
            if FilePathExtractor.check_file_size(config, file_path):
                continue
            if isinstance(file_path, (str, Path)):
                raw_patches.append(Util.read_file(file_path))
            elif isinstance(file_path, io.BytesIO):
                the_patch = Util.decode_bytes(file_path.read())
                raw_patches.append(the_patch)
            elif isinstance(file_path, tuple) and 1 < len(file_path) and isinstance(file_path[1], io.BytesIO):
                the_patch = Util.decode_bytes(file_path[1].read())
                raw_patches.append(the_patch)
            else:
                logger.error(f"Unknown path type: {file_path}")

        return raw_patches

    def get_files_sequence(self, raw_patches: List[List[str]]) -> Sequence[ContentProvider]:
        """Returns sequence of files"""
        files: List[ContentProvider] = []
        for raw_patch in raw_patches:
            files_data = DiffContentProvider.patch2files_diff(raw_patch, self.change_type)
            for file_path, file_diff in files_data.items():
                files.append(DiffContentProvider(file_path=file_path, change_type=self.change_type, diff=file_diff))
        return files

    def get_scannable_files(self, config: Config) -> Sequence[ContentProvider]:
        """Get files to scan. Output based on the `paths` field.

        Args:
            config: dict of credsweeper configuration

        Return:
            file objects for analysing

        """
        diff_data = self.load_patch_data(config)
        files = self.get_files_sequence(diff_data)
        return files
