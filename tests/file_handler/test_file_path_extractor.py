import pytest

from credsweeper.config import Config
from credsweeper.file_handler.file_path_extractor import FilePathExtractor
from tests.conftest import config


class TestFilePathExtractor:
    def test_apply_gitignore_p(self) -> None:
        """Evaluate that code files would be included after filtering with .gitignore"""

        files = ["file.py", "src/file.py", "src/dir/file.py"]

        filtered_files = FilePathExtractor.apply_gitignore(files)

        assert set(filtered_files) == set(files)

    def test_apply_gitignore_n(self) -> None:
        """Evaluate that .gitignore correctly filters out files from project"""

        files = [".idea", ".idea/file1.txt", ".idea/dir/file1.txt", ".cache", "system.log", "src/dir/file.so"]

        filtered_files = FilePathExtractor.apply_gitignore(files)

        assert len(filtered_files) == 0

    @pytest.mark.parametrize("file_path", ["/tmp/test.txt", "dummy.txt"])
    def test_find_by_ext_file_p(self, config: Config, file_path: pytest.fixture) -> None:
        config.find_by_ext = True
        assert FilePathExtractor.is_find_by_ext_file(config, file_path)

    @pytest.mark.parametrize("file_path", ["/tmp/test.bmp", "dummy.doc"])
    def test_find_by_ext_file_n(self, config: Config, file_path: pytest.fixture) -> None:
        assert not FilePathExtractor.is_find_by_ext_file(config, file_path)
        config.find_by_ext = False
        assert not FilePathExtractor.is_find_by_ext_file(config, file_path)
