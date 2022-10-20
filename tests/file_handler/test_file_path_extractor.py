import os.path
import tempfile
from unittest import mock
from unittest.mock import Mock

import git
import pytest
from humanfriendly import parse_size

from credsweeper.config import Config
from credsweeper.file_handler.file_path_extractor import FilePathExtractor


class TestFilePathExtractor:

    def test_apply_gitignore_p(self) -> None:
        """Evaluate that code files would be included after filtering with .gitignore"""

        files = ["file.py", "src/file.py", "src/dir/file.py"]

        filtered_files = FilePathExtractor.apply_gitignore(files)

        assert set(filtered_files) == set(files)

    def test_apply_gitignore_n(self) -> None:
        """Evaluate that .gitignore correctly filters out files from project"""

        with tempfile.TemporaryDirectory() as tmp_dir:
            git.Repo.init(tmp_dir)
            with open(os.path.join(tmp_dir, ".gitignore"), "w") as f:
                f.write(".*\n*.txt\n*.log\n*.so")
            files = [
                os.path.join(tmp_dir, ".idea"),
                os.path.join(tmp_dir, ".idea", "file1.txt"),
                os.path.join(tmp_dir, ".idea", "dir", "file1.txt"),
                os.path.join(tmp_dir, ".cache"),
                os.path.join(tmp_dir, "system.log"),
                os.path.join(tmp_dir, "src", "dir", "file.so"),
                os.path.join(tmp_dir, "src", "dir", "file.cpp")
            ]
            filtered_files = FilePathExtractor.apply_gitignore(files)

        assert len(filtered_files) == 1
        assert filtered_files[0] == os.path.join(tmp_dir, "src", "dir", "file.cpp")

    @pytest.mark.parametrize("file_path", [
        "/tmp/test/dummy.p12",
        "C:\\Users\\RUNNER~1\\AppData\\Local\\Temp\\tmptjz2p1zk\\test\\dummy.p12",
    ])
    def test_check_exclude_file_p(self, config: Config, file_path: pytest.fixture) -> None:
        config.find_by_ext = True
        assert not FilePathExtractor.check_exclude_file(config, file_path), f"{file_path}"

    @pytest.mark.parametrize("file_path", [
        "dummy.JPG",
        "/tmp/target/dummy.p12",
        "C:\\Users\\RUNNER~1\\AppData\\Local\\Temp\\tmptjz2p1zk\\target\\dummy.p12",
        "C:\\Users\\RUNNER~1\\AppData\\Local\\Temp\\tmptjz2p1zk\\tArGet\\dummy.p12",
    ])
    def test_check_exclude_file_n(self, config: Config, file_path: pytest.fixture) -> None:
        config.find_by_ext = True
        assert FilePathExtractor.check_exclude_file(config, file_path)

    @pytest.mark.parametrize("file_type", [".inf", ".txt"])
    def test_find_by_ext_file_p(self, config: Config, file_type: pytest.fixture) -> None:
        config.find_by_ext = True
        assert FilePathExtractor.is_find_by_ext_file(config, file_type)

    @pytest.mark.parametrize("file_type", [".bmp", ".doc"])
    def test_find_by_ext_file_n(self, config: Config, file_type: pytest.fixture) -> None:
        assert not FilePathExtractor.is_find_by_ext_file(config, file_type)
        config.find_by_ext = False
        assert not FilePathExtractor.is_find_by_ext_file(config, file_type)

    @mock.patch("os.path.getsize")
    def test_check_file_size_p(self, mock_getsize: Mock(), config: Config) -> None:
        mock_getsize.return_value = parse_size("11MiB")
        config.size_limit = parse_size("10MiB")
        assert FilePathExtractor.check_file_size(config, "")

    @mock.patch("os.path.getsize")
    def test_check_file_size_n(self, mock_getsize: Mock(), config: Config) -> None:
        mock_getsize.return_value = parse_size("11MiB")
        config.size_limit = None
        assert not FilePathExtractor.check_file_size(config, "")
        config.size_limit = parse_size("11MiB")
        assert not FilePathExtractor.check_file_size(config, "")
