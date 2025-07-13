import os.path
import re
import tempfile
import unittest
from typing import List
from unittest import mock

import git
from humanfriendly import parse_size

from credsweeper.config.config import Config
from credsweeper.file_handler.file_path_extractor import FilePathExtractor
from tests import AZ_STRING


class TestFilePathExtractor(unittest.TestCase):

    def setUp(self):
        config_dict = {
            "size_limit": None,
            "find_by_ext": False,
            "find_by_ext_list": [],
            "doc": False,
            "depth": 0,
            "exclude": {
                "path": [],
                "pattern": [],
                "containers": [],
                "documents": [],
                "extension": []
            },
            "source_ext": [],
            "source_quote_ext": [],
            "bruteforce_list": [],
            "check_for_literals": [],
            "use_filters": False,
            "line_data_output": [],
            "candidate_output": [],
            "max_password_value_length": 0,
            "max_url_cred_value_length": 0,
        }
        self.config = Config(config_dict)

        # excluded always not_allowed_path_pattern
        self.paths_not = ["dummy.css", "tmp/dummy.css", "c:\\temp\\dummy.css"]
        # pattern
        self.paths_reg = ["tmp/Magic/dummy.Number", "/tmp/log/MagicNumber.txt"]
        # "/.git/"
        self.paths_git = ["C:\\.git\\dummy", "./.git/dummy.sample", "~/.git\\dummy.txt"]
        # not excluded
        self.paths_src = ["dummy.py", "/tmp/dummy.py", "tmp/dummy.py", "C:\\dummy.py", "temp\\dummy.py"]
        # not excluded when --depth are set
        self.paths_pak = ["dummy.gz", "/tmp/dummy.gz", "tmp/dummy.gz", "C:\\dummy.gz", "temp\\dummy.gz"]
        # not excluded when --doc or --depth are set
        self.paths_doc = ["dummy.pdf", "/tmp/dummy.pdf", "tmp/dummy.pdf", "C:\\dummy.pdf", "temp\\dummy.pdf"]
        # extension to be excluded always
        self.paths_ext = ["dummy.so", "dummy.so", "/tmp/dummy.so", "tmp/dummy.so", "C:\\dummy.so", "temp\\dummy.so"]

    def tearDown(self):
        del self.config

    def test_apply_gitignore_p(self) -> None:
        """Evaluate that code files would be included after filtering with .gitignore"""
        files = ["file.py", "src/file.py", "src/dir/file.py"]
        filtered_files = FilePathExtractor.apply_gitignore(files)
        self.assertSetEqual(set(files), set(filtered_files))

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

        self.assertEqual(1, len(filtered_files))
        expected_path = os.path.join(tmp_dir, "src", "dir", "file.cpp")
        self.assertEqual(expected_path, filtered_files[0])

    def assert_true_check_exclude_file(self, paths: List[str]):
        for i in paths:
            self.assertTrue(FilePathExtractor.check_exclude_file(self.config, i), i)

    def assert_false_check_exclude_file(self, paths: List[str]):
        for i in paths:
            self.assertFalse(FilePathExtractor.check_exclude_file(self.config, i), i)

    def test_check_exclude_file_p(self) -> None:
        # matched only not_allowed_path_pattern
        self.config.exclude_containers = [".gz"]
        self.config.exclude_documents = [".pdf"]
        self.config.exclude_extensions = [".so"]
        self.config.exclude_paths = ["/.git/"]
        self.config.exclude_patterns = [re.compile(r".*magic.*number.*")]
        self.config.depth = 1
        self.config.doc = False
        self.assert_true_check_exclude_file(self.paths_not)
        self.assert_true_check_exclude_file(self.paths_reg)
        self.assert_true_check_exclude_file(self.paths_git)
        self.assert_false_check_exclude_file(self.paths_src)
        self.assert_false_check_exclude_file(self.paths_pak)
        self.assert_false_check_exclude_file(self.paths_doc)
        self.assert_true_check_exclude_file(self.paths_ext)

        # pdf should be not filtered
        self.config.depth = 0
        self.config.doc = True
        self.assert_true_check_exclude_file(self.paths_not)
        self.assert_true_check_exclude_file(self.paths_reg)
        self.assert_true_check_exclude_file(self.paths_git)
        self.assert_false_check_exclude_file(self.paths_src)
        self.assert_true_check_exclude_file(self.paths_pak)
        self.assert_false_check_exclude_file(self.paths_doc)
        self.assert_true_check_exclude_file(self.paths_ext)

    def test_check_exclude_file_n(self) -> None:
        # none of extension are in config, only not_allowed_path_pattern matches
        self.assert_true_check_exclude_file(self.paths_not)
        self.assert_false_check_exclude_file(self.paths_reg)
        self.assert_false_check_exclude_file(self.paths_git)
        self.assert_false_check_exclude_file(self.paths_src)
        self.assert_false_check_exclude_file(self.paths_pak)
        self.assert_false_check_exclude_file(self.paths_doc)
        self.assert_false_check_exclude_file(self.paths_ext)

        # matched only exclude_extensions
        self.config.exclude_containers = [".gz"]
        self.config.exclude_documents = [".pdf"]
        self.config.exclude_extensions = [".so"]
        self.assert_true_check_exclude_file(self.paths_not)
        self.assert_false_check_exclude_file(self.paths_reg)
        self.assert_false_check_exclude_file(self.paths_git)
        self.assert_false_check_exclude_file(self.paths_src)
        self.assert_true_check_exclude_file(self.paths_pak)
        self.assert_true_check_exclude_file(self.paths_doc)
        self.assert_true_check_exclude_file(self.paths_ext)

    def test_find_by_ext_file_p(self) -> None:
        self.config.find_by_ext = True
        self.config.find_by_ext_list = [".p12", ".jpg"]
        self.assertTrue(FilePathExtractor.is_find_by_ext_file(self.config, ".p12"))
        self.assertTrue(FilePathExtractor.is_find_by_ext_file(self.config, ".jpg"))
        self.assertFalse(FilePathExtractor.is_find_by_ext_file(self.config, ".bmp"))

    def test_find_by_ext_file_n(self) -> None:
        self.config.find_by_ext = False
        self.config.find_by_ext_list = [".p12", ".bmp"]
        self.assertFalse(FilePathExtractor.is_find_by_ext_file(self.config, ".p12"))
        self.assertFalse(FilePathExtractor.is_find_by_ext_file(self.config, ".bmp"))
        self.assertFalse(FilePathExtractor.is_find_by_ext_file(self.config, ".jpg"))

    @mock.patch("os.path.getsize")
    def test_check_file_size_p(self, mock_getsize) -> None:
        mock_getsize.return_value = parse_size("11MiB")
        self.config.size_limit = parse_size("10MiB")
        self.assertTrue(FilePathExtractor.check_file_size(self.config, ""))

    @mock.patch("os.path.getsize")
    def test_check_file_size_n(self, mock_getsize) -> None:
        mock_getsize.return_value = parse_size("11MiB")
        self.config.size_limit = None
        self.assertFalse(FilePathExtractor.check_file_size(self.config, ""))
        self.config.size_limit = parse_size("11MiB")
        self.assertFalse(FilePathExtractor.check_file_size(self.config, ""))

    def test_skip_symlink_n(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            sub_dir = os.path.join(tmp_dir, "sub_dir")
            os.mkdir(sub_dir)
            target_path = os.path.join(sub_dir, "target")
            with open(target_path, "w") as f:
                f.write(AZ_STRING)
            s_link_path = os.path.join(tmp_dir, "s_link")
            os.symlink(target_path, s_link_path)
            s_dir_path = os.path.join(tmp_dir, "s_dir_link")
            os.symlink(sub_dir, s_dir_path)

            dirs_walked = set()
            files_walked = set()
            for root, dirs, files in os.walk(tmp_dir):
                files_walked.update(files)
                dirs_walked.update(dirs)
            self.assertEqual({"sub_dir", "s_dir_link"}, dirs_walked)
            self.assertEqual({"target", "s_link"}, files_walked)

            paths = FilePathExtractor.get_file_paths(self.config, tmp_dir)
            self.assertEqual(1, len(paths))
            self.assertEqual(target_path, paths[0])
